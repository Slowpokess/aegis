from dataclasses import dataclass
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from app.collectors.pipeline import ObservationPipeline
from app.active_web.service import ActiveWebAssessmentService
from app.domain.active_web import ActiveWebProfile
from app.config import Settings
from app.discovery.engine import DiscoveryEngine
from app.discovery.policy import ToolPolicy
from app.discovery.registry import ToolRegistry
from app.domain.common import FactClassification, Provenance, utc_now
from app.domain.controller import (
    ActionSatisfaction,
    ControllerStep,
    EvidenceAcquisitionContract,
    ExpectedEvidenceType,
    HTTPAuthorization,
    HttpObserveActionProposal,
    DiscoverWebContentActionProposal,
    AssessWebTemplatesActionProposal,
    ResearchAction,
    ResearchActionPurpose,
    ResearchActionResult,
    ResearchActionStatus,
    ResearchActionType,
    ReproduceExperimentActionProposal,
    TypedResearchActionProposal,
    action_semantic_hash,
)
from app.domain.discovery import (
    DiscoveryPlan,
    DiscoveryPlanStatus,
    DiscoveryProfile,
    PlanItemRequirement,
    ToolCapability,
    ToolRequest,
    ToolRun,
    ToolRunStatus,
    ToolTarget,
    tool_run_config_sha256,
)
from app.domain.experiments import ExperimentExecutionStatus
from app.domain.research import ResearchSessionStatus
from app.domain.research_planner import (
    ExpectedInformation,
    ResearchIntent,
    ResearchIntentProposal,
    ResearchIntentStatus,
    ResearchIntentType,
    ResearchStep,
    ResearchStepStatus,
)
from app.domain.research_strategy import GapStatus, GapType
from app.execution.experiments import ExperimentRunner
from app.execution.identity import LaboratoryIdentityResolver, ResolvedIdentity
from app.execution.policy_protocol import PolicyAction, PolicyConfig, PolicyRequest
from app.execution.protocol import HttpMethod
from app.execution.rust_policy import RustPolicyClient
from app.research_planner.validator import intent_semantic_key
from app.storage.database import Database
from app.storage.repositories import RepositorySet
from app.verification.verifier import VerificationEngine


@dataclass(frozen=True)
class ResolvedEndpoint:
    entity_id: UUID
    url: str
    path: str
    method: HttpMethod


class EndpointResolver:
    def resolve(
        self, repositories: RepositorySet, session_id: UUID, endpoint_id: UUID, method: str
    ) -> ResolvedEndpoint:
        research = repositories.research_sessions.get(session_id)
        endpoint = repositories.system_endpoints.get(endpoint_id)
        if research is None or endpoint is None:
            raise ValueError("ENDPOINT_NOT_FOUND")
        if endpoint.research_session_id != session_id:
            raise ValueError("CROSS_SESSION_ENTITY")
        if method not in {"GET", "HEAD", "OPTIONS"}:
            raise ValueError("METHOD_NOT_ALLOWED")
        url = f"{endpoint.scheme}://{endpoint.host}:{endpoint.port}{endpoint.path}"
        research.scope.validate_url(url)
        return ResolvedEndpoint(endpoint.id, url, endpoint.path, HttpMethod(method))


class AuthorizedIdentityResolver:
    """Resolves only observed session identities; secrets never leave this boundary."""

    def __init__(self, credentials: LaboratoryIdentityResolver | None = None) -> None:
        self.credentials = credentials or LaboratoryIdentityResolver()

    def resolve(
        self, repositories: RepositorySet, session_id: UUID, identity_id: UUID
    ) -> ResolvedIdentity:
        identity = repositories.system_identities.get(identity_id)
        if identity is None:
            raise ValueError("IDENTITY_NOT_FOUND")
        if identity.research_session_id != session_id:
            raise ValueError("CROSS_SESSION_ENTITY")
        if identity.name not in self.credentials.allowed_names:
            raise ValueError("IDENTITY_NOT_AUTHORIZED")
        return self.credentials.resolve(identity.name)


@dataclass(frozen=True)
class ActionValidation:
    allowed: bool
    reason: str
    endpoint: ResolvedEndpoint | None = None
    identity: ResolvedIdentity | None = None


class ResearchActionValidator:
    _SUPPORTED = {
        ResearchActionType.HTTP_OBSERVE: {
            ExpectedEvidenceType.STATUS_CODE,
            ExpectedEvidenceType.CONTENT_TYPE,
            ExpectedEvidenceType.REDIRECT_LOCATION,
            ExpectedEvidenceType.JSON_VALIDITY,
            ExpectedEvidenceType.JSON_FIELD,
            ExpectedEvidenceType.BODY_HASH,
            ExpectedEvidenceType.RESOURCE_ID,
            ExpectedEvidenceType.RESOURCE_OWNER,
        },
        ResearchActionType.SERVICE_DISCOVERY: {
            ExpectedEvidenceType.SERVICE_STATE,
            ExpectedEvidenceType.SERVICE_NAME,
        },
        ResearchActionType.DNS_RESOLVE: {ExpectedEvidenceType.DNS_RESULT},
        ResearchActionType.TLS_INSPECT: {ExpectedEvidenceType.TLS_METADATA},
        ResearchActionType.REPRODUCE_EXPERIMENT: {
            ExpectedEvidenceType.STATUS_CODE,
            ExpectedEvidenceType.BODY_HASH,
        },
        ResearchActionType.DISCOVER_WEB_CONTENT: {ExpectedEvidenceType.WEB_RESOURCE},
        ResearchActionType.ASSESS_WEB_TEMPLATES: {
            ExpectedEvidenceType.TEMPLATE_CANDIDATE
        },
    }

    def __init__(self, *, experimental_mode: bool = False) -> None:
        self.endpoints = EndpointResolver()
        self.identities = AuthorizedIdentityResolver()
        self.experimental_mode = experimental_mode

    def validate(
        self,
        repositories: RepositorySet,
        proposal: TypedResearchActionProposal,
        *,
        experimental_mode: bool | None = None,
        max_semantic_repeats: int = 3,
        allow_action_repetition: bool | None = None,
        allow_closed_gap_revisit: bool | None = None,
        allow_off_gap_exploration: bool | None = None,
    ) -> ActionValidation:
        experimental = self.experimental_mode if experimental_mode is None else experimental_mode
        repetition_allowed = (
            experimental if allow_action_repetition is None else allow_action_repetition
        )
        closed_revisit_allowed = (
            experimental if allow_closed_gap_revisit is None else allow_closed_gap_revisit
        )
        off_gap_allowed = (
            experimental if allow_off_gap_exploration is None else allow_off_gap_exploration
        )
        research = repositories.research_sessions.get(proposal.research_session_id)
        if research is None:
            return ActionValidation(False, "SESSION_NOT_FOUND")
        if research.status in {ResearchSessionStatus.COMPLETED, ResearchSessionStatus.FAILED}:
            return ActionValidation(False, "SESSION_NOT_ACTIVE")
        prior_satisfied = repositories.research_actions.get_satisfied_by_hash(
            proposal.research_session_id, action_semantic_hash(proposal)
        )
        if (
            not repetition_allowed
            and prior_satisfied
            and proposal.action_type is not ResearchActionType.REPRODUCE_EXPERIMENT
        ):
            return ActionValidation(False, "DUPLICATE_SATISFIED_ACTION")
        if repetition_allowed and prior_satisfied:
            if proposal.repeat_reason is None:
                return ActionValidation(False, "REPEAT_REASON_REQUIRED")
            if (
                repositories.research_actions.count_by_hash(
                    proposal.research_session_id, action_semantic_hash(proposal)
                )
                >= max_semantic_repeats
            ):
                return ActionValidation(False, "SEMANTIC_REPEAT_LIMIT_REACHED")
        expected = {item.information for item in proposal.expected_information}
        if not expected.issubset(self._SUPPORTED.get(proposal.action_type, set())):
            return ActionValidation(False, "EXPECTED_INFORMATION_NOT_SUPPORTED")
        gaps = []
        for gap_id in proposal.supporting_gap_ids:
            gap = repositories.evidence_gaps.get(gap_id)
            if gap is None or gap.research_session_id != proposal.research_session_id:
                return ActionValidation(False, "SUPPORTING_GAP_INVALID")
            if not closed_revisit_allowed and gap.status not in {
                GapStatus.OPEN,
                GapStatus.PARTIALLY_RESOLVED,
                GapStatus.BLOCKED,
            }:
                return ActionValidation(False, "GAP_ALREADY_RESOLVED")
            gaps.append(gap)
        if (
            not off_gap_allowed
            and proposal.supporting_gap_ids == ()
            and proposal.action_type
            not in {
                ResearchActionType.SERVICE_DISCOVERY,
                ResearchActionType.STOP_RESEARCH,
            }
        ):
            return ActionValidation(False, "ACTION_NOT_RELEVANT_TO_OPEN_GAP")
        for question_id in proposal.supporting_question_ids:
            question = repositories.research_questions.get(question_id)
            if question is None or question.research_session_id != proposal.research_session_id:
                return ActionValidation(False, "SUPPORTING_QUESTION_INVALID")
        for signal_id in proposal.supporting_signal_ids:
            signal = repositories.candidate_signals.get(signal_id)
            if signal is None:
                return ActionValidation(False, "SUPPORTING_SIGNAL_INVALID")
            graph = repositories.attack_graph_snapshots.get(signal.graph_id)
            if graph is None or graph.research_session_id != proposal.research_session_id:
                return ActionValidation(False, "CROSS_SESSION_PROVENANCE")
        if isinstance(proposal, HttpObserveActionProposal):
            try:
                endpoint = self.endpoints.resolve(
                    repositories,
                    proposal.research_session_id,
                    proposal.endpoint_entity_id,
                    proposal.method,
                )
                identity = self.identities.resolve(
                    repositories,
                    proposal.research_session_id,
                    proposal.identity_entity_id,
                )
            except ValueError as error:
                return ActionValidation(False, str(error))
            if proposal.target_entity_id not in {None, proposal.endpoint_entity_id}:
                return ActionValidation(False, "TARGET_ENDPOINT_MISMATCH")
            for gap in gaps:
                if experimental:
                    continue
                if gap.gap_type is GapType.MISSING_BASELINE:
                    if gap.subject_entity_id != proposal.identity_entity_id:
                        return ActionValidation(False, "BASELINE_IDENTITY_MISMATCH")
                    if gap.target_entity_id != proposal.endpoint_entity_id:
                        return ActionValidation(False, "BASELINE_ENDPOINT_MISMATCH")
                    if gap.resource_entity_id != proposal.resource_entity_id:
                        return ActionValidation(False, "BASELINE_RESOURCE_MISMATCH")
                    if proposal.purpose is not ResearchActionPurpose.OWNER_BASELINE:
                        return ActionValidation(False, "BASELINE_PURPOSE_MISMATCH")
            reason = "VALIDATED_EXPERIMENTAL" if experimental else "VALIDATED"
            return ActionValidation(True, reason, endpoint, identity)
        if isinstance(proposal, ReproduceExperimentActionProposal):
            experiment = repositories.experiments.get(proposal.experiment_id)
            if experiment is None or experiment.research_session_id != proposal.research_session_id:
                return ActionValidation(False, "EXPERIMENT_NOT_FOUND")
        if isinstance(proposal, DiscoverWebContentActionProposal):
            resource = repositories.web_resources.get(proposal.web_resource_id)
            if resource is None or resource.research_session_id != proposal.research_session_id:
                return ActionValidation(False, "WEB_RESOURCE_NOT_FOUND")
            if proposal.subject_entity_id != proposal.web_resource_id:
                return ActionValidation(False, "WEB_RESOURCE_SUBJECT_MISMATCH")
        if isinstance(proposal, AssessWebTemplatesActionProposal):
            for resource_id in proposal.web_resource_ids:
                resource = repositories.web_resources.get(resource_id)
                if resource is None or resource.research_session_id != proposal.research_session_id:
                    return ActionValidation(False, "WEB_RESOURCE_NOT_FOUND")
            if proposal.subject_entity_id not in proposal.web_resource_ids:
                return ActionValidation(False, "WEB_RESOURCE_SUBJECT_MISMATCH")
        reason = "VALIDATED_EXPERIMENTAL" if experimental else "VALIDATED"
        return ActionValidation(True, reason)


class ActionIntentBridge:
    _MAP = {
        ResearchActionType.HTTP_OBSERVE: (
            ResearchIntentType.OBSERVE_HTTP,
            ToolCapability.HTTP_REQUEST,
            ExpectedInformation.HTTP_METADATA,
        ),
        ResearchActionType.SERVICE_DISCOVERY: (
            ResearchIntentType.DISCOVER_SERVICES,
            ToolCapability.SERVICE_DISCOVERY,
            ExpectedInformation.SERVICES,
        ),
        ResearchActionType.DNS_RESOLVE: (
            ResearchIntentType.RESOLVE_HOST,
            ToolCapability.DNS_LOOKUP,
            ExpectedInformation.DNS_ADDRESSES,
        ),
        ResearchActionType.TLS_INSPECT: (
            ResearchIntentType.INSPECT_TLS,
            ToolCapability.TLS_INSPECTION,
            ExpectedInformation.TLS_METADATA,
        ),
        ResearchActionType.DISCOVER_WEB_CONTENT: (
            ResearchIntentType.DISCOVER_WEB_CONTENT,
            ToolCapability.WEB_CONTENT_DISCOVERY,
            ExpectedInformation.WEB_RESOURCES,
        ),
        ResearchActionType.ASSESS_WEB_TEMPLATES: (
            ResearchIntentType.ASSESS_WEB_TEMPLATES,
            ToolCapability.TEMPLATE_ASSESSMENT,
            ExpectedInformation.TEMPLATE_CANDIDATES,
        ),
    }

    def create(
        self,
        repositories: RepositorySet,
        controller_step: ControllerStep,
        action: ResearchAction,
    ) -> ResearchIntent | None:
        mapped = self._MAP.get(action.action_type)
        if mapped is None:
            return None
        intent_type, capability, expected = mapped
        prior = repositories.research_steps.list_by_session(action.research_session_id)
        planner_step = ResearchStep(
            research_session_id=action.research_session_id,
            step_number=len(prior) + 1,
            context_hash=controller_step.context_hash,
            planner_provider="controller_bridge",
            planner_model="deterministic",
            status=ResearchStepStatus.PLANNED,
            model_hash_before=controller_step.model_hash,
            graph_hash_before=controller_step.graph_hash,
            provenance=_provenance("controller_intent_bridge", str(action.id)),
        )
        repositories.research_steps.add(planner_step)
        proposal = action.proposal
        intent_proposal = ResearchIntentProposal(
            intent_type=intent_type,
            subject_entity_id=proposal.subject_entity_id,
            target_entity_id=proposal.target_entity_id,
            reason=proposal.rationale,
            expected_information=(expected,),
            priority=proposal.priority,
            supporting_observation_ids=proposal.supporting_observation_ids,
            supporting_signal_ids=proposal.supporting_signal_ids,
            evidence_gap_ids=proposal.supporting_gap_ids,
        )
        semantic = intent_semantic_key(action.research_session_id, intent_proposal)
        intent = ResearchIntent(
            research_session_id=action.research_session_id,
            research_step_id=planner_step.id,
            context_hash=controller_step.context_hash,
            intent_type=intent_type,
            subject_entity_id=proposal.subject_entity_id,
            target_entity_id=proposal.target_entity_id,
            reason=proposal.rationale,
            expected_information=(expected,),
            priority=proposal.priority,
            source="DETERMINISTIC",
            supporting_observation_ids=proposal.supporting_observation_ids,
            supporting_signal_ids=proposal.supporting_signal_ids,
            evidence_gap_ids=proposal.supporting_gap_ids,
            semantic_key=semantic,
            status=ResearchIntentStatus.PLANNED,
            capability=capability,
            selected_profile={
                ToolCapability.HTTP_REQUEST: "entity_observe",
                ToolCapability.WEB_CONTENT_DISCOVERY: "web_content_small",
                ToolCapability.TEMPLATE_ASSESSMENT: "safe_templates",
            }.get(capability),
            selected_tool_id={
                ToolCapability.HTTP_REQUEST: "http",
                ToolCapability.WEB_CONTENT_DISCOVERY: "ffuf",
                ToolCapability.TEMPLATE_ASSESSMENT: "nuclei",
            }.get(capability),
            selection_reason="typed action mapped deterministically to capability",
            provenance=_provenance("controller_intent", str(action.id)),
        )
        repositories.research_intents.add(intent)
        repositories.research_steps.update(
            planner_step.model_copy(update={"intent_ids": (intent.id,)})
        )
        return intent


class EvidenceAcquirer:
    def __init__(
        self,
        database: Database,
        settings: Settings,
        registry: ToolRegistry,
        observation_pipeline: ObservationPipeline,
        policy_client: RustPolicyClient,
        discovery_engine: DiscoveryEngine,
        experiment_runner: ExperimentRunner,
        verification_engine: VerificationEngine,
    ) -> None:
        self.database = database
        self.settings = settings
        self.registry = registry
        self.observation_pipeline = observation_pipeline
        self.policy_client = policy_client
        self.discovery_engine = discovery_engine
        self.experiment_runner = experiment_runner
        self.verification_engine = verification_engine
        self.tool_policy = ToolPolicy(registry)
        self.active_web = ActiveWebAssessmentService(database, settings, registry)

    async def preview_policy(
        self,
        action: ResearchAction,
        validation: ActionValidation,
    ) -> tuple[bool, str]:
        """Evaluate the real policy boundaries without persisting or executing a ToolRun."""
        with self.database.session_factory() as session:
            research = RepositorySet(session).research_sessions.get(action.research_session_id)
        if research is None:
            return False, "SESSION_NOT_FOUND"
        if isinstance(action.proposal, DiscoverWebContentActionProposal):
            preview = self.active_web.preview_discovery(
                action.research_session_id,
                action.proposal.web_resource_id,
                ActiveWebProfile(action.proposal.profile),
            )
            return preview.policy_allowed, preview.policy_reason
        if isinstance(action.proposal, AssessWebTemplatesActionProposal):
            preview = self.active_web.preview_assessment(
                action.research_session_id,
                action.proposal.web_resource_ids,
                ActiveWebProfile(action.proposal.profile),
            )
            return preview.policy_allowed, preview.policy_reason
        capability = {
            ResearchActionType.HTTP_OBSERVE: ToolCapability.HTTP_REQUEST,
            ResearchActionType.SERVICE_DISCOVERY: ToolCapability.SERVICE_DISCOVERY,
            ResearchActionType.DNS_RESOLVE: ToolCapability.DNS_LOOKUP,
            ResearchActionType.TLS_INSPECT: ToolCapability.TLS_INSPECTION,
            ResearchActionType.DISCOVER_WEB_CONTENT: ToolCapability.WEB_CONTENT_DISCOVERY,
            ResearchActionType.ASSESS_WEB_TEMPLATES: ToolCapability.TEMPLATE_ASSESSMENT,
        }.get(action.action_type)
        if capability is None:
            # Experiment reproduction still enters its existing Phase 4 policy at execution.
            return True, "EXPERIMENT_POLICY_REQUIRED_AT_EXECUTION"
        from app.research_planner.resolver import ToolResolver

        resolution = ToolResolver(self.registry, self.tool_policy).resolve(capability, research)
        if resolution.policy_preview is None:
            return False, "NO_REGISTERED_TOOL"
        if not resolution.policy_preview.allowed:
            return False, resolution.policy_preview.reason.value
        if action.action_type is not ResearchActionType.HTTP_OBSERVE:
            return True, resolution.policy_preview.reason.value
        if validation.endpoint is None:
            return False, "ENDPOINT_NOT_RESOLVED"
        response = await self.policy_client.evaluate(
            PolicyRequest(
                decision_id=f"PREVIEW-{uuid4()}",
                policy=PolicyConfig(
                    allowed_hosts=list(research.scope.hosts),
                    allowed_ports=list(research.scope.ports),
                    allowed_schemes=list(research.scope.schemes),
                    allowed_methods=["GET", "HEAD", "OPTIONS"],
                    max_requests_per_minute=self.settings.policy_max_requests_per_minute,
                    max_response_bytes=self.settings.policy_max_response_bytes,
                    max_timeout_ms=self.settings.policy_max_timeout_ms,
                    follow_redirects=False,
                ),
                action=PolicyAction(
                    method=validation.endpoint.method.value,
                    url=validation.endpoint.url,
                    headers={},
                    timeout_ms=min(5000, self.settings.policy_max_timeout_ms),
                    max_response_bytes=self.settings.policy_max_response_bytes,
                    follow_redirects=False,
                ),
            )
        )
        return response.allowed, response.reason_code.value

    async def authorize_http(
        self,
        action: ResearchAction,
        validation: ActionValidation,
    ) -> tuple[EvidenceAcquisitionContract, DiscoveryPlan, ToolRun]:
        if validation.endpoint is None or validation.identity is None:
            raise ValueError("validated HTTP action lacks resolved entities")
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            research = repositories.research_sessions.get(action.research_session_id)
            if research is None:
                raise ValueError("research session does not exist")
            parsed = urlsplit(research.target.base_url)
            request = ToolRequest(
                tool="http",
                profile="entity_observe",
                target=ToolTarget.from_scope(
                    parsed.hostname or "", research.scope.ports, parsed.scheme
                ),
                timeout_seconds=min(5, self.settings.policy_max_timeout_ms / 1000),
                requirement=PlanItemRequirement.REQUIRED,
            )
            plan = DiscoveryPlan(
                research_session_id=research.id,
                profile=DiscoveryProfile.STANDARD,
                requested_capabilities=(ToolCapability.HTTP_REQUEST,),
                planned_tool_runs=(request,),
                provenance=_provenance("controller_discovery_plan", str(action.id)),
            )
            repositories.discovery_plans.add(plan)
            descriptor = self.registry.require("http")
            run = ToolRun(
                research_session_id=research.id,
                discovery_plan_id=plan.id,
                tool_id="http",
                tool_version=descriptor.version,
                profile="entity_observe",
                profile_version="http-entity-observe-v1",
                requested_target=request.target,
                normalized_target=request.target,
                status=ToolRunStatus.VALIDATED,
                config_sha256=tool_run_config_sha256(request, descriptor),
                provenance=_provenance("controller_tool_request", str(action.id)),
            )
            repositories.tool_runs.add(run)
            tool_decision = self.tool_policy.evaluate(
                research_session=research,
                discovery_plan_id=plan.id,
                tool_run_id=run.id,
                request=request,
            )
            repositories.tool_policy_decisions.add(tool_decision)
            run = run.model_copy(
                update={
                    "policy_decision_id": tool_decision.id,
                    "status": (
                        ToolRunStatus.POLICY_APPROVED
                        if tool_decision.allowed
                        else ToolRunStatus.POLICY_REJECTED
                    ),
                }
            )
            repositories.tool_runs.update(run)
        if not tool_decision.allowed:
            contract = EvidenceAcquisitionContract(
                research_session_id=action.research_session_id,
                action_type=ResearchActionType.HTTP_OBSERVE,
                purpose=action.purpose,
                endpoint_entity_id=validation.endpoint.entity_id,
                identity_entity_id=action.proposal.identity_entity_id,
                resource_entity_id=action.proposal.resource_entity_id,
                method=validation.endpoint.method.value,
                path=validation.endpoint.path,
                capability=ToolCapability.HTTP_REQUEST,
                expected_information=action.proposal.expected_information,
                timeout_ms=min(5000, self.settings.policy_max_timeout_ms),
                max_response_bytes=self.settings.policy_max_response_bytes,
                policy_decision=HTTPAuthorization(
                    decision_id=str(tool_decision.id),
                    allowed=False,
                    reason_code=tool_decision.reason.value,
                    message=tool_decision.message,
                    policy_sha256=tool_decision.policy_hash,
                    policy_engine="aegis-tool-policy-v1",
                    policy_engine_version="1",
                ),
            )
            return contract, plan, run
        policy = PolicyConfig(
            allowed_hosts=list(research.scope.hosts),
            allowed_ports=list(research.scope.ports),
            allowed_schemes=list(research.scope.schemes),
            allowed_methods=["GET", "HEAD", "OPTIONS"],
            max_requests_per_minute=self.settings.policy_max_requests_per_minute,
            max_response_bytes=self.settings.policy_max_response_bytes,
            max_timeout_ms=self.settings.policy_max_timeout_ms,
            follow_redirects=False,
        )
        response = await self.policy_client.evaluate(
            PolicyRequest(
                decision_id=f"DEC-{uuid4()}",
                policy=policy,
                action=PolicyAction(
                    method=validation.endpoint.method.value,
                    url=validation.endpoint.url,
                    headers={},
                    timeout_ms=min(5000, self.settings.policy_max_timeout_ms),
                    max_response_bytes=self.settings.policy_max_response_bytes,
                    follow_redirects=False,
                ),
            )
        )
        if not response.allowed or response.policy_sha256 is None:
            with self.database.session_factory.begin() as session:
                repositories = RepositorySet(session)
                repositories.tool_runs.update(
                    run.model_copy(
                        update={
                            "status": ToolRunStatus.POLICY_REJECTED,
                            "finished_at": utc_now(),
                            "error": response.message,
                        }
                    )
                )
            contract = EvidenceAcquisitionContract(
                research_session_id=action.research_session_id,
                action_type=ResearchActionType.HTTP_OBSERVE,
                purpose=action.purpose,
                endpoint_entity_id=validation.endpoint.entity_id,
                identity_entity_id=action.proposal.identity_entity_id,
                resource_entity_id=action.proposal.resource_entity_id,
                method=validation.endpoint.method.value,
                path=validation.endpoint.path,
                capability=ToolCapability.HTTP_REQUEST,
                expected_information=action.proposal.expected_information,
                timeout_ms=min(5000, self.settings.policy_max_timeout_ms),
                max_response_bytes=self.settings.policy_max_response_bytes,
                policy_decision=HTTPAuthorization(
                    decision_id=response.decision_id or "missing",
                    allowed=False,
                    reason_code=response.reason_code.value,
                    message=response.message,
                    policy_sha256=response.policy_sha256 or ("0" * 64),
                    policy_engine=response.policy_engine,
                    policy_engine_version=response.policy_engine_version,
                ),
            )
            return contract, plan, run
        contract = EvidenceAcquisitionContract(
            research_session_id=action.research_session_id,
            action_type=ResearchActionType.HTTP_OBSERVE,
            purpose=action.purpose,
            endpoint_entity_id=validation.endpoint.entity_id,
            identity_entity_id=action.proposal.identity_entity_id,
            resource_entity_id=action.proposal.resource_entity_id,
            method=validation.endpoint.method.value,
            path=validation.endpoint.path,
            capability=ToolCapability.HTTP_REQUEST,
            expected_information=action.proposal.expected_information,
            timeout_ms=min(5000, self.settings.policy_max_timeout_ms),
            max_response_bytes=self.settings.policy_max_response_bytes,
            follow_redirects=False,
            policy_decision=HTTPAuthorization(
                decision_id=response.decision_id or "missing",
                allowed=response.allowed,
                reason_code=response.reason_code.value,
                message=response.message,
                policy_sha256=response.policy_sha256,
                policy_engine=response.policy_engine,
                policy_engine_version=response.policy_engine_version,
            ),
        )
        return contract, plan, run

    async def execute_http(
        self,
        action: ResearchAction,
        validation: ActionValidation,
        contract: EvidenceAcquisitionContract,
        plan: DiscoveryPlan,
        run: ToolRun,
    ) -> ResearchActionResult:
        if validation.identity is None or contract.path is None or contract.method is None:
            raise ValueError("authorized HTTP contract is incomplete")
        started = utc_now()
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            repositories.discovery_plans.update(
                plan.model_copy(
                    update={"status": DiscoveryPlanStatus.RUNNING, "started_at": started}
                )
            )
            repositories.tool_runs.update(run.model_copy(update={"status": ToolRunStatus.RUNNING}))
        observed = await self.observation_pipeline.observe(
            research_session_id=action.research_session_id,
            path=contract.path,
            method=HttpMethod(contract.method),
            headers=validation.identity.headers,
            timeout_ms=contract.timeout_ms,
            max_response_bytes=contract.max_response_bytes,
            follow_redirects=False,
            identity_name=validation.identity.name,
            identity_roles=list(validation.identity.roles),
        )
        finished = utc_now()
        completed_run = run.model_copy(
            update={
                "status": ToolRunStatus.COMPLETED,
                "finished_at": finished,
                "observation_ids": [observed.observation.id],
                "exit_code": 0,
            }
        )
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            repositories.tool_runs.update(completed_run)
            repositories.discovery_plans.update(
                plan.model_copy(
                    update={
                        "status": DiscoveryPlanStatus.COMPLETED,
                        "started_at": started,
                        "finished_at": finished,
                    }
                )
            )
        return ResearchActionResult(
            action_id=action.id,
            research_session_id=action.research_session_id,
            status=ResearchActionStatus.COMPLETED,
            tool_run_ids=(run.id,),
            evidence_ids=(observed.evidence.id,),
            observation_ids=(observed.observation.id,),
            started_at=started,
            finished_at=finished,
            satisfaction=ActionSatisfaction.SATISFIED,
            provenance=_provenance("action_result", str(action.id)),
        )

    async def execute_discovery(self, action: ResearchAction) -> ResearchActionResult:
        capability = {
            ResearchActionType.SERVICE_DISCOVERY: ToolCapability.SERVICE_DISCOVERY,
            ResearchActionType.DNS_RESOLVE: ToolCapability.DNS_LOOKUP,
            ResearchActionType.TLS_INSPECT: ToolCapability.TLS_INSPECTION,
        }[action.action_type]
        from app.research_planner.resolver import ToolResolver

        with self.database.session_factory() as session:
            research = RepositorySet(session).research_sessions.get(action.research_session_id)
        if research is None:
            raise ValueError("research session does not exist")
        resolved = ToolResolver(self.registry, self.tool_policy).resolve(capability, research)
        if (
            resolved.request is None
            or resolved.policy_preview is None
            or not resolved.policy_preview.allowed
        ):
            raise ValueError(resolved.reason)
        plan = self.discovery_engine.create_resolved_plan(
            action.research_session_id,
            capabilities=(capability,),
            requests=(resolved.request,),
        )
        completed = await self.discovery_engine.run(plan.id)
        with self.database.session_factory() as session:
            repositories = RepositorySet(session)
            runs = repositories.tool_runs.list_by_plan(plan.id)
            observations = tuple(item for run in runs for item in run.observation_ids)
            artifacts = tuple(item for run in runs for item in run.artifact_ids)
        success = bool(observations) and completed.status.value in {"COMPLETED", "PARTIAL"}
        return ResearchActionResult(
            action_id=action.id,
            research_session_id=action.research_session_id,
            status=ResearchActionStatus.COMPLETED if success else ResearchActionStatus.FAILED,
            tool_run_ids=tuple(run.id for run in runs),
            evidence_ids=artifacts,
            observation_ids=observations,
            finished_at=utc_now(),
            satisfaction=(
                ActionSatisfaction.SATISFIED if success else ActionSatisfaction.UNSATISFIED
            ),
            failure_reason=None if success else completed.status.value,
            provenance=_provenance("action_result", str(action.id)),
        )

    async def execute_active_web(self, action: ResearchAction) -> ResearchActionResult:
        started = utc_now()
        proposal = action.proposal
        if isinstance(proposal, DiscoverWebContentActionProposal):
            result = await self.active_web.discover(
                action.research_session_id,
                proposal.web_resource_id,
                action_id=action.id,
                profile=ActiveWebProfile(proposal.profile),
                account_budget=False,
            )
        elif isinstance(proposal, AssessWebTemplatesActionProposal):
            result = await self.active_web.assess(
                action.research_session_id,
                action_id=action.id,
                resource_ids=proposal.web_resource_ids,
                profile=ActiveWebProfile(proposal.profile),
                account_budget=False,
            )
        else:
            raise ValueError("active Web action is malformed")
        success = result.status is ToolRunStatus.COMPLETED
        return ResearchActionResult(
            action_id=action.id,
            research_session_id=action.research_session_id,
            status=(
                ResearchActionStatus.COMPLETED if success else ResearchActionStatus.FAILED
            ),
            tool_run_ids=(result.tool_run_id,),
            observation_ids=result.observation_ids,
            request_cost=result.estimated_requests if success else 0,
            started_at=started,
            finished_at=utc_now(),
            satisfaction=(
                ActionSatisfaction.SATISFIED
                if result.observation_ids
                else ActionSatisfaction.UNSATISFIED
            ),
            failure_reason=result.error,
            provenance=_provenance("active_web_action_result", str(action.id)),
        )

    async def reproduce(self, action: ResearchAction) -> ResearchActionResult:
        proposal = action.proposal
        if not isinstance(proposal, ReproduceExperimentActionProposal):
            raise ValueError("reproduction action is malformed")
        result = await self.experiment_runner.run(proposal.experiment_id)
        execution = result.execution
        evidence_ids = tuple(
            item
            for item in (execution.control_evidence_id, execution.candidate_evidence_id)
            if item
        )
        observation_ids = tuple(
            item
            for item in (execution.control_observation_id, execution.candidate_observation_id)
            if item
        )
        success = execution.status is ExperimentExecutionStatus.EXECUTED
        verification_result_ids: tuple[UUID, ...] = ()
        if success:
            verified = self.verification_engine.verify_execution(execution.id)
            verification_result_ids = (verified.verification.id,)
        return ResearchActionResult(
            action_id=action.id,
            research_session_id=action.research_session_id,
            status=ResearchActionStatus.COMPLETED if success else ResearchActionStatus.FAILED,
            evidence_ids=evidence_ids,
            observation_ids=observation_ids,
            verification_result_ids=verification_result_ids,
            finished_at=utc_now(),
            satisfaction=(
                ActionSatisfaction.SATISFIED if success else ActionSatisfaction.UNSATISFIED
            ),
            failure_reason=None if success else execution.error_code,
            provenance=_provenance("action_result", str(action.id)),
        )


def _provenance(source_type: str, reference: str) -> Provenance:
    return Provenance(
        source_type=source_type,
        source_reference=reference,
        collector="closed-loop-controller-v1",
        classification=FactClassification.OBSERVED,
    )
