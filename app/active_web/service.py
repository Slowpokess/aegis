import hashlib
import re
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

from app.active_web.adapters import FfufAdapter, FfufProfile, NucleiAdapter, NucleiProfile
from app.active_web.parsers import FfufParser, NucleiParser
from app.attack_graph.builder import AttackGraphBuilder
from app.config import Settings
from app.discovery.errors import ToolExecutionError
from app.discovery.policy import ToolPolicy
from app.discovery.registry import ToolRegistry
from app.domain.active_web import (
    FFUF_PARSER_VERSION,
    NUCLEI_PARSER_VERSION,
    ActiveWebPreview,
    ActiveWebProfile,
    ActiveWebRunResult,
    TemplatePolicyClass,
    semantic_config_sha256,
)
from app.domain.controller import ResearchActionStatus, ResearchActionType
from app.domain.common import FactClassification, Provenance, TrustClassification, utc_now
from app.domain.discovery import (
    ArtifactType,
    DiscoveryPlan,
    DiscoveryPlanStatus,
    DiscoveryProfile,
    ParserStatus,
    ToolArtifact,
    ToolCapability,
    ToolErrorCode,
    ToolRequest,
    ToolRun,
    ToolRunStatus,
    ToolTarget,
)
from app.domain.observations import Observation, ObservationSource
from app.domain.operator import ApprovalMode, ApprovalStatus
from app.storage.database import Database
from app.storage.repositories import RepositorySet
from app.system_model.builder import SystemModelBuilder
from app.web_surface.builder import WebSurfaceBuilder
from app.web_surface.observations import assessment_observations


_DIAGNOSTIC_SECRETS = (
    re.compile(r"(?i)\b(?:authorization|proxy-authorization|cookie|set-cookie)\s*[:=]\s*[^\r\n]+"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)\bnvapi-[A-Za-z0-9._~-]+"),
    re.compile(
        r"(?i)\b(?:nvidia|openai|anthropic|google|azure|aws)_[A-Z0-9_]*KEY\s*[:=]\s*[^\s,;]+"
    ),
)


def _redact_diagnostic(value: str) -> str:
    redacted = value
    for pattern in _DIAGNOSTIC_SECRETS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


class ActiveWebAssessmentService:
    """Generic typed active Web plane; tools produce observations, never Findings."""

    def __init__(
        self,
        database: Database,
        settings: Settings,
        registry: ToolRegistry,
    ) -> None:
        self.database = database
        self.settings = settings
        self.registry = registry
        self.policy = ToolPolicy(registry)

    def preview_discovery(
        self,
        session_id: UUID,
        resource_id: UUID,
        profile: ActiveWebProfile = ActiveWebProfile.WEB_CONTENT_SMALL,
    ) -> ActiveWebPreview:
        if profile not in {
            ActiveWebProfile.WEB_CONTENT_SMALL,
            ActiveWebProfile.WEB_CONTENT_STANDARD,
        }:
            raise ValueError("unsupported ffuf profile")
        research, resources, budget, approval_mode = self._state(session_id, (resource_id,))
        selected = resources[0]
        ffuf_profile = self._ffuf_profile(profile)
        target = self._ffuf_target(selected)
        research.scope.validate_url(target.replace("FUZZ", "aegis-scope-check"))
        estimate = ffuf_profile.word_count
        policy = self._policy_preview(
            research,
            tool="ffuf",
            profile=profile.value,
            timeout=ffuf_profile.max_duration_seconds,
            estimated_requests=estimate,
            remaining_requests=self._remaining_requests(budget),
            budget=budget,
        )
        return ActiveWebPreview(
            research_session_id=session_id,
            web_resource_ids=(resource_id,),
            capability=ToolCapability.WEB_CONTENT_DISCOVERY,
            tool="ffuf",
            profile=profile,
            target=target,
            estimated_requests=estimate,
            timeout_seconds=ffuf_profile.max_duration_seconds,
            max_concurrency=ffuf_profile.concurrency,
            policy_allowed=policy.allowed,
            policy_reason=policy.reason.value,
            approval_required=self._approval_required(approval_mode),
            wordlist_id=ffuf_profile.wordlist_id,
            wordlist_sha256=ffuf_profile.wordlist_sha256,
            word_count=ffuf_profile.word_count,
        )

    def preview_assessment(
        self,
        session_id: UUID,
        resource_ids: tuple[UUID, ...] | None = None,
        profile: ActiveWebProfile = ActiveWebProfile.SAFE_TEMPLATES,
    ) -> ActiveWebPreview:
        if profile is not ActiveWebProfile.SAFE_TEMPLATES:
            raise ValueError("unsupported Nuclei profile")
        with self.database.session_factory() as session:
            all_resources = RepositorySet(session).web_resources.list_by_session(session_id)
        selected_ids = resource_ids or tuple(item.id for item in all_resources)
        if not selected_ids:
            raise ValueError("Nuclei assessment requires at least one WebResource")
        research, resources, budget, approval_mode = self._state(session_id, selected_ids)
        targets = tuple(self._resource_url(item) for item in resources)
        for target in targets:
            research.scope.validate_url(target)
        nuclei_profile = self._nuclei_profile(profile)
        estimate = len(targets) * len(nuclei_profile.template_paths)
        policy = self._policy_preview(
            research,
            tool="nuclei",
            profile=profile.value,
            timeout=nuclei_profile.max_duration_seconds,
            estimated_requests=estimate,
            remaining_requests=self._remaining_requests(budget),
            budget=budget,
        )
        return ActiveWebPreview(
            research_session_id=session_id,
            web_resource_ids=selected_ids,
            capability=ToolCapability.TEMPLATE_ASSESSMENT,
            tool="nuclei",
            profile=profile,
            target=f"{len(targets)} scoped WebResource target(s)",
            estimated_requests=estimate,
            timeout_seconds=nuclei_profile.max_duration_seconds,
            max_concurrency=nuclei_profile.concurrency,
            policy_allowed=policy.allowed,
            policy_reason=policy.reason.value,
            approval_required=self._approval_required(approval_mode),
            template_inventory_sha256=nuclei_profile.inventory_sha256,
            template_ids=nuclei_profile.template_ids,
            template_policy_class=TemplatePolicyClass.SAFE_ACTIVE,
        )

    async def discover(
        self,
        session_id: UUID,
        resource_id: UUID,
        *,
        action_id: UUID,
        profile: ActiveWebProfile = ActiveWebProfile.WEB_CONTENT_SMALL,
        account_budget: bool = True,
    ) -> ActiveWebRunResult:
        preview = self.preview_discovery(session_id, resource_id, profile)
        self._assert_authorized_action(preview, action_id)
        ffuf_profile = self._ffuf_profile(profile)
        return await self._execute_ffuf(preview, ffuf_profile, account_budget=account_budget)

    async def assess(
        self,
        session_id: UUID,
        *,
        action_id: UUID,
        resource_ids: tuple[UUID, ...] | None = None,
        profile: ActiveWebProfile = ActiveWebProfile.SAFE_TEMPLATES,
        account_budget: bool = True,
    ) -> ActiveWebRunResult:
        preview = self.preview_assessment(session_id, resource_ids, profile)
        self._assert_authorized_action(preview, action_id)
        nuclei_profile = self._nuclei_profile(profile)
        return await self._execute_nuclei(preview, nuclei_profile, account_budget=account_budget)

    async def _execute_ffuf(
        self, preview: ActiveWebPreview, profile: FfufProfile, *, account_budget: bool
    ) -> ActiveWebRunResult:
        plan, run, policy = self._create_run(preview, profile_metadata={
            "wordlist_id": profile.wordlist_id,
            "wordlist_sha256": profile.wordlist_sha256,
            "word_count": profile.word_count,
        })
        if not policy.allowed:
            return self._rejected_result(preview, run, policy.reason.value)
        descriptor = self.registry.require("ffuf")
        adapter = FfufAdapter(descriptor, output_max_bytes=self.settings.active_web_output_max_bytes)
        parser = FfufParser(
            max_bytes=self.settings.active_web_output_max_bytes,
            max_results=min(profile.max_results, self.settings.active_web_max_results),
        )
        return await self._execute(
            preview,
            plan,
            run,
            artifact_type=ArtifactType.FFUF_JSON,
            content_type="application/json",
            parser_version=FFUF_PARSER_VERSION,
            execute=lambda: adapter.execute(target=preview.target, profile=profile),
            parse=lambda raw, scope: parser.parse(raw, scope),
            map_observations=self._ffuf_observations,
            account_budget=account_budget,
        )

    async def _execute_nuclei(
        self, preview: ActiveWebPreview, profile: NucleiProfile, *, account_budget: bool
    ) -> ActiveWebRunResult:
        plan, run, policy = self._create_run(preview, profile_metadata={
            "template_ids": list(profile.template_ids),
            "template_inventory_sha256": profile.inventory_sha256,
            "template_policy_class": TemplatePolicyClass.SAFE_ACTIVE.value,
        })
        if not policy.allowed:
            return self._rejected_result(preview, run, policy.reason.value)
        with self.database.session_factory() as session:
            r = RepositorySet(session)
            resources = [r.web_resources.get(item) for item in preview.web_resource_ids]
        targets = tuple(self._resource_url(item) for item in resources if item is not None)
        descriptor = self.registry.require("nuclei")
        adapter = NucleiAdapter(
            descriptor, output_max_bytes=self.settings.active_web_output_max_bytes
        )
        parser = NucleiParser(
            max_bytes=self.settings.active_web_output_max_bytes,
            max_results=min(profile.max_results, self.settings.active_web_max_results),
        )
        return await self._execute(
            preview,
            plan,
            run,
            artifact_type=ArtifactType.NUCLEI_JSON,
            content_type="application/x-ndjson",
            parser_version=NUCLEI_PARSER_VERSION,
            execute=lambda: adapter.execute(targets=targets, profile=profile),
            parse=lambda raw, scope: parser.parse(raw, scope),
            map_observations=self._nuclei_observations,
            account_budget=account_budget,
        )

    async def _execute(
        self,
        preview: ActiveWebPreview,
        plan: DiscoveryPlan,
        run: ToolRun,
        *,
        artifact_type: ArtifactType,
        content_type: str,
        parser_version: str,
        execute: object,
        parse: object,
        map_observations: object,
        account_budget: bool,
    ) -> ActiveWebRunResult:
        before = self._surface_state(preview.research_session_id)
        findings_before = self._finding_count(preview.research_session_id)
        started = utc_now()
        self._mark_running(plan, run, started)
        try:
            process = await execute()  # type: ignore[operator]
        except ToolExecutionError as error:
            return self._fail_without_artifact(preview, plan, run, error)
        artifact = ToolArtifact.from_bytes(
            raw=process.stdout,
            research_session_id=run.research_session_id,
            tool_run_id=run.id,
            tool_id=run.tool_id,
            tool_version=run.tool_version,
            artifact_type=artifact_type,
            content_type=content_type,
            parser_version=parser_version,
            provenance=Provenance(
                source_type="active_web_tool_artifact",
                source_reference=str(run.id),
                collector=parser_version,
                classification=FactClassification.OBSERVED,
                metadata={"data_trust": "UNTRUSTED_TOOL_DATA"},
            ),
        )
        with self.database.session_factory.begin() as session:
            RepositorySet(session).tool_artifacts.add(artifact)
        if process.exit_code != 0:
            return self._fail_with_artifact(
                preview,
                plan,
                run,
                artifact,
                ToolErrorCode.PROCESS_FAILED,
                f"tool exited with code {process.exit_code}: {process.stderr[:500]}",
                process.argv,
                process.exit_code,
            )
        with self.database.session_factory() as session:
            research = RepositorySet(session).research_sessions.get(run.research_session_id)
        assert research is not None
        try:
            records = parse(process.stdout, research.scope)  # type: ignore[operator]
            observations = map_observations(  # type: ignore[operator]
                records, research.target.asset_id, run, artifact
            )
        except (ValueError, TypeError) as error:
            return self._fail_with_artifact(
                preview,
                plan,
                run,
                artifact,
                ToolErrorCode.PARSER_FAILED,
                str(error),
                process.argv,
                process.exit_code,
            )
        finished = utc_now()
        with self.database.session_factory.begin() as session:
            r = RepositorySet(session)
            r.tool_artifacts.update(
                artifact.model_copy(update={"parser_status": ParserStatus.COMPLETED})
            )
            for observation in observations:
                r.observations.add(observation)
            completed_run = run.model_copy(
                update={
                    "status": ToolRunStatus.COMPLETED,
                    "finished_at": finished,
                    "exit_code": process.exit_code,
                    "artifact_ids": [artifact.id],
                    "observation_ids": [item.id for item in observations],
                    "normalized_argv": process.argv,
                    "parser_version": parser_version,
                }
            )
            r.tool_runs.update(completed_run)
            r.discovery_plans.update(
                plan.model_copy(
                    update={
                        "status": DiscoveryPlanStatus.COMPLETED,
                        "started_at": started,
                        "finished_at": finished,
                    }
                )
            )
            if account_budget:
                self._consume_budget(
                    r,
                    preview.research_session_id,
                    preview.estimated_requests,
                    (finished - started).total_seconds(),
                )
        surface = WebSurfaceBuilder(self.database).build(preview.research_session_id)
        model = SystemModelBuilder(self.database).build(preview.research_session_id)
        graph_hash = None
        try:
            _, graph, _ = AttackGraphBuilder(
                self.database, max_nodes=self.settings.graph_max_nodes
            ).build(preview.research_session_id)
            graph_hash = graph.graph_hash
        except Exception:
            graph_hash = None
        after = self._surface_state(preview.research_session_id)
        observed_keys = {
            self._record_key(item) for item in records if self._record_key(item) is not None
        }
        return ActiveWebRunResult(
            research_session_id=preview.research_session_id,
            web_resource_ids=preview.web_resource_ids,
            capability=preview.capability,
            tool_run_id=run.id,
            tool_id=run.tool_id,
            tool_version=run.tool_version,
            profile=preview.profile,
            status=ToolRunStatus.COMPLETED,
            policy_allowed=True,
            policy_reason="ALLOWED",
            estimated_requests=preview.estimated_requests,
            actual_requests=None,
            timeout_seconds=preview.timeout_seconds,
            artifact_ids=(artifact.id,),
            observation_ids=tuple(item.id for item in observations),
            new_resource_count=len(after[1] - before[1]),
            deduplicated_resource_count=len(observed_keys.intersection(before[1])),
            candidate_count=after[2],
            finding_delta=self._finding_count(preview.research_session_id) - findings_before,
            surface_hash_before=before[0],
            surface_hash_after=surface.web_surface_sha256,
            system_model_hash=model.model_sha256,
            attack_graph_hash=graph_hash,
        )

    def _create_run(self, preview: ActiveWebPreview, *, profile_metadata: dict[str, object]):
        with self.database.session_factory.begin() as session:
            r = RepositorySet(session)
            research = r.research_sessions.get(preview.research_session_id)
            if research is None:
                raise ValueError("research session does not exist")
            parsed = urlsplit(research.target.base_url)
            request = ToolRequest(
                tool=preview.tool,
                profile=preview.profile.value,
                target=ToolTarget.from_scope(
                    parsed.hostname or "", research.scope.ports, parsed.scheme
                ),
                timeout_seconds=preview.timeout_seconds,
            )
            plan = DiscoveryPlan(
                research_session_id=research.id,
                profile=DiscoveryProfile.STANDARD,
                requested_capabilities=(preview.capability,),
                planned_tool_runs=(request,),
                provenance=Provenance(
                    source_type="active_web_assessment",
                    source_reference=str(research.id),
                    collector="active-web-assessment-v1",
                ),
            )
            r.discovery_plans.add(plan)
            descriptor = self.registry.require(preview.tool)
            run = ToolRun(
                research_session_id=research.id,
                discovery_plan_id=plan.id,
                tool_id=descriptor.id,
                tool_version=descriptor.version,
                profile=preview.profile.value,
                profile_version=self._profile_version(preview.profile),
                requested_target=request.target,
                normalized_target=request.target,
                status=ToolRunStatus.VALIDATED,
                parser_version=descriptor.parser_version,
                config_sha256=semantic_config_sha256(
                    {
                        "session_id": str(research.id),
                        "resource_ids": [str(item) for item in preview.web_resource_ids],
                        "capability": preview.capability.value,
                        "profile": preview.profile.value,
                        "estimated_requests": preview.estimated_requests,
                        **profile_metadata,
                    }
                ),
                provenance=Provenance(
                    source_type="active_web_tool_request",
                    source_reference=str(plan.id),
                    collector="active-web-assessment-v1",
                    metadata={
                        "capability": preview.capability.value,
                        "estimated_requests": preview.estimated_requests,
                        "resource_ids": [str(item) for item in preview.web_resource_ids],
                        **profile_metadata,
                    },
                ),
            )
            r.tool_runs.add(run)
            budget = r.research_budgets.get_by_session(research.id)
            decision = self.policy.evaluate(
                research_session=research,
                discovery_plan_id=plan.id,
                tool_run_id=run.id,
                request=request,
                estimated_request_cost=preview.estimated_requests,
                remaining_request_budget=self._remaining_requests(budget),
                remaining_tool_run_budget=self._remaining_tool_runs(budget),
                estimated_duration_seconds=preview.timeout_seconds,
                remaining_duration_seconds=self._remaining_duration(budget),
            )
            r.tool_policy_decisions.add(decision)
            run = run.model_copy(
                update={
                    "policy_decision_id": decision.id,
                    "status": (
                        ToolRunStatus.POLICY_APPROVED
                        if decision.allowed
                        else ToolRunStatus.POLICY_REJECTED
                    ),
                    "finished_at": None if decision.allowed else utc_now(),
                    "error_code": None if decision.allowed else self._policy_error(decision.reason.value),
                    "error": None if decision.allowed else decision.message,
                }
            )
            r.tool_runs.update(run)
            if not decision.allowed:
                r.discovery_plans.update(
                    plan.model_copy(
                        update={
                            "status": DiscoveryPlanStatus.FAILED,
                            "finished_at": utc_now(),
                            "error": decision.message,
                        }
                    )
                )
            return plan, run, decision

    def _policy_preview(
        self,
        research: object,
        *,
        tool: str,
        profile: str,
        timeout: float,
        estimated_requests: int,
        remaining_requests: int | None,
        budget: object | None,
    ):
        parsed = urlsplit(research.target.base_url)
        request = ToolRequest(
            tool=tool,
            profile=profile,
            target=ToolTarget.from_scope(parsed.hostname or "", research.scope.ports, parsed.scheme),
            timeout_seconds=timeout,
        )
        return self.policy.evaluate(
            research_session=research,
            discovery_plan_id=UUID(int=0),
            tool_run_id=UUID(int=0),
            request=request,
            estimated_request_cost=estimated_requests,
            remaining_request_budget=remaining_requests,
            remaining_tool_run_budget=self._remaining_tool_runs(budget),
            estimated_duration_seconds=timeout,
            remaining_duration_seconds=self._remaining_duration(budget),
        )

    def _state(self, session_id: UUID, resource_ids: tuple[UUID, ...]):
        with self.database.session_factory() as session:
            r = RepositorySet(session)
            research = r.research_sessions.get(session_id)
            if research is None:
                raise ValueError("research session does not exist")
            resources = []
            for resource_id in resource_ids:
                resource = r.web_resources.get(resource_id)
                if resource is None or resource.research_session_id != session_id:
                    raise ValueError("WebResource does not belong to the session")
                resources.append(resource)
            budget = r.research_budgets.get_by_session(session_id)
            project = r.research_projects.get(research.project_id) if research.project_id else None
        return research, resources, budget, project.approval_mode if project else ApprovalMode.AUTO

    def _assert_authorized_action(self, preview: ActiveWebPreview, action_id: UUID) -> None:
        with self.database.session_factory() as session:
            repositories = RepositorySet(session)
            action = repositories.research_actions.get(action_id)
            if action is None or action.research_session_id != preview.research_session_id:
                raise ValueError("AUTHORIZED_ACTIVE_WEB_ACTION_REQUIRED")
            expected_type = (
                ResearchActionType.DISCOVER_WEB_CONTENT
                if preview.tool == "ffuf"
                else ResearchActionType.ASSESS_WEB_TEMPLATES
            )
            if action.action_type is not expected_type:
                raise ValueError("ACTIVE_WEB_ACTION_TYPE_MISMATCH")
            if action.status not in {
                ResearchActionStatus.AUTHORIZED,
                ResearchActionStatus.EXECUTING,
            }:
                raise ValueError("ACTIVE_WEB_ACTION_NOT_EXECUTABLE")
            if getattr(action.proposal, "profile", None) != preview.profile.value:
                raise ValueError("ACTIVE_WEB_ACTION_PROFILE_MISMATCH")
            proposal_resources = (
                (action.proposal.web_resource_id,)
                if expected_type is ResearchActionType.DISCOVER_WEB_CONTENT
                else action.proposal.web_resource_ids
            )
            if tuple(proposal_resources) != preview.web_resource_ids:
                raise ValueError("ACTIVE_WEB_ACTION_RESOURCE_MISMATCH")
            research = repositories.research_sessions.get(preview.research_session_id)
            project = (
                repositories.research_projects.get(research.project_id)
                if research and research.project_id
                else None
            )
            if project and project.approval_mode is not ApprovalMode.AUTO:
                approval = repositories.action_approvals.get_by_action(action.id)
                if approval is None or approval.status is not ApprovalStatus.APPROVED:
                    raise ValueError("PERSISTED_ACTION_APPROVAL_REQUIRED")

    def _ffuf_profile(self, profile: ActiveWebProfile) -> FfufProfile:
        if profile is ActiveWebProfile.WEB_CONTENT_SMALL:
            return FfufProfile(
                profile_id=profile.value,
                version="ffuf-web-content-small-v1",
                wordlist_id="aegis-small-v1",
                wordlist_path=self._approved_inventory(self.settings.ffuf_small_wordlist, "wordlists"),
                concurrency=2,
                request_timeout_seconds=3,
                max_duration_seconds=20,
                max_results=200,
            )
        if profile is ActiveWebProfile.WEB_CONTENT_STANDARD:
            return FfufProfile(
                profile_id=profile.value,
                version="ffuf-web-content-standard-v1",
                wordlist_id="aegis-standard-v1",
                wordlist_path=self._approved_inventory(self.settings.ffuf_standard_wordlist, "wordlists"),
                concurrency=4,
                request_timeout_seconds=5,
                max_duration_seconds=60,
                max_results=1000,
            )
        raise ValueError("unsupported ffuf profile")

    def _nuclei_profile(self, profile: ActiveWebProfile) -> NucleiProfile:
        if profile is not ActiveWebProfile.SAFE_TEMPLATES:
            raise ValueError("unsupported Nuclei profile")
        return NucleiProfile(
            profile_id=profile.value,
            version="nuclei-safe-templates-v1",
            template_ids=("aegis-safe-lab-candidate",),
            template_paths=(self._approved_inventory(self.settings.nuclei_safe_template, "nuclei"),),
            concurrency=2,
            rate_limit=5,
            request_timeout_seconds=5,
            max_duration_seconds=30,
            max_results=500,
        )

    @staticmethod
    def _profile_version(profile: ActiveWebProfile) -> str:
        return {
            ActiveWebProfile.WEB_CONTENT_SMALL: "ffuf-web-content-small-v1",
            ActiveWebProfile.WEB_CONTENT_STANDARD: "ffuf-web-content-standard-v1",
            ActiveWebProfile.SAFE_TEMPLATES: "nuclei-safe-templates-v1",
        }[profile]

    @staticmethod
    def _approved_inventory(path: Path, directory: str) -> Path:
        root = (Path(__file__).resolve().parent / directory).resolve()
        resolved = path.resolve(strict=True)
        if resolved.parent != root or resolved.is_symlink() or not resolved.is_file():
            raise ValueError("inventory path is outside the approved configured inventory")
        return resolved

    @staticmethod
    def _resource_url(resource: object) -> str:
        default = 443 if resource.scheme == "https" else 80
        port = "" if resource.effective_port == default else f":{resource.effective_port}"
        return f"{resource.scheme}://{resource.host}{port}{resource.path}"

    def _ffuf_target(self, resource: object) -> str:
        path = resource.path
        if not path.endswith("/"):
            path = path.rsplit("/", 1)[0] + "/"
        default = 443 if resource.scheme == "https" else 80
        port = "" if resource.effective_port == default else f":{resource.effective_port}"
        return f"{resource.scheme}://{resource.host}{port}{path}FUZZ"

    @staticmethod
    def _approval_required(mode: ApprovalMode) -> bool:
        if mode is ApprovalMode.APPROVE_EVERY_ACTION:
            return True
        return mode is ApprovalMode.APPROVE_HIGHER_COST

    @staticmethod
    def _remaining_requests(budget: object | None) -> int | None:
        return None if budget is None else max(0, budget.max_requests - budget.consumed_requests)

    @staticmethod
    def _remaining_tool_runs(budget: object | None) -> int | None:
        return None if budget is None else max(0, budget.max_tool_runs - budget.consumed_tool_runs)

    @staticmethod
    def _remaining_duration(budget: object | None) -> float | None:
        return (
            None
            if budget is None
            else max(0.0, budget.max_duration_seconds - budget.consumed_duration_seconds)
        )

    @staticmethod
    def _policy_error(reason: str) -> ToolErrorCode:
        try:
            return ToolErrorCode(reason)
        except ValueError:
            return ToolErrorCode.POLICY_REJECTED

    def _mark_running(self, plan: DiscoveryPlan, run: ToolRun, started: object) -> None:
        with self.database.session_factory.begin() as session:
            r = RepositorySet(session)
            r.discovery_plans.update(
                plan.model_copy(update={"status": DiscoveryPlanStatus.RUNNING, "started_at": started})
            )
            r.tool_runs.update(run.model_copy(update={"status": ToolRunStatus.RUNNING}))

    def _ffuf_observations(self, records, asset_id: UUID, run: ToolRun, artifact: ToolArtifact):
        values = []
        for record in records:
            parsed = urlsplit(record.url)
            values.append(
                Observation(
                    asset_id=asset_id,
                    research_session_id=run.research_session_id,
                    request_id=f"FFUF-{hashlib.sha256(record.url.encode()).hexdigest()[:32]}",
                    tool_artifact_id=artifact.id,
                    source=ObservationSource.TOOL,
                    raw_data={"artifact_id": str(artifact.id), "tool_run_id": str(run.id)},
                    normalized_data={
                        "source_type": "ffuf_web_discovery",
                        "url": record.url,
                        "scheme": parsed.scheme,
                        "host": parsed.hostname,
                        "port": parsed.port or (443 if parsed.scheme == "https" else 80),
                        "method": "GET",
                        "path": parsed.path or "/",
                        "status_code": record.status_code,
                        "content_length": record.content_length,
                        "content_words": record.content_words,
                        "content_lines": record.content_lines,
                        "redirect_location": record.redirect_location,
                        "content_type": record.content_type,
                    },
                    trust=TrustClassification.UNTRUSTED,
                    normalized_data_trust=TrustClassification.TRUSTED,
                    provenance=Provenance(
                        source_type="ffuf",
                        source_reference=str(artifact.id),
                        collector=FFUF_PARSER_VERSION,
                        classification=FactClassification.OBSERVED,
                        metadata={
                            "tool_run_id": str(run.id),
                            "tool_artifact_id": str(artifact.id),
                            "artifact_sha256": artifact.sha256,
                            "data_trust": "UNTRUSTED_TOOL_DATA",
                        },
                    ),
                )
            )
        return tuple(values)

    @staticmethod
    def _nuclei_observations(records, asset_id: UUID, run: ToolRun, artifact: ToolArtifact):
        return assessment_observations(
            records,
            asset_id=asset_id,
            research_session_id=run.research_session_id,
            tool_artifact_id=artifact.id,
            artifact_sha256=artifact.sha256,
            provenance_source="nuclei",
            collector=NUCLEI_PARSER_VERSION,
        )

    def _rejected_result(self, preview: ActiveWebPreview, run: ToolRun, reason: str):
        return ActiveWebRunResult(
            research_session_id=preview.research_session_id,
            web_resource_ids=preview.web_resource_ids,
            capability=preview.capability,
            tool_run_id=run.id,
            tool_id=run.tool_id,
            tool_version=run.tool_version,
            profile=preview.profile,
            status=ToolRunStatus.POLICY_REJECTED,
            policy_allowed=False,
            policy_reason=reason,
            estimated_requests=preview.estimated_requests,
            timeout_seconds=preview.timeout_seconds,
            error_code=run.error_code,
            error=run.error,
        )

    def _fail_without_artifact(
        self, preview: ActiveWebPreview, plan: DiscoveryPlan, run: ToolRun, error: ToolExecutionError
    ) -> ActiveWebRunResult:
        return self._persist_failure(preview, plan, run, None, error.code, str(error), (), None)

    def _fail_with_artifact(
        self, preview, plan, run, artifact, code, error, argv, exit_code
    ) -> ActiveWebRunResult:
        return self._persist_failure(preview, plan, run, artifact, code, error, argv, exit_code)

    def _persist_failure(
        self, preview, plan, run, artifact, code, error, argv, exit_code
    ) -> ActiveWebRunResult:
        error = _redact_diagnostic(str(error))
        finished = utc_now()
        with self.database.session_factory.begin() as session:
            r = RepositorySet(session)
            if artifact is not None:
                r.tool_artifacts.update(
                    artifact.model_copy(
                        update={"parser_status": ParserStatus.FAILED, "parser_error": error}
                    )
                )
            r.tool_runs.update(
                run.model_copy(
                    update={
                        "status": ToolRunStatus.FAILED,
                        "finished_at": finished,
                        "exit_code": exit_code,
                        "artifact_ids": [artifact.id] if artifact else [],
                        "normalized_argv": argv,
                        "error_code": code,
                        "error": error[:1000],
                    }
                )
            )
            r.discovery_plans.update(
                plan.model_copy(
                    update={
                        "status": DiscoveryPlanStatus.FAILED,
                        "finished_at": finished,
                        "error": error[:1000],
                    }
                )
            )
        return ActiveWebRunResult(
            research_session_id=preview.research_session_id,
            web_resource_ids=preview.web_resource_ids,
            capability=preview.capability,
            tool_run_id=run.id,
            tool_id=run.tool_id,
            tool_version=run.tool_version,
            profile=preview.profile,
            status=ToolRunStatus.FAILED,
            policy_allowed=True,
            policy_reason="ALLOWED",
            estimated_requests=preview.estimated_requests,
            timeout_seconds=preview.timeout_seconds,
            artifact_ids=(artifact.id,) if artifact else (),
            error_code=code,
            error=error[:1000],
        )

    def _consume_budget(
        self, r: RepositorySet, session_id: UUID, requests: int, duration: float
    ) -> None:
        # The active process is one ToolRun but may amplify into many requests.
        # Consumption is clamped only after policy has proved sufficient remaining budget.
        budget = r.research_budgets.get_by_session(session_id)
        if budget is None:
            return
        r.research_budgets.update(
            budget.model_copy(
                update={
                    "consumed_tool_runs": budget.consumed_tool_runs + 1,
                    "consumed_requests": budget.consumed_requests + requests,
                    "consumed_duration_seconds": budget.consumed_duration_seconds + duration,
                    "updated_at": utc_now(),
                }
            )
        )

    def _surface_state(self, session_id: UUID):
        with self.database.session_factory() as session:
            r = RepositorySet(session)
            snapshots = r.web_surface_snapshots.list_by_session(session_id)
            resources = r.web_resources.list_by_session(session_id)
            candidates = r.web_template_candidates.list_by_session(session_id)
        return (
            snapshots[-1].web_surface_sha256 if snapshots else None,
            {item.canonical_key for item in resources},
            len(candidates),
        )

    def _finding_count(self, session_id: UUID) -> int:
        with self.database.session_factory() as session:
            return len(RepositorySet(session).findings.list_by_session(session_id))

    @staticmethod
    def _record_key(record: object) -> str | None:
        url = getattr(record, "url", None) or getattr(record, "matched_url", None)
        if not isinstance(url, str):
            return None
        from app.web_surface.pipeline import canonical_resource_key

        return canonical_resource_key("GET", url)
