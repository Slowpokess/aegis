from dataclasses import dataclass
from time import monotonic
from uuid import UUID

from app.attack_graph.builder import AttackGraphBuilder
from app.config import Settings
from app.controller.acquisition import (
    ActionIntentBridge,
    ActionValidation,
    EvidenceAcquirer,
    ResearchActionValidator,
    _provenance,
)
from app.controller.context import ControllerContextBuilder
from app.controller.planner import DeterministicControllerPlanner, LLMControllerPlanner
from app.controller.satisfaction import ResearchActionSatisfactionEvaluator
from app.domain.common import utc_now
from app.domain.controller import (
    ActionSatisfaction,
    ControllerDecision,
    ControllerDecisionType,
    ControllerStatus,
    ControllerStep,
    ControllerStepStatus,
    AssessWebTemplatesActionProposal,
    DiscoverWebContentActionProposal,
    ExpectedEvidence,
    ExpectedEvidenceType,
    ResearchAction,
    ResearchActionPurpose,
    ResearchActionResult,
    ResearchActionStatus,
    ResearchActionType,
    ResearchBudget,
    action_semantic_hash,
)
from app.domain.operator import (
    ActionApproval,
    ApprovalMode,
    ApprovalStatus,
    ControllerMode,
    EvidenceNovelty,
    ProjectStatus,
    ResearchPolicy,
    ResearchProject,
)
from app.domain.discovery import ToolCapability
from app.domain.research_planner import ResearchIntentStatus
from app.domain.research_strategy import StrategyRun
from app.llm.base import LLMGenerationMetadata, LLMProvider, LLMProviderError
from app.operator.policy import AdaptiveResearchPolicy
from app.research_planner.validator import intent_semantic_key
from app.research_strategy.strategy import ResearchStrategyEngine
from app.storage.database import Database
from app.storage.repositories import RepositorySet
from app.system_model.builder import SystemModelBuilder


@dataclass(frozen=True)
class ControllerStepResult:
    step: ControllerStep
    actions: tuple[ResearchAction, ...]
    results: tuple[ResearchActionResult, ...]
    decision: ControllerDecision


@dataclass(frozen=True)
class ControllerRunResult:
    session_id: UUID
    steps: tuple[ControllerStepResult, ...]
    stop_reason: str


class ClosedLoopResearchController:
    version = "closed-loop-controller-v1"

    def __init__(
        self,
        database: Database,
        settings: Settings,
        strategy: ResearchStrategyEngine,
        context_builder: ControllerContextBuilder,
        acquirer: EvidenceAcquirer,
        *,
        provider: LLMProvider | None = None,
        max_actions_per_step: int = 2,
    ) -> None:
        self.database = database
        self.settings = settings
        self.strategy = strategy
        self.context_builder = context_builder
        self.acquirer = acquirer
        self.provider = provider
        self.deterministic_planner = DeterministicControllerPlanner()
        self.validator = ResearchActionValidator(
            experimental_mode=settings.controller_experimental_mode
        )
        self.intent_bridge = ActionIntentBridge()
        self.satisfaction = ResearchActionSatisfactionEvaluator()
        self.adaptive_policy = AdaptiveResearchPolicy()
        self.max_actions_per_step = max_actions_per_step

    def ensure_budget(self, session_id: UUID) -> ResearchBudget:
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            if repositories.research_sessions.get(session_id) is None:
                raise ValueError("research session does not exist")
            existing = repositories.research_budgets.get_by_session(session_id)
            if existing:
                return existing
            budget = ResearchBudget(
                research_session_id=session_id,
                max_steps=self.settings.controller_max_steps,
                max_actions=self.settings.controller_max_actions,
                max_tool_runs=self.settings.controller_max_tool_runs,
                max_requests=self.settings.controller_max_requests,
                max_duration_seconds=self.settings.controller_max_duration_seconds,
                max_llm_calls=self.settings.controller_max_llm_calls,
                allowed_capabilities=self.settings.controller_allowed_capabilities,
                provenance=_provenance("research_budget", str(session_id)),
            )
            repositories.research_budgets.add(budget)
            return budget

    async def plan(
        self, session_id: UUID, *, decision: ControllerDecision | None = None
    ) -> ControllerStepResult:
        return await self.step(session_id, decision=decision, execute=False)

    async def step(
        self,
        session_id: UUID,
        *,
        decision: ControllerDecision | None = None,
        execute: bool = True,
        operator_initiated: bool = False,
    ) -> ControllerStepResult:
        started_clock = monotonic()
        budget = self.ensure_budget(session_id)
        project, research_policy = self._project_policy(session_id)
        experimental_mode = self.settings.controller_experimental_mode or bool(
            project and project.controller_mode is ControllerMode.EXPERIMENTAL
        )
        max_semantic_repeats = (
            research_policy.settings.max_repeated_semantic_action_count
            if research_policy
            else self.settings.controller_max_semantic_repeats
        )
        if project and project.status is ProjectStatus.CANCELLED:
            return self._persist_stop_step(
                session_id,
                budget,
                ControllerDecisionType.STOP_USER_REQUEST,
                "project is cancelled",
            )
        budget_reason = budget.exhausted_reason()
        if budget_reason == "max_llm_calls" and self.provider is None:
            budget_reason = None
        if budget.pause_requested or budget.controller_status is ControllerStatus.PAUSED:
            return self._persist_stop_step(
                session_id,
                budget,
                ControllerDecisionType.STOP_USER_REQUEST,
                "controller is paused",
            )
        if budget_reason:
            return self._persist_stop_step(
                session_id,
                budget,
                ControllerDecisionType.STOP_LIMIT_REACHED,
                f"research budget exhausted: {budget_reason}",
            )
        self.reconcile(session_id)
        strategy_run, _ = self.strategy.plan(session_id)
        if research_policy:
            strategy_run = self._adapt_strategy(session_id, strategy_run, research_policy, budget)
        context = self.context_builder.build(session_id, budget, strategy_run)
        with self.database.session_factory() as session:
            repositories = RepositorySet(session)
            prior_steps = repositories.controller_steps.list_by_session(session_id)
        step = ControllerStep(
            research_session_id=session_id,
            step_number=len(prior_steps) + 1,
            context_hash=context.sha256,
            knowledge_hash=context.knowledge_hash,
            model_hash=context.model_hash,
            graph_hash=context.graph_hash,
            provider=(self.provider.provider_name if self.provider else "deterministic"),
            model=(self.provider.model_name if self.provider else "closed-loop-rules-v1"),
            budget_before=self._budget_payload(budget),
            provenance=_provenance("controller_step", context.sha256),
        )
        metadata: LLMGenerationMetadata | None = None
        llm_called = False
        try:
            if decision is None and self.provider is not None:
                generated = await LLMControllerPlanner(
                    self.provider,
                    max_actions=self.max_actions_per_step,
                    experimental_mode=experimental_mode,
                ).decide(context, step.id)
                decision = generated.output
                metadata = generated.metadata
                llm_called = True
            elif decision is None:
                decision = self.deterministic_planner.decide(context)
            self._validate_decision(decision, session_id)
        except (LLMProviderError, ValueError) as error:
            failed_decision = ControllerDecision(
                session_id=session_id,
                decision_type=ControllerDecisionType.INCONCLUSIVE,
                stop_reason=f"controller decision rejected: {type(error).__name__}",
                limitations=(str(error),),
            )
            failed_step = step.model_copy(
                update={
                    "decision": failed_decision,
                    "decision_hash": failed_decision.sha256,
                    "decision_type": failed_decision.decision_type,
                    "status": ControllerStepStatus.FAILED,
                    "stop_reason": failed_decision.stop_reason,
                    "finished_at": utc_now(),
                }
            )
            with self.database.session_factory.begin() as session:
                repositories = RepositorySet(session)
                repositories.controller_steps.add(failed_step)
                if execute:
                    self._consume_budget(repositories, budget, steps=1, llm_calls=int(llm_called))
            if project and isinstance(error, LLMProviderError):
                from app.domain.operator import EventSeverity, ResearchEventType
                from app.operator.service import ResearchEventService

                ResearchEventService(self.database).emit(
                    project.id,
                    ResearchEventType.LLM_PROVIDER_ERROR,
                    "ControllerStep",
                    str(failed_step.id),
                    "Configured LLM provider returned an error",
                    session_id=session_id,
                    severity=EventSeverity.ERROR,
                    data={
                        "provider": self.provider.provider_name if self.provider else None,
                        "model": self.provider.model_name if self.provider else None,
                        "error_type": type(error).__name__,
                    },
                )
            return ControllerStepResult(failed_step, (), (), failed_decision)
        assert decision is not None
        planned_step = step.model_copy(
            update={
                "decision": decision,
                "decision_hash": decision.sha256,
                "decision_type": decision.decision_type,
                "status": ControllerStepStatus.PLANNED,
                "provider_request_id": metadata.provider_request_id if metadata else None,
                "input_tokens": metadata.usage.input_tokens if metadata else None,
                "output_tokens": metadata.usage.output_tokens if metadata else None,
                "latency_ms": metadata.latency_ms if metadata else None,
            }
        )
        with self.database.session_factory.begin() as session:
            RepositorySet(session).controller_steps.add(planned_step)
        if decision.decision_type is not ControllerDecisionType.CONTINUE:
            completed = planned_step.model_copy(
                update={
                    "status": ControllerStepStatus.COMPLETED,
                    "stop_reason": decision.stop_reason,
                    "finished_at": utc_now(),
                    "budget_after": self._budget_payload(budget),
                }
            )
            with self.database.session_factory.begin() as session:
                repositories = RepositorySet(session)
                repositories.controller_steps.update(completed)
                if execute:
                    status = (
                        ControllerStatus.COMPLETED
                        if decision.decision_type is ControllerDecisionType.STOP_SUFFICIENT_EVIDENCE
                        else ControllerStatus.INCONCLUSIVE
                    )
                    self._consume_budget(
                        repositories,
                        budget,
                        steps=1,
                        llm_calls=int(llm_called),
                        status=status,
                        stop_reason=decision.stop_reason,
                    )
                    if project:
                        repositories.research_projects.update(
                            project.model_copy(
                                update={
                                    "status": (
                                        ProjectStatus.COMPLETED
                                        if status is ControllerStatus.COMPLETED
                                        else ProjectStatus.INCONCLUSIVE
                                    ),
                                    "updated_at": utc_now(),
                                }
                            )
                        )
            return ControllerStepResult(completed, (), (), decision)
        actions, validations = self._persist_and_validate_actions(
            planned_step,
            decision,
            project=project,
            experimental_mode=experimental_mode,
            max_semantic_repeats=max_semantic_repeats,
            research_policy=research_policy,
            operator_initiated=operator_initiated,
        )
        planned_step = planned_step.model_copy(
            update={"action_ids": tuple(action.id for action in actions)}
        )
        with self.database.session_factory.begin() as session:
            RepositorySet(session).controller_steps.update(planned_step)
        if not execute:
            return ControllerStepResult(planned_step, tuple(actions), (), decision)
        waiting = await self._prepare_approvals(project, actions, validations)
        if waiting:
            waiting_step = planned_step.model_copy(
                update={
                    "status": ControllerStepStatus.WAITING_FOR_APPROVAL,
                    "stop_reason": "operator approval required",
                    "finished_at": utc_now(),
                }
            )
            with self.database.session_factory.begin() as session:
                repositories = RepositorySet(session)
                current = repositories.research_budgets.get_by_session(session_id) or budget
                after = self._consume_budget(
                    repositories,
                    current,
                    steps=1,
                    llm_calls=int(llm_called),
                    status=ControllerStatus.WAITING_FOR_APPROVAL,
                    stop_reason="operator approval required",
                )
                repositories.controller_steps.update(
                    waiting_step.model_copy(update={"budget_after": self._budget_payload(after)})
                )
            return ControllerStepResult(waiting_step, tuple(actions), (), decision)
        results: list[ResearchActionResult] = []
        executed_actions: list[ResearchAction] = []
        for action, validation in zip(actions, validations, strict=True):
            if action.status is ResearchActionStatus.REJECTED:
                executed_actions.append(action)
                continue
            capability = {
                ResearchActionType.HTTP_OBSERVE: ToolCapability.HTTP_REQUEST,
                ResearchActionType.SERVICE_DISCOVERY: ToolCapability.SERVICE_DISCOVERY,
                ResearchActionType.DNS_RESOLVE: ToolCapability.DNS_LOOKUP,
                ResearchActionType.TLS_INSPECT: ToolCapability.TLS_INSPECTION,
                ResearchActionType.DISCOVER_WEB_CONTENT: ToolCapability.WEB_CONTENT_DISCOVERY,
                ResearchActionType.ASSESS_WEB_TEMPLATES: ToolCapability.TEMPLATE_ASSESSMENT,
            }.get(action.action_type)
            if (
                capability is not None
                and budget.allowed_capabilities
                and capability not in budget.allowed_capabilities
            ):
                executed_actions.append(
                    self._update_action(
                        action,
                        status=ResearchActionStatus.REJECTED,
                        failure_reason="CAPABILITY_NOT_AUTHORIZED_BY_BUDGET",
                    )
                )
                continue
            if budget.consumed_actions + len(results) >= budget.max_actions:
                executed_actions.append(
                    self._update_action(
                        action,
                        status=ResearchActionStatus.CANCELLED,
                        failure_reason="ACTION_BUDGET_EXHAUSTED",
                    )
                )
                break
            used_tool_runs = sum(len(item.tool_run_ids) for item in results)
            if budget.consumed_tool_runs + used_tool_runs >= budget.max_tool_runs:
                executed_actions.append(
                    self._update_action(
                        action,
                        status=ResearchActionStatus.CANCELLED,
                        failure_reason="TOOL_RUN_BUDGET_EXHAUSTED",
                    )
                )
                break
            used_requests = sum(
                1
                for completed_action in executed_actions
                if completed_action.action_type is ResearchActionType.HTTP_OBSERVE
                and completed_action.status
                in {ResearchActionStatus.SATISFIED, ResearchActionStatus.UNSATISFIED}
            )
            if (
                action.action_type is ResearchActionType.HTTP_OBSERVE
                and budget.consumed_requests + used_requests >= budget.max_requests
            ):
                executed_actions.append(
                    self._update_action(
                        action,
                        status=ResearchActionStatus.CANCELLED,
                        failure_reason="REQUEST_BUDGET_EXHAUSTED",
                    )
                )
                break
            updated, result = await self._execute_action(planned_step, action, validation)
            executed_actions.append(updated)
            if result:
                results.append(result)
        model_hash, graph_hash, knowledge_hash = self._rebuild(session_id)
        executed_actions = self._reevaluate_actions(executed_actions, results)
        elapsed = monotonic() - started_clock
        tool_runs = sum(len(item.tool_run_ids) for item in results)
        requests = sum(
            1
            for action in executed_actions
            if action.action_type is ResearchActionType.HTTP_OBSERVE
            and action.status in {ResearchActionStatus.SATISFIED, ResearchActionStatus.UNSATISFIED}
        ) + sum(item.request_cost for item in results)
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            current_budget = repositories.research_budgets.get_by_session(session_id) or budget
            after = self._consume_budget(
                repositories,
                current_budget,
                steps=1,
                actions=len(results),
                tool_runs=tool_runs,
                requests=requests,
                llm_calls=int(llm_called),
                duration=elapsed,
                status=ControllerStatus.RUNNING,
            )
            completed = planned_step.model_copy(
                update={
                    "status": ControllerStepStatus.COMPLETED,
                    "budget_after": self._budget_payload(after),
                    "model_hash": model_hash,
                    "graph_hash": graph_hash,
                    "knowledge_hash": knowledge_hash,
                    "finished_at": utc_now(),
                }
            )
            repositories.controller_steps.update(completed)
        return ControllerStepResult(completed, tuple(executed_actions), tuple(results), decision)

    async def request_web_discovery(
        self,
        session_id: UUID,
        resource_id: UUID,
        profile: str,
    ) -> ControllerStepResult:
        """Persist an operator-requested ffuf action and use the Phase 13 authority path."""
        proposal = DiscoverWebContentActionProposal(
            research_session_id=session_id,
            action_type=ResearchActionType.DISCOVER_WEB_CONTENT,
            purpose=ResearchActionPurpose.WEB_CONTENT_ENUMERATION,
            subject_entity_id=resource_id,
            target_entity_id=resource_id,
            resource_entity_id=resource_id,
            web_resource_id=resource_id,
            profile=profile,
            expected_information=(
                ExpectedEvidence(information=ExpectedEvidenceType.WEB_RESOURCE),
            ),
            rationale="Operator requested bounded Web content discovery.",
        )
        return await self.step(
            session_id,
            decision=ControllerDecision(
                session_id=session_id,
                decision_type=ControllerDecisionType.CONTINUE,
                actions=(proposal,),
            ),
            execute=True,
            operator_initiated=True,
        )

    async def request_web_assessment(
        self,
        session_id: UUID,
        resource_ids: tuple[UUID, ...],
        profile: str,
    ) -> ControllerStepResult:
        """Persist an operator-requested Nuclei action and use the Phase 13 authority path."""
        if not resource_ids:
            raise ValueError("Nuclei assessment requires at least one WebResource")
        proposal = AssessWebTemplatesActionProposal(
            research_session_id=session_id,
            action_type=ResearchActionType.ASSESS_WEB_TEMPLATES,
            purpose=ResearchActionPurpose.WEB_TEMPLATE_ASSESSMENT,
            subject_entity_id=resource_ids[0],
            target_entity_id=resource_ids[0],
            resource_entity_id=resource_ids[0],
            web_resource_ids=resource_ids,
            profile=profile,
            expected_information=(
                ExpectedEvidence(information=ExpectedEvidenceType.TEMPLATE_CANDIDATE),
            ),
            rationale="Operator requested bounded safe-template assessment.",
        )
        return await self.step(
            session_id,
            decision=ControllerDecision(
                session_id=session_id,
                decision_type=ControllerDecisionType.CONTINUE,
                actions=(proposal,),
            ),
            execute=True,
            operator_initiated=True,
        )

    async def run(self, session_id: UUID) -> ControllerRunResult:
        output: list[ControllerStepResult] = []
        while True:
            result = await self.step(session_id)
            output.append(result)
            if result.decision.decision_type is not ControllerDecisionType.CONTINUE:
                return ControllerRunResult(
                    session_id,
                    tuple(output),
                    result.decision.stop_reason or result.decision.decision_type.value,
                )
            if any(
                action.status is ResearchActionStatus.WAITING_FOR_APPROVAL
                for action in result.actions
            ):
                return ControllerRunResult(session_id, tuple(output), "operator approval required")
            budget = self.ensure_budget(session_id)
            if budget.pause_requested:
                return ControllerRunResult(session_id, tuple(output), "controller paused")

    def pause(self, session_id: UUID) -> ResearchBudget:
        budget = self.ensure_budget(session_id)
        with self.database.session_factory.begin() as session:
            updated = budget.model_copy(
                update={
                    "pause_requested": True,
                    "controller_status": ControllerStatus.PAUSED,
                    "updated_at": utc_now(),
                }
            )
            RepositorySet(session).research_budgets.update(updated)
        project, _ = self._project_policy(session_id)
        if project:
            with self.database.session_factory.begin() as session:
                RepositorySet(session).research_projects.update(
                    project.model_copy(update={"status": ProjectStatus.PAUSED, "updated_at": utc_now()})
                )
            from app.domain.operator import ResearchEventType
            from app.operator.service import ResearchEventService

            ResearchEventService(self.database).emit(
                project.id,
                ResearchEventType.CONTROLLER_PAUSED,
                "ResearchBudget",
                str(updated.id),
                "Controller paused at a safe boundary",
                session_id=session_id,
                key=f"controller-paused:{updated.id}:{updated.updated_at.isoformat()}",
            )
        return updated

    async def resume(self, session_id: UUID) -> ControllerRunResult:
        budget = self.ensure_budget(session_id)
        project, _ = self._project_policy(session_id)
        if budget.controller_status is ControllerStatus.CANCELLED or (
            project and project.status is ProjectStatus.CANCELLED
        ):
            raise ValueError("cancelled controller cannot be resumed")
        with self.database.session_factory.begin() as session:
            updated = budget.model_copy(
                update={
                    "pause_requested": False,
                    "controller_status": ControllerStatus.READY,
                    "stop_reason": None,
                    "updated_at": utc_now(),
                }
            )
            RepositorySet(session).research_budgets.update(updated)
        if project:
            with self.database.session_factory.begin() as session:
                RepositorySet(session).research_projects.update(
                    project.model_copy(update={"status": ProjectStatus.RUNNING, "updated_at": utc_now()})
                )
            from app.domain.operator import ResearchEventType
            from app.operator.service import ResearchEventService

            ResearchEventService(self.database).emit(
                project.id,
                ResearchEventType.CONTROLLER_RESUMED,
                "ResearchBudget",
                str(updated.id),
                "Controller resumed with persisted budget",
                session_id=session_id,
                key=f"controller-resumed:{updated.id}:{updated.updated_at.isoformat()}",
            )
        self.reconcile(session_id)
        return await self.run(session_id)

    def reconcile(self, session_id: UUID) -> None:
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            for action in repositories.research_actions.list_by_session(session_id):
                if action.status is not ResearchActionStatus.EXECUTING:
                    continue
                result = repositories.research_action_results.get_by_action(action.id)
                if result is not None:
                    repositories.research_actions.update(
                        action.model_copy(
                            update={
                                "status": result.status,
                                "tool_run_ids": result.tool_run_ids,
                                "evidence_ids": result.evidence_ids,
                                "observation_ids": result.observation_ids,
                                "verification_result_ids": result.verification_result_ids,
                                "satisfaction": result.satisfaction,
                                "finished_at": result.finished_at,
                            }
                        )
                    )
                    continue
                runs = [repositories.tool_runs.get(item) for item in action.tool_run_ids]
                completed = [item for item in runs if item and item.status.value == "COMPLETED"]
                if completed and len(completed) == len(runs):
                    repositories.research_actions.update(
                        action.model_copy(
                            update={
                                "status": ResearchActionStatus.COMPLETED,
                                "observation_ids": tuple(
                                    observation
                                    for run in completed
                                    for observation in run.observation_ids
                                ),
                                "finished_at": utc_now(),
                            }
                        )
                    )

    def _persist_and_validate_actions(
        self,
        step: ControllerStep,
        decision: ControllerDecision,
        *,
        project: ResearchProject | None,
        experimental_mode: bool,
        max_semantic_repeats: int,
        research_policy: ResearchPolicy | None,
        operator_initiated: bool = False,
    ) -> tuple[list[ResearchAction], list[ActionValidation]]:
        actions: list[ResearchAction] = []
        validations: list[ActionValidation] = []
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            for proposal in decision.actions:
                action = ResearchAction(
                    controller_step_id=step.id,
                    research_session_id=proposal.research_session_id,
                    action_type=proposal.action_type,
                    purpose=proposal.purpose,
                    proposal=proposal,
                    semantic_hash=action_semantic_hash(proposal),
                    operator_initiated=operator_initiated,
                    provenance=_provenance("research_action", step.context_hash),
                )
                repositories.research_actions.add(action)
                validation = self.validator.validate(
                    repositories,
                    proposal,
                    experimental_mode=experimental_mode,
                    max_semantic_repeats=max_semantic_repeats,
                    allow_action_repetition=(
                        research_policy.settings.allow_action_repetition
                        if research_policy
                        else None
                    ),
                    allow_closed_gap_revisit=(
                        research_policy.settings.allow_closed_gap_revisit
                        if research_policy
                        else None
                    ),
                    allow_off_gap_exploration=(
                        True
                        if operator_initiated
                        else (
                            research_policy.settings.allow_off_gap_exploration
                            if research_policy
                            else None
                        )
                    ),
                )
                if project and hasattr(proposal, "identity_entity_id"):
                    identity_id = getattr(proposal, "identity_entity_id", None)
                    identity = (
                        repositories.system_identities.get(identity_id) if identity_id else None
                    )
                    if (
                        identity
                        and project.identity_names
                        and identity.name not in project.identity_names
                    ):
                        validation = ActionValidation(False, "IDENTITY_BLOCKED_BY_PROJECT")
                if project and proposal.action_type in project.blocked_action_types:
                    validation = ActionValidation(False, "ACTION_TYPE_BLOCKED_BY_OPERATOR")
                status = (
                    ResearchActionStatus.VALIDATED
                    if validation.allowed
                    else ResearchActionStatus.REJECTED
                )
                action = action.model_copy(
                    update={"status": status, "validation_reason": validation.reason}
                )
                repositories.research_actions.update(action)
                if validation.allowed:
                    intent = self.intent_bridge.create(repositories, step, action)
                    if intent:
                        action = action.model_copy(update={"research_intent_id": intent.id})
                        repositories.research_actions.update(action)
                actions.append(action)
                validations.append(validation)
        return actions, validations

    async def _prepare_approvals(
        self,
        project: ResearchProject | None,
        actions: list[ResearchAction],
        validations: list[ActionValidation],
    ) -> bool:
        if project is None or project.approval_mode is ApprovalMode.AUTO:
            return False
        waiting = False
        high_cost = {
            ResearchActionType.SERVICE_DISCOVERY,
            ResearchActionType.REPRODUCE_EXPERIMENT,
            ResearchActionType.DISCOVER_WEB_CONTENT,
            ResearchActionType.ASSESS_WEB_TEMPLATES,
        }
        previews: dict[UUID, tuple[bool, str]] = {}
        for action, validation in zip(actions, validations, strict=True):
            if action.status is not ResearchActionStatus.REJECTED:
                previews[action.id] = await self.acquirer.preview_policy(action, validation)
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            for index, action in enumerate(actions):
                if action.status is ResearchActionStatus.REJECTED:
                    continue
                required = (
                    project.approval_mode is ApprovalMode.APPROVE_EVERY_ACTION
                    or action.action_type in high_cost
                )
                if not required:
                    continue
                preview_allowed, preview_reason = previews[action.id]
                if not preview_allowed:
                    updated = action.model_copy(
                        update={
                            "status": ResearchActionStatus.REJECTED,
                            "failure_reason": f"POLICY_PREVIEW_REJECTED:{preview_reason}",
                            "finished_at": utc_now(),
                        }
                    )
                    repositories.research_actions.update(updated)
                    actions[index] = updated
                    continue
                approval = repositories.action_approvals.get_by_action(action.id)
                if approval is None:
                    approval = ActionApproval(
                        project_id=project.id,
                        research_session_id=action.research_session_id,
                        action_id=action.id,
                        policy_preview_allowed=True,
                        policy_preview_reason=preview_reason,
                        provenance=_provenance("action_approval", str(action.id)),
                    )
                    repositories.action_approvals.add(approval)
                updated = action.model_copy(
                    update={"status": ResearchActionStatus.WAITING_FOR_APPROVAL}
                )
                repositories.research_actions.update(updated)
                actions[index] = updated
                waiting = True
        return waiting

    async def approve_action(self, action_id: UUID, *, reason: str | None = None) -> ResearchAction:
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            action = repositories.research_actions.get(action_id)
            approval = repositories.action_approvals.get_by_action(action_id)
            if action is None or approval is None:
                raise ValueError("pending action approval does not exist")
            if approval.status is not ApprovalStatus.PENDING:
                raise ValueError("action approval is already resolved")
            step = repositories.controller_steps.get(action.controller_step_id)
            if step is None:
                raise ValueError("controller step does not exist")
            repositories.action_approvals.update(
                approval.model_copy(
                    update={
                        "status": ApprovalStatus.APPROVED,
                        "resolved_at": utc_now(),
                        "reason": reason,
                    }
                )
            )
            project, policy = self._project_policy_from_repositories(
                repositories, action.research_session_id
            )
            experimental = self.settings.controller_experimental_mode or bool(
                project and project.controller_mode is ControllerMode.EXPERIMENTAL
            )
            max_repeats = (
                policy.settings.max_repeated_semantic_action_count
                if policy
                else self.settings.controller_max_semantic_repeats
            )
            validation = self.validator.validate(
                repositories,
                action.proposal,
                experimental_mode=experimental,
                max_semantic_repeats=max_repeats,
                allow_action_repetition=(
                    policy.settings.allow_action_repetition if policy else None
                ),
                allow_closed_gap_revisit=(
                    policy.settings.allow_closed_gap_revisit if policy else None
                ),
                allow_off_gap_exploration=(
                    True
                    if action.operator_initiated
                    else (policy.settings.allow_off_gap_exploration if policy else None)
                ),
            )
            if not validation.allowed:
                rejected = action.model_copy(
                    update={
                        "status": ResearchActionStatus.REJECTED,
                        "failure_reason": validation.reason,
                        "finished_at": utc_now(),
                    }
                )
                repositories.research_actions.update(rejected)
                return rejected
        updated, result = await self._execute_action(step, action, validation)
        project, _ = self._project_policy(action.research_session_id)
        if project:
            from app.domain.operator import ResearchEventType
            from app.operator.service import ResearchEventService

            ResearchEventService(self.database).emit(
                project.id,
                ResearchEventType.ACTION_APPROVED,
                "ResearchAction",
                str(action.id),
                "Operator approved policy-previewed action",
                session_id=action.research_session_id,
            )
        self._rebuild(action.research_session_id)
        updated = self._reevaluate_actions([updated], [result] if result is not None else [])[0]
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            budget = repositories.research_budgets.get_by_session(action.research_session_id)
            if budget and result:
                self._consume_budget(
                    repositories,
                    budget,
                    actions=1,
                    tool_runs=len(result.tool_run_ids),
                    requests=(
                        int(action.action_type is ResearchActionType.HTTP_OBSERVE)
                        + result.request_cost
                    ),
                    status=ControllerStatus.READY,
                    stop_reason=None,
                )
        return updated

    def reject_action(self, action_id: UUID, *, reason: str | None = None) -> ResearchAction:
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            action = repositories.research_actions.get(action_id)
            approval = repositories.action_approvals.get_by_action(action_id)
            if action is None or approval is None or approval.status is not ApprovalStatus.PENDING:
                raise ValueError("pending action approval does not exist")
            repositories.action_approvals.update(
                approval.model_copy(
                    update={
                        "status": ApprovalStatus.REJECTED,
                        "resolved_at": utc_now(),
                        "reason": reason,
                    }
                )
            )
            rejected = action.model_copy(
                update={
                    "status": ResearchActionStatus.REJECTED,
                    "failure_reason": "OPERATOR_REJECTED",
                    "finished_at": utc_now(),
                }
            )
            repositories.research_actions.update(rejected)
            budget = repositories.research_budgets.get_by_session(action.research_session_id)
            if budget:
                repositories.research_budgets.update(
                    budget.model_copy(
                        update={
                            "controller_status": ControllerStatus.READY,
                            "stop_reason": None,
                            "updated_at": utc_now(),
                        }
                    )
                )
            return rejected

    def stop(self, session_id: UUID) -> ResearchBudget:
        budget = self.ensure_budget(session_id)
        with self.database.session_factory.begin() as session:
            updated = budget.model_copy(
                update={
                    "controller_status": ControllerStatus.CANCELLED,
                    "stop_reason": "operator stopped controller",
                    "pause_requested": True,
                    "updated_at": utc_now(),
                }
            )
            RepositorySet(session).research_budgets.update(updated)
        project, _ = self._project_policy(session_id)
        if project:
            with self.database.session_factory.begin() as session:
                RepositorySet(session).research_projects.update(
                    project.model_copy(
                        update={"status": ProjectStatus.CANCELLED, "updated_at": utc_now()}
                    )
                )
            from app.domain.operator import ResearchEventType
            from app.operator.service import ResearchEventService

            ResearchEventService(self.database).emit(
                project.id,
                ResearchEventType.CONTROLLER_STOPPED,
                "ResearchBudget",
                str(updated.id),
                "Controller stopped by operator",
                session_id=session_id,
            )
        return updated

    def _project_policy(
        self, session_id: UUID
    ) -> tuple[ResearchProject | None, ResearchPolicy | None]:
        with self.database.session_factory() as session:
            return self._project_policy_from_repositories(RepositorySet(session), session_id)

    @staticmethod
    def _project_policy_from_repositories(
        repositories: RepositorySet, session_id: UUID
    ) -> tuple[ResearchProject | None, ResearchPolicy | None]:
        research = repositories.research_sessions.get(session_id)
        if research is None or research.project_id is None:
            return None, None
        project = repositories.research_projects.get(research.project_id)
        if project is None:
            return None, None
        return project, repositories.research_policies.get(project.research_policy_id)

    def _adapt_strategy(
        self,
        session_id: UUID,
        strategy_run: StrategyRun,
        policy: ResearchPolicy,
        budget: ResearchBudget,
    ) -> StrategyRun:
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            prior_keys = {
                item.semantic_key
                for item in repositories.research_intents.list_by_session(session_id)
            }
            remaining_ratio = min(
                (budget.max_actions - budget.consumed_actions) / budget.max_actions,
                (budget.max_steps - budget.consumed_steps) / budget.max_steps,
            )
            adjusted = []
            for candidate in strategy_run.candidates:
                novelty = (
                    EvidenceNovelty.NONE
                    if intent_semantic_key(session_id, candidate.proposed_intent) in prior_keys
                    else EvidenceNovelty.HIGH
                )
                score = self.adaptive_policy.effective_priority(
                    candidate,
                    policy,
                    novelty=novelty,
                    remaining_budget_ratio=remaining_ratio,
                )
                adjusted.append(
                    candidate.model_copy(
                        update={
                            "priority_score": score,
                            "selection_reason": (
                                f"{candidate.selection_reason}; policy={policy.profile.value}; "
                                f"novelty={novelty.value}; effective_priority={score}"
                            ),
                            "selected": False,
                        }
                    )
                )
            adjusted.sort(
                key=lambda item: (
                    -item.priority_score,
                    tuple(str(value) for value in item.gap_ids),
                )
            )
            selected = 0
            final = []
            for candidate in adjusted:
                choose = bool(
                    candidate.policy_allowed
                    and candidate.priority_score >= policy.settings.min_information_gain
                    and selected < self.strategy.max_selected_intents
                )
                if choose:
                    selected += 1
                final.append(candidate.model_copy(update={"selected": choose}))
            updated = strategy_run.model_copy(
                update={"candidates": tuple(final), "selected_intent_count": selected}
            )
            repositories.strategy_runs.update(updated)
            return updated

    async def _execute_action(
        self, step: ControllerStep, action: ResearchAction, validation: ActionValidation
    ) -> tuple[ResearchAction, ResearchActionResult | None]:
        executing = self._update_action(action, status=ResearchActionStatus.EXECUTING)
        try:
            if action.action_type is ResearchActionType.HTTP_OBSERVE:
                contract, plan, run = await self.acquirer.authorize_http(action, validation)
                executing = self._update_action(
                    executing,
                    status=ResearchActionStatus.AUTHORIZED,
                    contract=contract,
                    discovery_plan_id=plan.id,
                    tool_run_ids=(run.id,),
                )
                if contract.policy_decision is None or not contract.policy_decision.allowed:
                    return self._update_action(
                        executing,
                        status=ResearchActionStatus.REJECTED,
                        failure_reason=(
                            contract.policy_decision.reason_code
                            if contract.policy_decision
                            else "POLICY_REJECTED"
                        ),
                        finished_at=utc_now(),
                    ), None
                executing = self._update_action(executing, status=ResearchActionStatus.EXECUTING)
                result = await self.acquirer.execute_http(
                    executing, validation, contract, plan, run
                )
            elif action.action_type in {
                ResearchActionType.SERVICE_DISCOVERY,
                ResearchActionType.DNS_RESOLVE,
                ResearchActionType.TLS_INSPECT,
            }:
                result = await self.acquirer.execute_discovery(executing)
            elif action.action_type in {
                ResearchActionType.DISCOVER_WEB_CONTENT,
                ResearchActionType.ASSESS_WEB_TEMPLATES,
            }:
                result = await self.acquirer.execute_active_web(executing)
            elif action.action_type is ResearchActionType.REPRODUCE_EXPERIMENT:
                result = await self.acquirer.reproduce(executing)
            else:
                result = None
            if result is None:
                return self._update_action(
                    executing,
                    status=ResearchActionStatus.CANCELLED,
                    failure_reason="STOP_ACTION_NOT_EXECUTABLE",
                ), None
            with self.database.session_factory.begin() as session:
                RepositorySet(session).research_action_results.add(result)
            completed = self._update_action(
                executing,
                status=result.status,
                tool_run_ids=result.tool_run_ids,
                evidence_ids=result.evidence_ids,
                observation_ids=result.observation_ids,
                verification_result_ids=result.verification_result_ids,
                satisfaction=result.satisfaction,
                failure_reason=result.failure_reason,
                finished_at=result.finished_at,
            )
            return completed, result
        except Exception as error:
            failed = self._update_action(
                executing,
                status=ResearchActionStatus.REJECTED,
                failure_reason=f"{type(error).__name__}: {error}",
                finished_at=utc_now(),
            )
            return failed, None

    def _rebuild(self, session_id: UUID) -> tuple[str, str | None, str]:
        model = SystemModelBuilder(self.database).build(session_id)
        graph_hash = None
        try:
            _, graph, _ = AttackGraphBuilder(
                self.database, max_nodes=self.settings.graph_max_nodes
            ).build(session_id)
            graph_hash = graph.graph_hash
        except Exception:
            graph_hash = None
        _, knowledge, _ = self.strategy.knowledge.build(session_id)
        return model.model_sha256 or "0" * 64, graph_hash, knowledge.sha256

    def _reevaluate_actions(
        self, actions: list[ResearchAction], results: list[ResearchActionResult]
    ) -> list[ResearchAction]:
        result_by_action = {item.action_id: item for item in results}
        output = []
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            for action in actions:
                result = result_by_action.get(action.id)
                if result is None or action.status in {
                    ResearchActionStatus.REJECTED,
                    ResearchActionStatus.FAILED,
                    ResearchActionStatus.CANCELLED,
                }:
                    output.append(action)
                    continue
                satisfied = self.satisfaction.evaluate(repositories, action, result)
                updated = action.model_copy(
                    update={
                        "status": (
                            ResearchActionStatus.SATISFIED
                            if satisfied
                            else ResearchActionStatus.UNSATISFIED
                        ),
                        "satisfaction": (
                            ActionSatisfaction.SATISFIED
                            if satisfied
                            else ActionSatisfaction.UNSATISFIED
                        ),
                    }
                )
                repositories.research_actions.update(updated)
                if updated.research_intent_id:
                    intent = repositories.research_intents.get(updated.research_intent_id)
                    if intent:
                        repositories.research_intents.update(
                            intent.model_copy(
                                update={
                                    "status": (
                                        ResearchIntentStatus.SATISFIED
                                        if satisfied
                                        else ResearchIntentStatus.UNSATISFIED
                                    ),
                                    "tool_run_ids": updated.tool_run_ids,
                                    "resulting_observation_ids": updated.observation_ids,
                                    "discovery_plan_id": updated.discovery_plan_id,
                                    "finished_at": utc_now(),
                                }
                            )
                        )
                output.append(updated)
        return output

    def _persist_stop_step(
        self,
        session_id: UUID,
        budget: ResearchBudget,
        decision_type: ControllerDecisionType,
        reason: str,
    ) -> ControllerStepResult:
        strategy_run, _ = self.strategy.plan(session_id)
        context = self.context_builder.build(session_id, budget, strategy_run)
        with self.database.session_factory() as session:
            prior = RepositorySet(session).controller_steps.list_by_session(session_id)
        decision = ControllerDecision(
            session_id=session_id, decision_type=decision_type, stop_reason=reason
        )
        step = ControllerStep(
            research_session_id=session_id,
            step_number=len(prior) + 1,
            context_hash=context.sha256,
            knowledge_hash=context.knowledge_hash,
            model_hash=context.model_hash,
            graph_hash=context.graph_hash,
            provider="deterministic",
            model="budget-gate-v1",
            decision=decision,
            decision_hash=decision.sha256,
            decision_type=decision_type,
            budget_before=self._budget_payload(budget),
            budget_after=self._budget_payload(budget),
            status=ControllerStepStatus.COMPLETED,
            stop_reason=reason,
            finished_at=utc_now(),
            provenance=_provenance("controller_step", context.sha256),
        )
        with self.database.session_factory.begin() as session:
            RepositorySet(session).controller_steps.add(step)
        return ControllerStepResult(step, (), (), decision)

    def _validate_decision(self, decision: ControllerDecision, session_id: UUID) -> None:
        if decision.session_id != session_id:
            raise ValueError("controller decision references another session")
        if len(decision.actions) > self.max_actions_per_step:
            raise ValueError("controller decision exceeds max actions per step")
        if any(action.research_session_id != session_id for action in decision.actions):
            raise ValueError("controller action references another session")
        for index, action in enumerate(decision.actions):
            if any(dependency < 0 or dependency >= index for dependency in action.depends_on):
                raise ValueError("action dependency must reference an earlier action index")

    def _update_action(self, action: ResearchAction, **updates: object) -> ResearchAction:
        updated = action.model_copy(update=updates)
        with self.database.session_factory.begin() as session:
            RepositorySet(session).research_actions.update(updated)
        return updated

    @staticmethod
    def _budget_payload(budget: ResearchBudget) -> dict[str, object]:
        return {
            "max_steps": budget.max_steps,
            "max_actions": budget.max_actions,
            "max_tool_runs": budget.max_tool_runs,
            "max_requests": budget.max_requests,
            "max_duration_seconds": budget.max_duration_seconds,
            "max_llm_calls": budget.max_llm_calls,
            "consumed_steps": budget.consumed_steps,
            "consumed_actions": budget.consumed_actions,
            "consumed_tool_runs": budget.consumed_tool_runs,
            "consumed_requests": budget.consumed_requests,
            "consumed_duration_seconds": budget.consumed_duration_seconds,
            "consumed_llm_calls": budget.consumed_llm_calls,
        }

    @staticmethod
    def _consume_budget(
        repositories: RepositorySet,
        budget: ResearchBudget,
        *,
        steps: int = 0,
        actions: int = 0,
        tool_runs: int = 0,
        requests: int = 0,
        llm_calls: int = 0,
        duration: float = 0,
        status: ControllerStatus | None = None,
        stop_reason: str | None = None,
    ) -> ResearchBudget:
        updated = budget.model_copy(
            update={
                "consumed_steps": min(budget.max_steps, budget.consumed_steps + steps),
                "consumed_actions": min(budget.max_actions, budget.consumed_actions + actions),
                "consumed_tool_runs": min(
                    budget.max_tool_runs, budget.consumed_tool_runs + tool_runs
                ),
                "consumed_requests": min(budget.max_requests, budget.consumed_requests + requests),
                "consumed_llm_calls": min(
                    budget.max_llm_calls, budget.consumed_llm_calls + llm_calls
                ),
                "consumed_duration_seconds": min(
                    budget.max_duration_seconds,
                    budget.consumed_duration_seconds + duration,
                ),
                "controller_status": status or budget.controller_status,
                "stop_reason": stop_reason,
                "updated_at": utc_now(),
            }
        )
        repositories.research_budgets.update(updated)
        return updated
