import time
from collections.abc import Callable
from uuid import UUID

from app.attack_graph.builder import AttackGraphBuilder
from app.config import Settings
from app.discovery.engine import DiscoveryEngine
from app.domain.attack_graph import GraphSnapshotStatus
from app.domain.common import FactClassification, Provenance, utc_now
from app.domain.research_planner import (
    IntentSource,
    IntentSatisfaction,
    PlannerDecision,
    PlannerState,
    ResearchIntent,
    ResearchIntentStatus,
    ResearchRunResult,
    ResearchStep,
    ResearchStepStatus,
)
from app.llm.base import LLMProvider, LLMProviderError
from app.llm.factory import create_llm_provider
from app.llm.providers.fake import FakeLLMProvider
from app.logging_config import research_planner_log
from app.research_planner.context import ResearchContextBuilder
from app.research_planner.planner import ResearchPlanner, deterministic_fake_decision
from app.research_planner.resolver import CapabilityResolver, ToolResolver
from app.research_planner.satisfaction import IntentSatisfactionEvaluator
from app.research_planner.validator import PlannerValidator, intent_semantic_key
from app.storage.database import Database
from app.storage.repositories import RepositorySet
from app.system_model.builder import SystemModelBuilder
from app.system_model.serialization import model_sha256

ProviderFactory = Callable[[object], LLMProvider]


class ResearchEngine:
    def __init__(
        self,
        database: Database,
        settings: Settings,
        discovery: DiscoveryEngine,
        *,
        provider: LLMProvider | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.database = database
        self.settings = settings
        self.discovery = discovery
        self.provider = provider
        self.clock = clock
        self.context_builder = ResearchContextBuilder(
            database,
            max_context_bytes=settings.planner_max_context_bytes,
            max_entities=settings.planner_max_entities,
            max_signals=settings.planner_max_signals,
            max_history=settings.planner_max_history,
        )
        self.validator = PlannerValidator(settings.planner_max_intents_per_step)
        self.capability_resolver = CapabilityResolver()
        self.tool_resolver = ToolResolver(discovery.registry, discovery.policy)
        self.satisfaction = IntentSatisfactionEvaluator()

    async def step(
        self,
        session_id: UUID,
        *,
        execute: bool = True,
        tool_run_budget: int | None = None,
    ) -> ResearchStep:
        context = self.context_builder.build(session_id)
        provider = self.provider
        if provider is None:
            if self.settings.llm_provider == "fake":
                provider = FakeLLMProvider(
                    [deterministic_fake_decision(context)],
                    model="fake-research-planner-v1",
                )
            else:
                provider = create_llm_provider(self.settings)
        with self.database.session_factory() as session:
            repositories = RepositorySet(session)
            previous = repositories.research_steps.list_by_session(session_id)
            snapshots = repositories.attack_graph_snapshots.list_by_session(session_id)
            current_graph = next(
                (
                    item
                    for item in reversed(snapshots)
                    if item.status is GraphSnapshotStatus.CURRENT
                ),
                None,
            )
            model_before = model_sha256(repositories, session_id)
        step = ResearchStep(
            research_session_id=session_id,
            step_number=len(previous) + 1,
            context_hash=context.sha256,
            planner_provider=provider.provider_name,
            planner_model=provider.model_name,
            model_hash_before=model_before,
            graph_hash_before=current_graph.graph_hash if current_graph else None,
            provenance=Provenance(
                source_type="research_planner",
                source_reference=context.sha256,
                collector="research-planner-v1",
                classification=FactClassification.INFERRED,
            ),
        )
        with self.database.session_factory.begin() as session:
            RepositorySet(session).research_steps.add(step)
        try:
            generated = await ResearchPlanner(provider).decide(context)
            decision = generated.output
            if decision.session_id != session_id:
                raise ValueError("planner decision crosses research sessions")
            self.validator.validate_decision(session_id, decision.intents)
        except (LLMProviderError, ValueError) as error:
            failed = step.model_copy(
                update={
                    "status": ResearchStepStatus.FAILED,
                    "stop_reason": PlannerState.INCONCLUSIVE.value,
                    "error": str(error),
                    "finished_at": utc_now(),
                }
            )
            with self.database.session_factory.begin() as session:
                RepositorySet(session).research_steps.update(failed)
            return failed
        planned = step.model_copy(
            update={
                "decision": decision,
                "decision_hash": decision.sha256,
                "status": ResearchStepStatus.PLANNED,
                "provider_request_id": generated.metadata.provider_request_id,
                "input_tokens": generated.metadata.usage.input_tokens,
                "output_tokens": generated.metadata.usage.output_tokens,
                "latency_ms": generated.metadata.latency_ms,
            }
        )
        with self.database.session_factory.begin() as session:
            RepositorySet(session).research_steps.update(planned)
        research_planner_log.info(
            "step planned session_id=%s step_id=%s context_hash=%s provider=%s "
            "model=%s state=%s intents=%d",
            session_id,
            planned.id,
            planned.context_hash,
            planned.planner_provider,
            planned.planner_model,
            decision.state.value,
            len(decision.intents),
        )
        if decision.state is not PlannerState.CONTINUE:
            completed = planned.model_copy(
                update={
                    "status": ResearchStepStatus.COMPLETED,
                    "stop_reason": decision.stop_reason or decision.state.value,
                    "finished_at": utc_now(),
                }
            )
            with self.database.session_factory.begin() as session:
                RepositorySet(session).research_steps.update(completed)
            return completed
        intents = self._persist_resolutions(planned, decision)
        planned = planned.model_copy(update={"intent_ids": tuple(item.id for item in intents)})
        with self.database.session_factory.begin() as session:
            RepositorySet(session).research_steps.update(planned)
        executable = [
            item
            for item in intents
            if item.status is ResearchIntentStatus.PLANNED and item.policy_allowed
        ]
        budget = (
            self.settings.research_max_tool_runs
            if tool_run_budget is None
            else max(0, tool_run_budget)
        )
        if len(executable) > budget:
            deferred = executable[budget:]
            with self.database.session_factory.begin() as session:
                repositories = RepositorySet(session)
                for item in deferred:
                    repositories.research_intents.update(
                        item.model_copy(
                            update={
                                "status": ResearchIntentStatus.UNSATISFIED,
                                "policy_allowed": False,
                                "policy_reason": "RESEARCH_TOOL_RUN_LIMIT",
                                "finished_at": utc_now(),
                            }
                        )
                    )
            executable = executable[:budget]
        if not execute:
            return planned
        if not executable:
            completed = planned.model_copy(
                update={
                    "status": ResearchStepStatus.COMPLETED,
                    "stop_reason": PlannerState.STOP_NO_SAFE_ACTION.value,
                    "finished_at": utc_now(),
                }
            )
            with self.database.session_factory.begin() as session:
                RepositorySet(session).research_steps.update(completed)
            return completed
        running = planned.model_copy(update={"status": ResearchStepStatus.EXECUTING})
        with self.database.session_factory.begin() as session:
            RepositorySet(session).research_steps.update(running)
        plan_ids: list[UUID] = []
        for intent in executable:
            intent = await self._execute_intent(intent)
            if intent.discovery_plan_id:
                plan_ids.append(intent.discovery_plan_id)
        model_build = SystemModelBuilder(self.database).build(session_id)
        graph_hash: str | None = None
        with self.database.session_factory() as session:
            repositories = RepositorySet(session)
            has_entities = bool(repositories.system_assets.list_by_session(session_id))
        if has_entities:
            _, graph, _ = AttackGraphBuilder(
                self.database, max_nodes=self.settings.graph_max_nodes
            ).build(session_id)
            graph_hash = graph.graph_hash
        completed = running.model_copy(
            update={
                "status": ResearchStepStatus.COMPLETED,
                "discovery_plan_ids": tuple(plan_ids),
                "model_hash_after": model_build.model_sha256,
                "graph_hash_after": graph_hash,
                "finished_at": utc_now(),
            }
        )
        with self.database.session_factory.begin() as session:
            RepositorySet(session).research_steps.update(completed)
        return completed

    def _persist_resolutions(
        self, step: ResearchStep, decision: PlannerDecision
    ) -> list[ResearchIntent]:
        priority = {"HIGH": 0, "NORMAL": 1, "LOW": 2}
        proposals = sorted(
            decision.intents,
            key=lambda item: (
                priority[item.priority.value],
                intent_semantic_key(step.research_session_id, item),
            ),
        )
        persisted: list[ResearchIntent] = []
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            research = repositories.research_sessions.get(step.research_session_id)
            if research is None:
                raise ValueError("research session does not exist")
            for proposal in proposals:
                key = intent_semantic_key(step.research_session_id, proposal)
                existing = next(
                    (
                        item
                        for item in reversed(
                            repositories.research_intents.list_by_session(
                                step.research_session_id
                            )
                        )
                        if item.semantic_key == key
                    ),
                    None,
                )
                if existing is not None:
                    persisted.append(existing)
                    continue
                status = ResearchIntentStatus.PLANNED
                capability = None
                selected = None
                profile = None
                reason = None
                policy_allowed = None
                policy_reason = None
                try:
                    key = self.validator.validate_intent(
                        repositories, step.research_session_id, proposal
                    )
                    capability = self.capability_resolver.resolve(proposal.intent_type)
                    resolution = self.tool_resolver.resolve(capability, research)
                    selected = resolution.descriptor.id if resolution.descriptor else None
                    profile = resolution.profile
                    reason = resolution.reason
                    policy_allowed = (
                        resolution.policy_preview.allowed
                        if resolution.policy_preview
                        else False
                    )
                    policy_reason = (
                        resolution.policy_preview.reason.value
                        if resolution.policy_preview
                        else "NO_TOOL_AVAILABLE"
                    )
                    if not policy_allowed:
                        status = ResearchIntentStatus.UNSATISFIED
                except ValueError as error:
                    status = ResearchIntentStatus.REJECTED
                    policy_reason = str(error)
                intent = ResearchIntent(
                    research_session_id=step.research_session_id,
                    research_step_id=step.id,
                    context_hash=step.context_hash,
                    intent_type=proposal.intent_type,
                    subject_entity_id=proposal.subject_entity_id,
                    target_entity_id=proposal.target_entity_id,
                    reason=proposal.reason,
                    expected_information=proposal.expected_information,
                    priority=proposal.priority,
                    source=IntentSource.LLM,
                    supporting_observation_ids=proposal.supporting_observation_ids,
                    supporting_evidence_ids=proposal.supporting_evidence_ids,
                    supporting_signal_ids=proposal.supporting_signal_ids,
                    evidence_gap_ids=proposal.evidence_gap_ids,
                    semantic_key=key,
                    status=status,
                    capability=capability,
                    selected_tool_id=selected,
                    selected_profile=profile,
                    selection_reason=reason,
                    policy_allowed=policy_allowed,
                    policy_reason=policy_reason,
                    provenance=Provenance(
                        source_type="llm_proposal",
                        source_reference=str(step.id),
                        collector=step.planner_model,
                        classification=FactClassification.INFERRED,
                    ),
                )
                repositories.research_intents.add(intent)
                research_planner_log.info(
                    "intent resolved session_id=%s step_id=%s intent_id=%s "
                    "capability=%s tool=%s profile=%s policy_allowed=%s",
                    step.research_session_id,
                    step.id,
                    intent.id,
                    intent.capability.value if intent.capability else None,
                    intent.selected_tool_id,
                    intent.selected_profile,
                    intent.policy_allowed,
                )
                persisted.append(intent)
        return persisted

    async def _execute_intent(self, intent: ResearchIntent) -> ResearchIntent:
        with self.database.session_factory() as session:
            research = RepositorySet(session).research_sessions.get(
                intent.research_session_id
            )
        if research is None or intent.capability is None:
            return intent
        resolution = self.tool_resolver.resolve(intent.capability, research)
        if resolution.request is None or not resolution.policy_preview or not resolution.policy_preview.allowed:
            return intent
        plan = self.discovery.create_resolved_plan(
            intent.research_session_id,
            capabilities=(intent.capability,),
            requests=(resolution.request,),
        )
        executing = intent.model_copy(
            update={
                "status": ResearchIntentStatus.EXECUTING,
                "discovery_plan_id": plan.id,
            }
        )
        with self.database.session_factory.begin() as session:
            RepositorySet(session).research_intents.update(executing)
        await self.discovery.run(plan.id)
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            runs = repositories.tool_runs.list_by_plan(plan.id)
            observations = tuple(
                observation_id for run in runs for observation_id in run.observation_ids
            )
            evaluated = executing.model_copy(
                update={
                    "tool_run_ids": tuple(run.id for run in runs),
                    "resulting_observation_ids": observations,
                }
            )
            satisfaction = self.satisfaction.evaluate(repositories, evaluated)
            satisfied_values = {
                IntentSatisfaction.SATISFIED,
                IntentSatisfaction.ENOUGH_EVIDENCE_FOR_HYPOTHESIS,
            }
            completed = evaluated.model_copy(
                update={
                    "status": (
                        ResearchIntentStatus.SATISFIED
                        if satisfaction in satisfied_values
                        else ResearchIntentStatus.UNSATISFIED
                    ),
                    "satisfaction": satisfaction,
                    "finished_at": utc_now(),
                }
            )
            repositories.research_intents.update(completed)
        return completed

    async def run(self, session_id: UUID) -> ResearchRunResult:
        started = self.clock()
        produced: list[ResearchStep] = []
        stop_state = PlannerState.INCONCLUSIVE
        stop_reason = "planner did not establish a terminal state"
        initial_runs = self._tool_run_count(session_id)
        for _ in range(self.settings.research_max_steps):
            if self.clock() - started >= self.settings.research_max_duration_seconds:
                stop_state = PlannerState.STOP_LIMIT_REACHED
                stop_reason = "research duration limit reached"
                break
            if self._tool_run_count(session_id) - initial_runs >= self.settings.research_max_tool_runs:
                stop_state = PlannerState.STOP_LIMIT_REACHED
                stop_reason = "research tool-run limit reached"
                break
            remaining_runs = self.settings.research_max_tool_runs - (
                self._tool_run_count(session_id) - initial_runs
            )
            step = await self.step(
                session_id, execute=True, tool_run_budget=remaining_runs
            )
            produced.append(step)
            if step.status is ResearchStepStatus.FAILED:
                stop_state = PlannerState.INCONCLUSIVE
                stop_reason = step.error or "planner step failed"
                break
            if step.stop_reason:
                try:
                    stop_state = PlannerState(step.stop_reason)
                except ValueError:
                    stop_state = step.decision.state if step.decision else PlannerState.INCONCLUSIVE
                stop_reason = step.stop_reason
                break
        else:
            stop_state = PlannerState.STOP_LIMIT_REACHED
            stop_reason = "research step limit reached"
        return ResearchRunResult(
            research_session_id=session_id,
            steps=tuple(produced),
            stop_state=stop_state,
            stop_reason=stop_reason,
            total_intents=sum(len(step.intent_ids) for step in produced),
            total_tool_runs=self._tool_run_count(session_id) - initial_runs,
        )

    def _tool_run_count(self, session_id: UUID) -> int:
        with self.database.session_factory() as session:
            return len(RepositorySet(session).tool_runs.list_by_session(session_id))
