from collections import defaultdict
from uuid import UUID

from app.domain.common import FactClassification, Provenance, utc_now
from app.domain.discovery import ToolRisk
from app.domain.research_planner import (
    ExpectedInformation,
    IntentPriority,
    PlannerDecision,
    PlannerState,
    ResearchIntentProposal,
    ResearchIntentStatus,
    ResearchIntentType,
)
from app.domain.research_strategy import (
    STRATEGY_VERSION,
    EvidenceGap,
    GapPriority,
    GapStatus,
    GapType,
    InformationGainEstimate,
    InformationGainLevel,
    QuestionStatus,
    QuestionType,
    ResearchCost,
    ResearchQuestion,
    StrategyCandidate,
    StrategyMode,
    StrategyRun,
    StrategyRunStatus,
)
from app.research_planner.resolver import CapabilityResolver, ToolResolver
from app.research_planner.validator import intent_semantic_key
from app.research_strategy.knowledge import KnowledgeService
from app.storage.database import Database
from app.storage.repositories import RepositorySet


class ResearchQuestionGenerator:
    _TYPES = {
        GapType.MISSING_BASELINE: QuestionType.ACCESS_COMPARISON,
        GapType.MISSING_COMPARISON: QuestionType.ACCESS_COMPARISON,
        GapType.MISSING_IDENTITY_OBSERVATION: QuestionType.ACCESS_COMPARISON,
        GapType.MISSING_SERVICE_INFORMATION: QuestionType.SERVICE_IDENTIFICATION,
        GapType.MISSING_RESOURCE_OWNERSHIP: QuestionType.OWNERSHIP_CONFIRMATION,
        GapType.MISSING_ROLE_BEHAVIOR: QuestionType.ROLE_COMPARISON,
        GapType.MISSING_PROTOCOL_INFORMATION: QuestionType.SERVICE_IDENTIFICATION,
        GapType.CONFLICTING_OBSERVATIONS: QuestionType.REPRODUCTION,
        GapType.INSUFFICIENT_REPRODUCTION: QuestionType.REPRODUCTION,
        GapType.UNKNOWN: QuestionType.REPRODUCTION,
    }

    def generate(self, gap: EvidenceGap) -> ResearchQuestion:
        question_type = self._TYPES[gap.gap_type]
        semantic = f"{gap.semantic_key}:{question_type.value}"
        return ResearchQuestion(
            research_session_id=gap.research_session_id,
            gap_id=gap.id,
            semantic_key=semantic,
            question_type=question_type,
            subject_entity_id=gap.subject_entity_id,
            target_entity_id=gap.target_entity_id,
            resource_entity_id=gap.resource_entity_id,
            expected_information=gap.required_information,
            candidate_answers=("supported by observation", "not observed", "inconclusive"),
            status=(
                QuestionStatus.ANSWERED
                if gap.status is GapStatus.RESOLVED
                else QuestionStatus.OPEN
            ),
            provenance=Provenance(
                source_type="research_question",
                source_reference=semantic,
                collector=STRATEGY_VERSION,
                classification=FactClassification.INFERRED,
            ),
        )


class ResearchStrategyEngine:
    """Ranks evidence acquisition; it never executes target operations."""

    def __init__(
        self,
        database: Database,
        tool_resolver: ToolResolver,
        *,
        minimum_verification_runs: int = 1,
        max_selected_intents: int = 3,
    ) -> None:
        self.database = database
        self.tool_resolver = tool_resolver
        self.capability_resolver = CapabilityResolver()
        self.knowledge = KnowledgeService(
            database, minimum_verification_runs=minimum_verification_runs
        )
        self.questions = ResearchQuestionGenerator()
        self.max_selected_intents = max_selected_intents

    def plan(
        self, session_id: UUID, *, mode: StrategyMode = StrategyMode.DETERMINISTIC
    ) -> tuple[StrategyRun, PlannerDecision]:
        if mode is not StrategyMode.DETERMINISTIC:
            raise ValueError("LLM-assisted strategy is not enabled; use deterministic mode")
        _, snapshot, gaps = self.knowledge.build(session_id)
        open_gaps = [
            gap
            for gap in gaps
            if gap.status in {GapStatus.OPEN, GapStatus.PARTIALLY_RESOLVED, GapStatus.BLOCKED}
        ]
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            research = repositories.research_sessions.get(session_id)
            if research is None:
                raise ValueError("research session does not exist")
            questions: dict[UUID, ResearchQuestion] = {}
            for gap in open_gaps:
                proposed = self.questions.generate(gap)
                existing = repositories.research_questions.get_by_semantic(
                    session_id, proposed.semantic_key
                )
                question = existing or proposed
                if existing is None:
                    repositories.research_questions.add(question)
                questions[gap.id] = question
            candidates, redundant = self._candidates(
                repositories, research, open_gaps, questions
            )
            candidate_gap_ids = {
                gap_id for candidate in candidates for gap_id in candidate.gap_ids
            }
            selected_count = 0
            ranked: list[StrategyCandidate] = []
            for candidate in candidates:
                selected = bool(
                    candidate.policy_allowed
                    and selected_count < self.max_selected_intents
                )
                if selected:
                    selected_count += 1
                ranked.append(candidate.model_copy(update={"selected": selected}))
                if candidate.policy_allowed is False:
                    for gap_id in candidate.gap_ids:
                        gap = repositories.evidence_gaps.get(gap_id)
                        if gap:
                            repositories.evidence_gaps.update(
                                gap.model_copy(
                                    update={
                                        "status": GapStatus.BLOCKED,
                                        "blocked_reason": candidate.policy_reason,
                                    }
                                )
                            )
                    for question_id in candidate.research_question_ids:
                        question = repositories.research_questions.get(question_id)
                        if question:
                            repositories.research_questions.update(
                                question.model_copy(
                                    update={"status": QuestionStatus.BLOCKED}
                                )
                            )
                elif candidate.policy_allowed:
                    for gap_id in candidate.gap_ids:
                        gap = repositories.evidence_gaps.get(gap_id)
                        if gap and gap.status is GapStatus.BLOCKED:
                            repositories.evidence_gaps.update(
                                gap.model_copy(
                                    update={
                                        "status": GapStatus.OPEN,
                                        "blocked_reason": None,
                                    }
                                )
                            )
                    for question_id in candidate.research_question_ids:
                        question = repositories.research_questions.get(question_id)
                        if question and question.status is QuestionStatus.BLOCKED:
                            repositories.research_questions.update(
                                question.model_copy(update={"status": QuestionStatus.OPEN})
                            )
            for gap in open_gaps:
                if gap.id in candidate_gap_ids:
                    continue
                repositories.evidence_gaps.update(
                    gap.model_copy(
                        update={
                            "status": GapStatus.BLOCKED,
                            "blocked_reason": "NO_SAFE_CAPABILITY",
                        }
                    )
                )
                question = questions[gap.id]
                repositories.research_questions.update(
                    question.model_copy(update={"status": QuestionStatus.BLOCKED})
                )
            status = (
                StrategyRunStatus.COMPLETED
                if selected_count
                else StrategyRunStatus.NO_SAFE_ACTION
            )
            run = StrategyRun(
                research_session_id=session_id,
                knowledge_snapshot_id=snapshot.id,
                strategy_version=STRATEGY_VERSION,
                mode=mode,
                finished_at=utc_now(),
                candidates=tuple(ranked),
                candidate_count=len(ranked),
                selected_intent_count=selected_count,
                redundant_intents_prevented=redundant,
                status=status,
                provenance=Provenance(
                    source_type="research_strategy",
                    source_reference=snapshot.sha256,
                    collector=STRATEGY_VERSION,
                    classification=FactClassification.INFERRED,
                ),
            )
            repositories.strategy_runs.add(run)
        selected_intents = tuple(
            item.proposed_intent for item in ranked if item.selected
        )
        decision = PlannerDecision(
            session_id=session_id,
            state=(
                PlannerState.CONTINUE
                if selected_intents
                else PlannerState.STOP_NO_SAFE_ACTION
            ),
            intents=selected_intents,
            stop_reason=None if selected_intents else "No safe strategy candidate exists.",
            limitations=("deterministic evidence-gap strategy",),
        )
        return run, decision

    def _candidates(self, repositories, research, gaps, questions):
        grouped: dict[
            tuple[object, ...], list[tuple[EvidenceGap, ResearchQuestion]]
        ] = defaultdict(list)
        redundant = 0
        for gap in gaps:
            intent = self._intent(gap)
            if intent is None:
                continue
            key = (
                intent.intent_type,
                intent.subject_entity_id,
                intent.target_entity_id,
                intent.expected_information,
            )
            grouped[key].append((gap, questions[gap.id]))
        candidates: list[StrategyCandidate] = []
        history = repositories.research_intents.list_by_session(research.id)
        for pairs in grouped.values():
            gaps_for_intent = [item[0] for item in pairs]
            base = self._intent(gaps_for_intent[0])
            if base is None:
                continue
            all_gap_ids = tuple(sorted((item.id for item in gaps_for_intent), key=str))
            all_signal_ids = tuple(
                sorted(
                    {signal for item in gaps_for_intent for signal in item.supporting_signal_ids},
                    key=str,
                )
            )
            intent = base.model_copy(
                update={
                    "evidence_gap_ids": all_gap_ids,
                    "supporting_signal_ids": all_signal_ids,
                }
            )
            semantic = intent_semantic_key(research.id, intent)
            if any(
                item.semantic_key == semantic
                and item.status is ResearchIntentStatus.SATISFIED
                for item in history
            ):
                redundant += 1
                continue
            capability = self.capability_resolver.resolve(intent.intent_type)
            resolution = self.tool_resolver.resolve(capability, research)
            policy_allowed = bool(
                resolution.policy_preview and resolution.policy_preview.allowed
            )
            gain = self._information_gain(gaps_for_intent)
            risk = (
                resolution.descriptor.risk_class
                if resolution.descriptor
                else ToolRisk.LOW
            )
            cost = ResearchCost(
                tool_runs=1,
                network_requests=1,
                estimated_duration_seconds=(
                    resolution.request.timeout_seconds if resolution.request else 0
                ),
                risk_class=risk,
            )
            failures = sum(
                item.intent_type is intent.intent_type
                and item.subject_entity_id == intent.subject_entity_id
                and item.status
                in {ResearchIntentStatus.FAILED, ResearchIntentStatus.UNSATISFIED}
                for item in history
            )
            relevance = 25 if all_signal_ids else 15 if any(
                gap.supporting_hypothesis_ids for gap in gaps_for_intent
            ) else 5
            multi_gap = min(15, (len(gaps_for_intent) - 1) * 10)
            risk_penalty = 5 if risk is ToolRisk.LOW else 0
            score = max(
                0,
                min(100, gain.score + relevance + multi_gap - 5 - risk_penalty - failures * 10),
            )
            candidates.append(
                StrategyCandidate(
                    gap_ids=all_gap_ids,
                    research_question_ids=tuple(
                        sorted((item[1].id for item in pairs), key=str)
                    ),
                    proposed_intent=intent,
                    information_gain=gain,
                    cost=cost,
                    priority_score=score,
                    expected_resolution="Reevaluate associated gaps after new observations.",
                    selection_reason=(
                        "signal-backed gap first; then hypothesis relevance, multi-gap value, "
                        "cost, risk, and failed-attempt penalty"
                    ),
                    policy_allowed=policy_allowed,
                    policy_reason=(
                        resolution.policy_preview.reason.value
                        if resolution.policy_preview
                        else "NO_SAFE_CAPABILITY"
                    ),
                )
            )
        candidates.sort(
            key=lambda item: (
                -item.priority_score,
                min(str(gap_id) for gap_id in item.gap_ids),
            )
        )
        return candidates, redundant

    @staticmethod
    def _information_gain(gaps: list[EvidenceGap]) -> InformationGainEstimate:
        high = any(
            gap.priority is GapPriority.HIGH or gap.supporting_signal_ids for gap in gaps
        )
        level = InformationGainLevel.HIGH if high else InformationGainLevel.MEDIUM
        base = 60 if high else 40
        score = min(75, base + (len(gaps) - 1) * 10)
        return InformationGainEstimate(
            level=level,
            score=score,
            factors=("gap importance", "signal relevance", "multi-gap coverage"),
        )

    @staticmethod
    def _intent(gap: EvidenceGap) -> ResearchIntentProposal | None:
        if gap.gap_type in {
            GapType.MISSING_SERVICE_INFORMATION,
            GapType.MISSING_PROTOCOL_INFORMATION,
        }:
            return ResearchIntentProposal(
                intent_type=ResearchIntentType.DISCOVER_SERVICES,
                subject_entity_id=gap.subject_entity_id,
                reason=gap.description,
                expected_information=(ExpectedInformation.SERVICES,),
                priority=IntentPriority.HIGH if gap.priority is GapPriority.HIGH else IntentPriority.NORMAL,
                supporting_observation_ids=gap.supporting_observation_ids,
                supporting_evidence_ids=gap.supporting_evidence_ids,
                evidence_gap_ids=(gap.id,),
            )
        if gap.gap_type is GapType.INSUFFICIENT_REPRODUCTION:
            return None
        intent_type = (
            ResearchIntentType.VERIFY_CANDIDATE_SIGNAL
            if gap.supporting_signal_ids
            else ResearchIntentType.OBSERVE_HTTP
        )
        expected = (
            ExpectedInformation.CANDIDATE_EVIDENCE
            if intent_type is ResearchIntentType.VERIFY_CANDIDATE_SIGNAL
            else ExpectedInformation.HTTP_METADATA
        )
        return ResearchIntentProposal(
            intent_type=intent_type,
            subject_entity_id=gap.subject_entity_id,
            target_entity_id=gap.target_entity_id,
            reason=gap.description,
            expected_information=(expected,),
            priority=IntentPriority.HIGH if gap.priority is GapPriority.HIGH else IntentPriority.NORMAL,
            supporting_observation_ids=gap.supporting_observation_ids,
            supporting_evidence_ids=gap.supporting_evidence_ids,
            supporting_signal_ids=gap.supporting_signal_ids,
            evidence_gap_ids=(gap.id,),
        )
