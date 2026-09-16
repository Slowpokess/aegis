from uuid import UUID

from app.domain.attack_graph import GraphSnapshotStatus
from app.domain.common import FactClassification, Provenance
from app.domain.research_strategy import (
    KNOWLEDGE_VERSION,
    AccessMatrix,
    AccessMatrixCell,
    EvidenceGap,
    GapStatus,
    KnowledgeClassification,
    KnowledgeFact,
    KnowledgeSnapshot,
    KnowledgeState,
    QuestionStatus,
    SufficiencyState,
    knowledge_sha256,
)
from app.domain.system_model import RelationshipType
from app.research_strategy.gaps import EvidenceGapDetector, EvidenceGapResolver
from app.storage.database import Database
from app.storage.repositories import RepositorySet
from app.system_model.serialization import model_sha256

_FACT_REPOSITORIES = (
    "system_assets",
    "system_services",
    "system_endpoints",
    "system_identities",
    "system_roles",
    "system_permissions",
    "system_capabilities",
    "system_data_objects",
    "system_trust_boundaries",
    "system_relationships",
)


class KnowledgeStateBuilder:
    def build(
        self,
        repositories: RepositorySet,
        session_id: UUID,
        gaps: list[EvidenceGap],
    ) -> KnowledgeState:
        facts: list[KnowledgeFact] = []
        for name in _FACT_REPOSITORIES:
            for item in getattr(repositories, name).list_by_session(session_id):
                if (
                    item.classification is FactClassification.OBSERVED
                    and item.observation_ids
                    and item.evidence_ids
                ):
                    facts.append(
                        KnowledgeFact(
                            semantic_key=f"known:{item.canonical_identifier}",
                            statement=item.canonical_identifier,
                            classification=KnowledgeClassification.KNOWN,
                            subject_entity_id=item.id,
                            observation_ids=tuple(sorted(item.observation_ids)),
                            evidence_ids=tuple(sorted(item.evidence_ids)),
                        )
                    )
        for hypothesis in repositories.hypotheses.list_by_session(session_id):
            for index, assumption in enumerate(hypothesis.assumptions):
                facts.append(
                    KnowledgeFact(
                        semantic_key=f"assumed:{hypothesis.id}:{index}",
                        statement=assumption,
                        classification=KnowledgeClassification.ASSUMED,
                        subject_entity_id=hypothesis.id,
                    )
                )
            if hypothesis.status.value in {"NEW", "TESTING"}:
                facts.append(
                    KnowledgeFact(
                        semantic_key=f"untested:hypothesis:{hypothesis.id}",
                        statement=hypothesis.title,
                        classification=KnowledgeClassification.UNTESTED,
                        subject_entity_id=hypothesis.id,
                        observation_ids=tuple(sorted(hypothesis.observation_ids)),
                        evidence_ids=tuple(sorted(hypothesis.evidence_ids)),
                    )
                )
        for result in repositories.verification_results.list_by_session(session_id):
            if result.verdict.value == "INCONCLUSIVE":
                facts.append(
                    KnowledgeFact(
                        semantic_key=f"inconclusive:verification:{result.id}",
                        statement=result.reason,
                        classification=KnowledgeClassification.INCONCLUSIVE,
                        subject_entity_id=result.hypothesis_id,
                        observation_ids=tuple(
                            item
                            for item in (
                                result.candidate_observation_id,
                                result.control_observation_id,
                            )
                            if item
                        ),
                        evidence_ids=tuple(
                            item
                            for item in (
                                result.candidate_evidence_id,
                                result.control_evidence_id,
                            )
                            if item
                        ),
                    )
                )
        for gap in gaps:
            if gap.status not in {GapStatus.OPEN, GapStatus.PARTIALLY_RESOLVED, GapStatus.BLOCKED}:
                continue
            facts.append(
                KnowledgeFact(
                    semantic_key=f"gap:{gap.semantic_key}",
                    statement=gap.description,
                    classification=gap.current_state,
                    subject_entity_id=gap.subject_entity_id,
                    target_entity_id=gap.target_entity_id,
                    observation_ids=gap.supporting_observation_ids,
                    evidence_ids=gap.supporting_evidence_ids,
                )
            )
        facts.sort(key=lambda item: item.semantic_key)
        return KnowledgeState(session_id=session_id, facts=tuple(facts))


class KnowledgeService:
    def __init__(self, database: Database, *, minimum_verification_runs: int = 1) -> None:
        self.database = database
        self.detector = EvidenceGapDetector(
            minimum_verification_runs=minimum_verification_runs
        )
        self.resolver = EvidenceGapResolver()
        self.builder = KnowledgeStateBuilder()

    def build(self, session_id: UUID) -> tuple[KnowledgeState, KnowledgeSnapshot, list[EvidenceGap]]:
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            if repositories.research_sessions.get(session_id) is None:
                raise ValueError("research session does not exist")
            detected = self.detector.detect(repositories, session_id)
            gaps = self.resolver.reevaluate(repositories, session_id, detected)
            statuses = {gap.id: gap.status for gap in gaps}
            for question in repositories.research_questions.list_by_session(session_id):
                gap_status = statuses.get(question.gap_id)
                if gap_status is None:
                    continue
                question_status = {
                    GapStatus.RESOLVED: QuestionStatus.ANSWERED,
                    GapStatus.BLOCKED: QuestionStatus.BLOCKED,
                    GapStatus.STALE: QuestionStatus.STALE,
                }.get(gap_status, QuestionStatus.OPEN)
                if question.status is not question_status:
                    repositories.research_questions.update(
                        question.model_copy(update={"status": question_status})
                    )
            state = self.builder.build(repositories, session_id, gaps)
            model_hash = model_sha256(repositories, session_id)
            graphs = repositories.attack_graph_snapshots.list_by_session(session_id)
            current = next(
                (
                    graph
                    for graph in reversed(graphs)
                    if graph.status is GraphSnapshotStatus.CURRENT
                ),
                None,
            )
            semantic_hash = knowledge_sha256(
                system_model_hash=model_hash,
                graph_hash=current.graph_hash if current else None,
                facts=state.facts,
                gaps=tuple(gaps),
            )
            snapshot = KnowledgeSnapshot(
                research_session_id=session_id,
                system_model_hash=model_hash,
                graph_hash=current.graph_hash if current else None,
                knowledge_version=KNOWLEDGE_VERSION,
                known_count=state.count(KnowledgeClassification.KNOWN),
                assumed_count=state.count(KnowledgeClassification.ASSUMED),
                unknown_count=state.count(KnowledgeClassification.UNKNOWN),
                conflicting_count=state.count(KnowledgeClassification.CONFLICTING),
                untested_count=state.count(KnowledgeClassification.UNTESTED),
                inconclusive_count=state.count(KnowledgeClassification.INCONCLUSIVE),
                open_gap_count=sum(
                    gap.status in {GapStatus.OPEN, GapStatus.PARTIALLY_RESOLVED}
                    for gap in gaps
                ),
                sha256=semantic_hash,
                provenance=Provenance(
                    source_type="knowledge_state",
                    source_reference=semantic_hash,
                    collector=KNOWLEDGE_VERSION,
                    classification=FactClassification.INFERRED,
                ),
            )
            repositories.knowledge_snapshots.add(snapshot)
        return state, snapshot, gaps


class AccessMatrixBuilder:
    """Projects only observed, signal-relevant identity/endpoint cells."""

    def build(self, repositories: RepositorySet, session_id: UUID) -> AccessMatrix:
        relationships = repositories.system_relationships.list_by_session(session_id)
        cells: list[AccessMatrixCell] = []
        for item in relationships:
            if item.relationship_type not in {
                RelationshipType.CAN_ACCESS,
                RelationshipType.CANNOT_ACCESS,
            }:
                continue
            cells.append(
                AccessMatrixCell(
                    identity_id=item.source_entity_id,
                    endpoint_id=item.target_entity_id,
                    observed=True,
                    result=item.relationship_type.value,
                    observation_ids=tuple(item.observation_ids),
                )
            )
        cells.sort(key=lambda item: (str(item.endpoint_id), str(item.identity_id)))
        return AccessMatrix(session_id=session_id, cells=tuple(cells))


class EvidenceSufficiencyEvaluator:
    def evaluate_gap(self, gap: EvidenceGap) -> SufficiencyState:
        if gap.status is not GapStatus.RESOLVED:
            return SufficiencyState.INSUFFICIENT
        if gap.supporting_hypothesis_ids:
            return SufficiencyState.SUFFICIENT_FOR_EXPERIMENT
        if gap.supporting_signal_ids:
            return SufficiencyState.SUFFICIENT_FOR_HYPOTHESIS
        return SufficiencyState.SUFFICIENT_FOR_HYPOTHESIS
