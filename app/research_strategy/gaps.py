import hashlib
from uuid import UUID

from app.domain.attack_graph import CandidateSignalType, GraphSnapshotStatus
from app.domain.common import FactClassification, Provenance, utc_now
from app.domain.hypotheses import MissingInformation
from app.domain.research_strategy import (
    EvidenceGap,
    GapPriority,
    GapStatus,
    GapType,
    KnowledgeClassification,
)
from app.domain.system_model import RelationshipType
from app.storage.repositories import RepositorySet


def gap_semantic_key(
    session_id: UUID,
    gap_type: GapType,
    subject_id: UUID,
    target_id: UUID | None = None,
    resource_id: UUID | None = None,
) -> str:
    payload = "|".join(
        map(str, (session_id, gap_type.value, subject_id, target_id or "", resource_id or ""))
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def _provenance(reference: str) -> Provenance:
    return Provenance(
        source_type="evidence_gap_detector",
        source_reference=reference,
        collector="research-strategy-v1",
        classification=FactClassification.INFERRED,
    )


class EvidenceGapDetector:
    def __init__(self, *, minimum_verification_runs: int = 1) -> None:
        self.minimum_verification_runs = minimum_verification_runs

    def detect(self, repositories: RepositorySet, session_id: UUID) -> list[EvidenceGap]:
        research = repositories.research_sessions.get(session_id)
        if research is None:
            raise ValueError("research session does not exist")
        gaps: list[EvidenceGap] = []
        services = repositories.system_services.list_by_session(session_id)
        if not services:
            gaps.append(
                self._gap(
                    session_id,
                    GapType.MISSING_SERVICE_INFORMATION,
                    research.target.asset_id,
                    "No deterministic service observation exists for the scoped target.",
                    ("scoped service protocol, port, and state",),
                    priority=GapPriority.NORMAL,
                )
            )
        for service in services:
            if service.protocol.lower() in {"tcp", "unknown"} or service.service_type.lower() in {
                "unknown",
                "unidentified",
            }:
                gaps.append(
                    self._gap(
                        session_id,
                        GapType.MISSING_PROTOCOL_INFORMATION,
                        service.id,
                        "A service exists but application protocol metadata is unknown.",
                        ("application protocol identification",),
                    )
                )
        snapshots = repositories.attack_graph_snapshots.list_by_session(session_id)
        current = next(
            (
                item
                for item in reversed(snapshots)
                if item.status is GraphSnapshotStatus.CURRENT
            ),
            None,
        )
        signals = repositories.candidate_signals.list_by_graph(current.id) if current else []
        relationships = repositories.system_relationships.list_by_session(session_id)
        for signal in signals:
            if signal.signal_type is not CandidateSignalType.CROSS_IDENTITY_RESOURCE_ACCESS:
                continue
            owner_baseline = any(
                item.relationship_type is RelationshipType.CAN_ACCESS
                and item.source_entity_id == signal.target_entity_id
                and item.target_entity_id == signal.endpoint_entity_id
                for item in relationships
            )
            if not owner_baseline:
                gaps.append(
                    self._gap(
                        session_id,
                        GapType.MISSING_BASELINE,
                        signal.target_entity_id,
                        "The resource owner has not been observed at the candidate endpoint.",
                        (
                            "owner response at the same endpoint",
                            "stable resource identity and ownership fields",
                        ),
                        target_id=signal.endpoint_entity_id,
                        resource_id=signal.resource_entity_id,
                        observations=tuple(signal.observation_ids),
                        evidence=tuple(signal.evidence_ids),
                        signals=(signal.id,),
                        priority=GapPriority.HIGH,
                    )
                )
        observations = repositories.observations.list_by_session(session_id)
        conflict_groups: dict[str, dict[str, list[UUID]]] = {}
        for observation in observations:
            key = observation.normalized_data.get("knowledge_key")
            value = observation.normalized_data.get("value")
            if isinstance(key, str) and value is not None:
                conflict_groups.setdefault(key, {}).setdefault(str(value), []).append(
                    observation.id
                )
        for key, values in sorted(conflict_groups.items()):
            if len(values) < 2:
                continue
            observation_ids = tuple(
                item for value in sorted(values) for item in sorted(values[value])
            )
            gaps.append(
                self._gap(
                    session_id,
                    GapType.CONFLICTING_OBSERVATIONS,
                    research.target.asset_id,
                    f"Observations disagree for semantic fact {key}.",
                    ("a controlled observation distinguishing the conflicting values",),
                    observations=observation_ids,
                    priority=GapPriority.HIGH,
                    key_suffix=key,
                )
            )
        for hypothesis in repositories.hypotheses.list_by_session(session_id):
            for missing in hypothesis.missing_information:
                if not isinstance(missing, MissingInformation) or not missing.gap_type:
                    continue
                try:
                    gap_type = GapType(missing.gap_type)
                except ValueError:
                    continue
                subject = missing.subject_entity_id or research.target.asset_id
                gaps.append(
                    self._gap(
                        session_id,
                        gap_type,
                        subject,
                        missing.description,
                        (missing.expected_fact or missing.description,),
                        target_id=missing.target_entity_id,
                        resource_id=missing.resource_entity_id,
                        observations=tuple(missing.related_observation_ids),
                        hypotheses=(hypothesis.id,),
                        priority=GapPriority.NORMAL,
                    )
                )
        if self.minimum_verification_runs > 1:
            for finding in repositories.findings.list_by_session(session_id):
                results = [
                    item
                    for item in repositories.verification_results.list_by_session(session_id)
                    if item.experiment_id == finding.experiment_id
                ]
                if len(results) < self.minimum_verification_runs:
                    gaps.append(
                        self._gap(
                            session_id,
                            GapType.INSUFFICIENT_REPRODUCTION,
                            finding.hypothesis_id,
                            "Verification history is below the configured reproduction threshold.",
                            ("additional controlled verification execution",),
                            hypotheses=(finding.hypothesis_id,),
                        )
                    )
        unique = {item.semantic_key: item for item in gaps}
        return [unique[key] for key in sorted(unique)]

    @staticmethod
    def _gap(
        session_id: UUID,
        gap_type: GapType,
        subject_id: UUID,
        description: str,
        required: tuple[str, ...],
        *,
        target_id: UUID | None = None,
        resource_id: UUID | None = None,
        observations: tuple[UUID, ...] = (),
        evidence: tuple[UUID, ...] = (),
        signals: tuple[UUID, ...] = (),
        hypotheses: tuple[UUID, ...] = (),
        priority: GapPriority = GapPriority.NORMAL,
        key_suffix: str = "",
    ) -> EvidenceGap:
        semantic = gap_semantic_key(
            session_id, gap_type, subject_id, target_id, resource_id
        )
        if key_suffix:
            semantic = hashlib.sha256(f"{semantic}|{key_suffix}".encode()).hexdigest()
        return EvidenceGap(
            research_session_id=session_id,
            semantic_key=semantic,
            gap_type=gap_type,
            subject_entity_id=subject_id,
            target_entity_id=target_id,
            resource_entity_id=resource_id,
            description=description,
            current_state=(
                KnowledgeClassification.CONFLICTING
                if gap_type is GapType.CONFLICTING_OBSERVATIONS
                else KnowledgeClassification.UNKNOWN
            ),
            required_information=required,
            supporting_observation_ids=observations,
            supporting_evidence_ids=evidence,
            supporting_signal_ids=signals,
            supporting_hypothesis_ids=hypotheses,
            priority=priority,
            provenance=_provenance(semantic),
        )


class EvidenceGapResolver:
    def reevaluate(
        self,
        repositories: RepositorySet,
        session_id: UUID,
        detected: list[EvidenceGap],
    ) -> list[EvidenceGap]:
        detected_by_key = {item.semantic_key: item for item in detected}
        existing = repositories.evidence_gaps.list_by_session(session_id)
        valid_entities = self._entity_ids(repositories, session_id)
        valid_entities.add(
            repositories.research_sessions.get(session_id).target.asset_id  # type: ignore[union-attr]
        )
        output: list[EvidenceGap] = []
        for old in existing:
            current = detected_by_key.pop(old.semantic_key, None)
            if current:
                status = old.status if old.status is GapStatus.BLOCKED else GapStatus.OPEN
                updated = old.model_copy(
                    update={
                        "description": current.description,
                        "required_information": current.required_information,
                        "supporting_observation_ids": current.supporting_observation_ids,
                        "supporting_evidence_ids": current.supporting_evidence_ids,
                        "supporting_signal_ids": current.supporting_signal_ids,
                        "supporting_hypothesis_ids": current.supporting_hypothesis_ids,
                        "current_state": current.current_state,
                        "status": status,
                        "resolved_at": None,
                    }
                )
            elif old.subject_entity_id not in valid_entities:
                updated = old.model_copy(update={"status": GapStatus.STALE})
            else:
                updated = old.model_copy(
                    update={"status": GapStatus.RESOLVED, "resolved_at": utc_now()}
                )
            repositories.evidence_gaps.update(updated)
            output.append(updated)
        for new in detected_by_key.values():
            repositories.evidence_gaps.add(new)
            output.append(new)
        return sorted(output, key=lambda item: item.semantic_key)

    @staticmethod
    def _entity_ids(repositories: RepositorySet, session_id: UUID) -> set[UUID]:
        output: set[UUID] = set()
        for name in (
            "system_assets",
            "system_services",
            "system_endpoints",
            "system_identities",
            "system_roles",
            "system_data_objects",
            "hypotheses",
        ):
            output.update(item.id for item in getattr(repositories, name).list_by_session(session_id))
        for graph in repositories.attack_graph_snapshots.list_by_session(session_id):
            output.update(
                item.id for item in repositories.candidate_signals.list_by_graph(graph.id)
            )
        return output
