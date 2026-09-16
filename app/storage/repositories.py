from collections.abc import Callable
from typing import Generic, TypeVar
from uuid import UUID

from pydantic import BaseModel
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.domain.assets import Asset
from app.domain.active_web import WebCandidateProvenance
from app.domain.client_verification import ClientVerificationRun
from app.domain.recommendations import VerificationRecommendation
from app.domain.generated_payloads import GeneratedPayload
from app.domain.attack_graph import AttackGraphSnapshot, CandidateSignal, GraphSnapshotStatus
from app.domain.capabilities import Capability
from app.domain.evidence import Evidence
from app.domain.discovery import (
    DiscoveryPlan,
    ToolArtifact,
    ToolPolicyDecision,
    ToolRun,
)
from app.domain.experiments import Experiment, ExperimentExecution
from app.domain.findings import Finding
from app.domain.hypotheses import Hypothesis
from app.domain.identities import Identity
from app.domain.llm_runs import LLMRun
from app.domain.policy import PolicyDecisionAudit
from app.domain.observations import Observation
from app.domain.verification import VerificationResult
from app.domain.evaluation import BenchmarkRun, ScenarioEvaluation, ScenarioRun
from app.domain.research import ResearchSession, ResearchSessionStatus
from app.domain.research_planner import ResearchIntent, ResearchStep
from app.domain.research_strategy import (
    EvidenceGap,
    KnowledgeSnapshot,
    ResearchQuestion,
    StrategyRun,
)
from app.domain.controller import (
    ControllerStep,
    ResearchAction,
    ResearchActionResult,
    ResearchBudget,
)
from app.domain.operator import (
    ActionApproval,
    ReportMetadata,
    ResearchEvent,
    ResearchPolicy,
    ResearchProject,
)
from app.domain.system_model import (
    ProcessedModelObservation,
    SystemAsset,
    SystemCapability,
    SystemDataObject,
    SystemEndpoint,
    SystemFact,
    SystemIdentity,
    SystemEntityType,
    SystemModelBuild,
    SystemPermission,
    SystemRelationship,
    SystemRole,
    SystemService,
    SystemTrustBoundary,
)
from app.domain.web_surface import (
    HTTPRequestTemplate,
    WebParameter,
    WebResource,
    WebResourceProvenance,
    WebSurfaceSnapshot,
    WebTemplateCandidate,
)
from app.storage.models import (
    AttackGraphSnapshotRecord,
    AssetRecord,
    CapabilityRecord,
    CandidateSignalRecord,
    DiscoveryPlanRecord,
    EvidenceRecord,
    ExperimentRecord,
    ExperimentExecutionRecord,
    FindingRecord,
    HypothesisRecord,
    IdentityRecord,
    LLMRunRecord,
    ObservationRecord,
    PolicyDecisionRecord,
    ResearchSessionRecord,
    ResearchIntentRecord,
    EvidenceGapRecord,
    KnowledgeSnapshotRecord,
    ResearchQuestionRecord,
    ResearchStepRecord,
    StrategyRunRecord,
    ControllerStepRecord,
    ResearchActionRecord,
    ResearchActionResultRecord,
    ResearchBudgetRecord,
    ActionApprovalRecord,
    ReportMetadataRecord,
    ResearchEventRecord,
    ResearchPolicyRecord,
    ResearchProjectRecord,
    VerificationResultRecord,
    BenchmarkRunRecord,
    ScenarioEvaluationRecord,
    ScenarioRunRecord,
    ProcessedModelObservationRecord,
    SystemAssetRecord,
    SystemCapabilityRecord,
    SystemDataObjectRecord,
    SystemEndpointRecord,
    SystemIdentityRecord,
    SystemModelBuildRecord,
    SystemPermissionRecord,
    SystemRelationshipRecord,
    SystemRoleRecord,
    SystemServiceRecord,
    SystemTrustBoundaryRecord,
    ToolArtifactRecord,
    ToolPolicyDecisionRecord,
    ToolRunRecord,
    HTTPRequestTemplateRecord,
    WebParameterRecord,
    WebResourceProvenanceRecord,
    WebResourceRecord,
    WebSurfaceSnapshotRecord,
    WebTemplateCandidateRecord,
    WebCandidateProvenanceRecord,
    ClientVerificationRunRecord,
    VerificationRecommendationRecord,
    GeneratedPayloadRecord,
)

DomainT = TypeVar("DomainT", bound=BaseModel)
RecordT = TypeVar("RecordT")


class Repository(Generic[DomainT, RecordT]):
    def __init__(
        self,
        session: Session,
        domain_type: type[DomainT],
        record_type: type[RecordT],
        record_fields: Callable[[DomainT], dict[str, object]] | None = None,
    ) -> None:
        self.session = session
        self.domain_type = domain_type
        self.record_type = record_type
        self.record_fields = record_fields or (lambda _: {})

    def add(self, item: DomainT) -> DomainT:
        payload = item.model_dump(mode="json")
        record = self.record_type(
            id=str(item.id),  # type: ignore[attr-defined,call-arg]
            payload=payload,
            **self.record_fields(item),
        )
        self.session.add(record)
        self.session.flush()
        return item

    def get(self, item_id: UUID) -> DomainT | None:
        record = self.session.get(self.record_type, str(item_id))
        if record is None:
            return None
        return self.domain_type.model_validate(record.payload)  # type: ignore[attr-defined]

    def list(self) -> list[DomainT]:
        statement = select(self.record_type).order_by(self.record_type.id)  # type: ignore[attr-defined]
        records = self.session.scalars(statement).all()
        return [self.domain_type.model_validate(record.payload) for record in records]  # type: ignore[attr-defined]

    def delete(self, item_id: UUID) -> bool:
        record = self.session.get(self.record_type, str(item_id))
        if record is None:
            return False
        self.session.delete(record)
        self.session.flush()
        return True

    def update(self, item: DomainT) -> DomainT:
        record = self.session.get(self.record_type, str(item.id))  # type: ignore[attr-defined]
        if record is None:
            raise ValueError(f"{self.domain_type.__name__} does not exist")
        record.payload = item.model_dump(mode="json")  # type: ignore[attr-defined]
        for name, value in self.record_fields(item).items():
            setattr(record, name, value)
        self.session.flush()
        return item


class ResearchSessionRepository(Repository[ResearchSession, ResearchSessionRecord]):
    def update(self, item: ResearchSession) -> ResearchSession:
        existing = self.get(item.id)
        if existing is None:
            raise ValueError("ResearchSession does not exist")
        if existing.status is not ResearchSessionStatus.CREATED and item.scope != existing.scope:
            raise ValueError("scope cannot change after a research session starts")
        return super().update(item)

    def list_by_project(self, project_id: UUID) -> list[ResearchSession]:
        statement = (
            select(ResearchSessionRecord)
            .where(ResearchSessionRecord.project_id == str(project_id))
            .order_by(ResearchSessionRecord.id)
        )
        return [
            ResearchSession.model_validate(row.payload) for row in self.session.scalars(statement)
        ]


class ObservationRepository(Repository[Observation, ObservationRecord]):
    def add(self, item: Observation) -> Observation:
        if item.tool_artifact_id:
            artifact = self.session.get(ToolArtifactRecord, str(item.tool_artifact_id))
            if artifact is None:
                raise ValueError("observation tool artifact does not exist")
            if artifact.research_session_id != str(item.research_session_id):
                raise ValueError("observation tool artifact cannot cross sessions")
        return super().add(item)

    def list_by_session(self, research_session_id: UUID) -> list[Observation]:
        statement = (
            select(ObservationRecord)
            .where(ObservationRecord.research_session_id == str(research_session_id))
            .order_by(ObservationRecord.id)
        )
        return [
            Observation.model_validate(record.payload) for record in self.session.scalars(statement)
        ]


class EvidenceRepository(Repository[Evidence, EvidenceRecord]):
    def list_by_session(self, research_session_id: UUID) -> list[Evidence]:
        statement = (
            select(EvidenceRecord)
            .where(EvidenceRecord.research_session_id == str(research_session_id))
            .order_by(EvidenceRecord.id)
        )
        return [
            Evidence.model_validate(record.payload) for record in self.session.scalars(statement)
        ]


class ClientVerificationRunRepository(Repository[ClientVerificationRun, ClientVerificationRunRecord]):
    def add(self, item: ClientVerificationRun) -> ClientVerificationRun:
        action = self.session.get(ResearchActionRecord, str(item.research_action_id))
        approval = self.session.get(ActionApprovalRecord, str(item.action_approval_id))
        resource = self.session.get(WebResourceRecord, str(item.web_resource_id))
        hypothesis = self.session.get(HypothesisRecord, str(item.hypothesis_id))
        if any(value is None for value in (action, approval, resource, hypothesis)):
            raise ValueError("client verification lineage reference does not exist")
        session_id = str(item.research_session_id)
        if (
            action.research_session_id != session_id
            or approval.research_session_id != session_id
            or approval.action_id != str(item.research_action_id)
            or resource.research_session_id != session_id
            or hypothesis.research_session_id != session_id
        ):
            raise ValueError("client verification lineage cannot cross research sessions")
        return super().add(item)

    def list_by_session(self, research_session_id: UUID) -> list[ClientVerificationRun]:
        statement = (select(ClientVerificationRunRecord)
            .where(ClientVerificationRunRecord.research_session_id == str(research_session_id))
            .order_by(ClientVerificationRunRecord.created_at, ClientVerificationRunRecord.id))
        return [ClientVerificationRun.model_validate(item.payload) for item in self.session.scalars(statement)]


class VerificationRecommendationRepository(Repository[VerificationRecommendation, VerificationRecommendationRecord]):
    def add(self, item: VerificationRecommendation) -> VerificationRecommendation:
        run = self.session.get(ClientVerificationRunRecord, str(item.run_id))
        if run is None or run.research_session_id != str(item.research_session_id):
            raise ValueError("recommendation run lineage cannot cross research sessions")
        evidence_ids = {str(value.id) for value in EvidenceRepository(self.session, Evidence, EvidenceRecord).list_by_session(item.research_session_id)}
        if not set(map(str, item.evidence_refs)).issubset(evidence_ids):
            raise ValueError("recommendation evidence lineage does not exist in research session")
        return super().add(item)

    def get_by_run(self, run_id: UUID) -> VerificationRecommendation | None:
        statement = select(VerificationRecommendationRecord).where(VerificationRecommendationRecord.run_id == str(run_id))
        record = self.session.scalar(statement)
        return VerificationRecommendation.model_validate(record.payload) if record else None

    def list_by_session(self, research_session_id: UUID, *, offset: int = 0, limit: int = 100) -> list[VerificationRecommendation]:
        statement = (select(VerificationRecommendationRecord)
            .where(VerificationRecommendationRecord.research_session_id == str(research_session_id))
            .order_by(VerificationRecommendationRecord.created_at, VerificationRecommendationRecord.id)
            .offset(offset).limit(limit))
        return [VerificationRecommendation.model_validate(item.payload) for item in self.session.scalars(statement)]


class GeneratedPayloadRepository(Repository[GeneratedPayload, GeneratedPayloadRecord]):
    def add(self, item: GeneratedPayload) -> GeneratedPayload:
        run = self.session.get(ClientVerificationRunRecord, str(item.verification_run_id))
        if run is None or run.research_session_id != str(item.research_session_id):
            raise ValueError("generated payload run lineage cannot cross research sessions")
        return super().add(item)

    def get_by_run(self, run_id: UUID) -> GeneratedPayload | None:
        record = self.session.scalar(select(GeneratedPayloadRecord).where(GeneratedPayloadRecord.verification_run_id == str(run_id)))
        return GeneratedPayload.model_validate(record.payload) if record else None


class HypothesisRepository(Repository[Hypothesis, HypothesisRecord]):
    def list_by_session(self, research_session_id: UUID) -> list[Hypothesis]:
        statement = (
            select(HypothesisRecord)
            .where(HypothesisRecord.research_session_id == str(research_session_id))
            .order_by(HypothesisRecord.id)
        )
        return [
            Hypothesis.model_validate(record.payload) for record in self.session.scalars(statement)
        ]


class LLMRunRepository(Repository[LLMRun, LLMRunRecord]):
    def list_by_session(self, research_session_id: UUID) -> list[LLMRun]:
        statement = (
            select(LLMRunRecord)
            .where(LLMRunRecord.research_session_id == str(research_session_id))
            .order_by(LLMRunRecord.id)
        )
        return [LLMRun.model_validate(record.payload) for record in self.session.scalars(statement)]


class ExperimentRepository(Repository[Experiment, ExperimentRecord]):
    def list_by_session(self, research_session_id: UUID) -> list[Experiment]:
        statement = (
            select(ExperimentRecord)
            .where(ExperimentRecord.research_session_id == str(research_session_id))
            .order_by(ExperimentRecord.id)
        )
        return [
            Experiment.model_validate(record.payload) for record in self.session.scalars(statement)
        ]


class ExperimentExecutionRepository(Repository[ExperimentExecution, ExperimentExecutionRecord]):
    def list_by_experiment(self, experiment_id: UUID) -> list[ExperimentExecution]:
        statement = (
            select(ExperimentExecutionRecord)
            .where(ExperimentExecutionRecord.experiment_id == str(experiment_id))
            .order_by(ExperimentExecutionRecord.started_at)
        )
        return [
            ExperimentExecution.model_validate(record.payload)
            for record in self.session.scalars(statement)
        ]


class PolicyDecisionRepository(Repository[PolicyDecisionAudit, PolicyDecisionRecord]):
    def list_by_experiment(self, experiment_id: UUID) -> list[PolicyDecisionAudit]:
        statement = (
            select(PolicyDecisionRecord)
            .where(PolicyDecisionRecord.experiment_id == str(experiment_id))
            .order_by(PolicyDecisionRecord.id)
        )
        return [
            PolicyDecisionAudit.model_validate(record.payload)
            for record in self.session.scalars(statement)
        ]


class VerificationResultRepository(Repository[VerificationResult, VerificationResultRecord]):
    def list_by_session(self, research_session_id: UUID) -> list[VerificationResult]:
        statement = (
            select(VerificationResultRecord)
            .where(VerificationResultRecord.research_session_id == str(research_session_id))
            .order_by(VerificationResultRecord.created_at)
        )
        return [
            VerificationResult.model_validate(record.payload)
            for record in self.session.scalars(statement)
        ]

    def list_by_execution(self, execution_id: UUID) -> list[VerificationResult]:
        statement = (
            select(VerificationResultRecord)
            .where(VerificationResultRecord.execution_id == str(execution_id))
            .order_by(VerificationResultRecord.created_at)
        )
        return [
            VerificationResult.model_validate(record.payload)
            for record in self.session.scalars(statement)
        ]

    def list_by_experiment(self, experiment_id: UUID) -> list[VerificationResult]:
        statement = (
            select(VerificationResultRecord)
            .where(VerificationResultRecord.experiment_id == str(experiment_id))
            .order_by(VerificationResultRecord.created_at)
        )
        return [
            VerificationResult.model_validate(record.payload)
            for record in self.session.scalars(statement)
        ]


class FindingRepository(Repository[Finding, FindingRecord]):
    def list_by_session(self, research_session_id: UUID) -> list[Finding]:
        statement = (
            select(FindingRecord)
            .where(FindingRecord.research_session_id == str(research_session_id))
            .order_by(FindingRecord.id)
        )
        return [
            Finding.model_validate(record.payload) for record in self.session.scalars(statement)
        ]

    def get_by_experiment(self, experiment_id: UUID) -> Finding | None:
        statement = select(FindingRecord).where(FindingRecord.experiment_id == str(experiment_id))
        record = self.session.scalars(statement).first()
        return Finding.model_validate(record.payload) if record else None


class BenchmarkRunRepository(Repository[BenchmarkRun, BenchmarkRunRecord]):
    pass


class ScenarioRunRepository(Repository[ScenarioRun, ScenarioRunRecord]):
    def list_by_benchmark(self, benchmark_run_id: UUID) -> list[ScenarioRun]:
        statement = (
            select(ScenarioRunRecord)
            .where(ScenarioRunRecord.benchmark_run_id == str(benchmark_run_id))
            .order_by(ScenarioRunRecord.scenario_id)
        )
        return [
            ScenarioRun.model_validate(record.payload) for record in self.session.scalars(statement)
        ]

    def get_by_benchmark_scenario(
        self, benchmark_run_id: UUID, scenario_id: str
    ) -> ScenarioRun | None:
        statement = select(ScenarioRunRecord).where(
            ScenarioRunRecord.benchmark_run_id == str(benchmark_run_id),
            ScenarioRunRecord.scenario_id == scenario_id,
        )
        record = self.session.scalars(statement).first()
        return ScenarioRun.model_validate(record.payload) if record else None


class ScenarioEvaluationRepository(Repository[ScenarioEvaluation, ScenarioEvaluationRecord]):
    def list_by_benchmark(self, benchmark_run_id: UUID) -> list[ScenarioEvaluation]:
        statement = (
            select(ScenarioEvaluationRecord)
            .where(ScenarioEvaluationRecord.benchmark_run_id == str(benchmark_run_id))
            .order_by(ScenarioEvaluationRecord.scenario_id)
        )
        return [
            ScenarioEvaluation.model_validate(record.payload)
            for record in self.session.scalars(statement)
        ]

    def get_by_benchmark_scenario(
        self, benchmark_run_id: UUID, scenario_id: str
    ) -> ScenarioEvaluation | None:
        statement = select(ScenarioEvaluationRecord).where(
            ScenarioEvaluationRecord.benchmark_run_id == str(benchmark_run_id),
            ScenarioEvaluationRecord.scenario_id == scenario_id,
        )
        record = self.session.scalars(statement).first()
        return ScenarioEvaluation.model_validate(record.payload) if record else None


SystemFactT = TypeVar("SystemFactT", bound=SystemFact)


class SystemFactRepository(Repository[SystemFactT, RecordT], Generic[SystemFactT, RecordT]):
    def list_by_session(self, research_session_id: UUID) -> list[SystemFactT]:
        statement = (
            select(self.record_type)
            .where(self.record_type.research_session_id == str(research_session_id))
            .order_by(self.record_type.canonical_identifier)
        )
        return [
            self.domain_type.model_validate(row.payload) for row in self.session.scalars(statement)
        ]

    def get_by_canonical(
        self, research_session_id: UUID, canonical_identifier: str
    ) -> SystemFactT | None:
        statement = select(self.record_type).where(
            self.record_type.research_session_id == str(research_session_id),
            self.record_type.canonical_identifier == canonical_identifier,
        )
        row = self.session.scalars(statement).first()
        return self.domain_type.model_validate(row.payload) if row else None

    def delete_by_session(self, research_session_id: UUID) -> None:
        self.session.execute(
            delete(self.record_type).where(
                self.record_type.research_session_id == str(research_session_id)
            )
        )
        self.session.flush()


def _require_same_session(
    session: Session,
    record_type: type[object],
    item_id: UUID,
    research_session_id: UUID,
) -> None:
    record = session.get(record_type, str(item_id))
    if record is None:
        raise ValueError("referenced system model entity does not exist")
    if record.research_session_id != str(research_session_id):
        raise ValueError("system model reference cannot cross research sessions")


class SystemAssetRepository(SystemFactRepository[SystemAsset, SystemAssetRecord]):
    def add(self, item: SystemAsset) -> SystemAsset:
        if item.parent_asset_id:
            _require_same_session(
                self.session,
                SystemAssetRecord,
                item.parent_asset_id,
                item.research_session_id,
            )
        return super().add(item)


class SystemServiceRepository(SystemFactRepository[SystemService, SystemServiceRecord]):
    def add(self, item: SystemService) -> SystemService:
        _require_same_session(
            self.session, SystemAssetRecord, item.asset_id, item.research_session_id
        )
        return super().add(item)


class SystemEndpointRepository(SystemFactRepository[SystemEndpoint, SystemEndpointRecord]):
    def add(self, item: SystemEndpoint) -> SystemEndpoint:
        _require_same_session(
            self.session, SystemServiceRecord, item.service_id, item.research_session_id
        )
        return super().add(item)


class SystemIdentityRepository(SystemFactRepository[SystemIdentity, SystemIdentityRecord]):
    def add(self, item: SystemIdentity) -> SystemIdentity:
        if item.role_id:
            _require_same_session(
                self.session, SystemRoleRecord, item.role_id, item.research_session_id
            )
        return super().add(item)


_SYSTEM_ENTITY_RECORDS = {
    SystemEntityType.ASSET: SystemAssetRecord,
    SystemEntityType.SERVICE: SystemServiceRecord,
    SystemEntityType.ENDPOINT: SystemEndpointRecord,
    SystemEntityType.IDENTITY: SystemIdentityRecord,
    SystemEntityType.ROLE: SystemRoleRecord,
    SystemEntityType.PERMISSION: SystemPermissionRecord,
    SystemEntityType.CAPABILITY: SystemCapabilityRecord,
    SystemEntityType.DATA_OBJECT: SystemDataObjectRecord,
    SystemEntityType.TRUST_BOUNDARY: SystemTrustBoundaryRecord,
}


class SystemPermissionRepository(SystemFactRepository[SystemPermission, SystemPermissionRecord]):
    def add(self, item: SystemPermission) -> SystemPermission:
        _require_same_session(
            self.session,
            _SYSTEM_ENTITY_RECORDS[item.subject_entity_type],
            item.subject_entity_id,
            item.research_session_id,
        )
        _require_same_session(
            self.session,
            _SYSTEM_ENTITY_RECORDS[item.resource_type],
            item.resource_id,
            item.research_session_id,
        )
        return super().add(item)


class SystemCapabilityRepository(SystemFactRepository[SystemCapability, SystemCapabilityRecord]):
    def add(self, item: SystemCapability) -> SystemCapability:
        _require_same_session(
            self.session,
            _SYSTEM_ENTITY_RECORDS[item.subject_entity_type],
            item.subject_entity_id,
            item.research_session_id,
        )
        _require_same_session(
            self.session,
            _SYSTEM_ENTITY_RECORDS[item.resource_entity_type],
            item.resource_entity_id,
            item.research_session_id,
        )
        return super().add(item)


class SystemRelationshipRepository(
    SystemFactRepository[SystemRelationship, SystemRelationshipRecord]
):
    def add(self, item: SystemRelationship) -> SystemRelationship:
        source = self.session.get(
            _SYSTEM_ENTITY_RECORDS[item.source_entity_type], str(item.source_entity_id)
        )
        target = self.session.get(
            _SYSTEM_ENTITY_RECORDS[item.target_entity_type], str(item.target_entity_id)
        )
        if source is None or target is None:
            raise ValueError("system relationship endpoints must exist")
        if source.research_session_id != str(
            item.research_session_id
        ) or target.research_session_id != str(item.research_session_id):
            raise ValueError("system relationship cannot cross research sessions")
        return super().add(item)

    def list_filtered(
        self,
        research_session_id: UUID,
        *,
        relationship_type: str | None = None,
        source_entity_id: UUID | None = None,
        target_entity_id: UUID | None = None,
    ) -> list[SystemRelationship]:
        statement = select(SystemRelationshipRecord).where(
            SystemRelationshipRecord.research_session_id == str(research_session_id)
        )
        if relationship_type:
            statement = statement.where(
                SystemRelationshipRecord.relationship_type == relationship_type
            )
        if source_entity_id:
            statement = statement.where(
                SystemRelationshipRecord.source_entity_id == str(source_entity_id)
            )
        if target_entity_id:
            statement = statement.where(
                SystemRelationshipRecord.target_entity_id == str(target_entity_id)
            )
        statement = statement.order_by(SystemRelationshipRecord.canonical_identifier)
        return [
            SystemRelationship.model_validate(row.payload)
            for row in self.session.scalars(statement)
        ]


class ProcessedModelObservationRepository(
    Repository[ProcessedModelObservation, ProcessedModelObservationRecord]
):
    def observation_ids(self, research_session_id: UUID) -> set[UUID]:
        statement = select(ProcessedModelObservationRecord.observation_id).where(
            ProcessedModelObservationRecord.research_session_id == str(research_session_id)
        )
        return {UUID(value) for value in self.session.scalars(statement)}

    def delete_by_session(self, research_session_id: UUID) -> None:
        self.session.execute(
            delete(ProcessedModelObservationRecord).where(
                ProcessedModelObservationRecord.research_session_id == str(research_session_id)
            )
        )


class SystemModelBuildRepository(Repository[SystemModelBuild, SystemModelBuildRecord]):
    def list_by_session(self, research_session_id: UUID) -> list[SystemModelBuild]:
        statement = (
            select(SystemModelBuildRecord)
            .where(SystemModelBuildRecord.research_session_id == str(research_session_id))
            .order_by(SystemModelBuildRecord.started_at)
        )
        return [
            SystemModelBuild.model_validate(row.payload) for row in self.session.scalars(statement)
        ]


class AttackGraphSnapshotRepository(Repository[AttackGraphSnapshot, AttackGraphSnapshotRecord]):
    def add(self, item: AttackGraphSnapshot) -> AttackGraphSnapshot:
        if item.system_model_build_id:
            _require_same_session(
                self.session,
                SystemModelBuildRecord,
                item.system_model_build_id,
                item.research_session_id,
            )
        return super().add(item)

    def list_by_session(self, research_session_id: UUID) -> list[AttackGraphSnapshot]:
        statement = (
            select(AttackGraphSnapshotRecord)
            .where(AttackGraphSnapshotRecord.research_session_id == str(research_session_id))
            .order_by(AttackGraphSnapshotRecord.created_at)
        )
        return [
            AttackGraphSnapshot.model_validate(row.payload)
            for row in self.session.scalars(statement)
        ]

    def mark_stale_except(self, research_session_id: UUID, current_model_hash: str) -> None:
        for item in self.list_by_session(research_session_id):
            if (
                item.status is GraphSnapshotStatus.CURRENT
                and item.system_model_hash != current_model_hash
            ):
                self.update(item.model_copy(update={"status": GraphSnapshotStatus.STALE}))


class CandidateSignalRepository(Repository[CandidateSignal, CandidateSignalRecord]):
    def add(self, item: CandidateSignal) -> CandidateSignal:
        graph = self.session.get(AttackGraphSnapshotRecord, str(item.graph_id))
        if graph is None:
            raise ValueError("candidate signal graph does not exist")
        if graph.research_session_id != str(item.research_session_id):
            raise ValueError("candidate signal cannot cross research sessions")
        for record_type, entity_id in (
            (SystemIdentityRecord, item.subject_entity_id),
            (SystemIdentityRecord, item.target_entity_id),
            (SystemDataObjectRecord, item.resource_entity_id),
            (SystemEndpointRecord, item.endpoint_entity_id),
        ):
            if entity_id:
                _require_same_session(
                    self.session, record_type, entity_id, item.research_session_id
                )
        return super().add(item)

    def list_by_graph(self, graph_id: UUID) -> list[CandidateSignal]:
        statement = (
            select(CandidateSignalRecord)
            .where(CandidateSignalRecord.graph_id == str(graph_id))
            .order_by(CandidateSignalRecord.semantic_key)
        )
        return [
            CandidateSignal.model_validate(row.payload) for row in self.session.scalars(statement)
        ]


class DiscoveryPlanRepository(Repository[DiscoveryPlan, DiscoveryPlanRecord]):
    def list_by_session(self, research_session_id: UUID) -> list[DiscoveryPlan]:
        statement = (
            select(DiscoveryPlanRecord)
            .where(DiscoveryPlanRecord.research_session_id == str(research_session_id))
            .order_by(DiscoveryPlanRecord.created_at)
        )
        return [
            DiscoveryPlan.model_validate(row.payload) for row in self.session.scalars(statement)
        ]


class ToolRunRepository(Repository[ToolRun, ToolRunRecord]):
    def add(self, item: ToolRun) -> ToolRun:
        plan = self.session.get(DiscoveryPlanRecord, str(item.discovery_plan_id))
        if plan is None or plan.research_session_id != str(item.research_session_id):
            raise ValueError("tool run plan cannot cross research sessions")
        return super().add(item)

    def list_by_plan(self, discovery_plan_id: UUID) -> list[ToolRun]:
        statement = (
            select(ToolRunRecord)
            .where(ToolRunRecord.discovery_plan_id == str(discovery_plan_id))
            .order_by(ToolRunRecord.started_at)
        )
        return [ToolRun.model_validate(row.payload) for row in self.session.scalars(statement)]

    def list_by_session(self, research_session_id: UUID) -> list[ToolRun]:
        statement = (
            select(ToolRunRecord)
            .where(ToolRunRecord.research_session_id == str(research_session_id))
            .order_by(ToolRunRecord.started_at)
        )
        return [ToolRun.model_validate(row.payload) for row in self.session.scalars(statement)]


class ToolPolicyDecisionRepository(Repository[ToolPolicyDecision, ToolPolicyDecisionRecord]):
    def add(self, item: ToolPolicyDecision) -> ToolPolicyDecision:
        run = self.session.get(ToolRunRecord, str(item.tool_run_id))
        if run is None or run.research_session_id != str(item.research_session_id):
            raise ValueError("tool policy decision cannot cross research sessions")
        return super().add(item)


class ToolArtifactRepository(Repository[ToolArtifact, ToolArtifactRecord]):
    def add(self, item: ToolArtifact) -> ToolArtifact:
        run = self.session.get(ToolRunRecord, str(item.tool_run_id))
        if run is None or run.research_session_id != str(item.research_session_id):
            raise ValueError("tool artifact cannot cross research sessions")
        return super().add(item)

    def list_by_run(self, tool_run_id: UUID) -> list[ToolArtifact]:
        statement = (
            select(ToolArtifactRecord)
            .where(ToolArtifactRecord.tool_run_id == str(tool_run_id))
            .order_by(ToolArtifactRecord.created_at)
        )
        return [ToolArtifact.model_validate(row.payload) for row in self.session.scalars(statement)]

    def list_by_session(self, research_session_id: UUID) -> list[ToolArtifact]:
        statement = (
            select(ToolArtifactRecord)
            .where(ToolArtifactRecord.research_session_id == str(research_session_id))
            .order_by(ToolArtifactRecord.created_at, ToolArtifactRecord.id)
        )
        return [ToolArtifact.model_validate(row.payload) for row in self.session.scalars(statement)]


class ResearchStepRepository(Repository[ResearchStep, ResearchStepRecord]):
    def list_by_session(self, research_session_id: UUID) -> list[ResearchStep]:
        statement = (
            select(ResearchStepRecord)
            .where(ResearchStepRecord.research_session_id == str(research_session_id))
            .order_by(ResearchStepRecord.step_number)
        )
        return [ResearchStep.model_validate(row.payload) for row in self.session.scalars(statement)]


class ResearchIntentRepository(Repository[ResearchIntent, ResearchIntentRecord]):
    def list_by_session(self, research_session_id: UUID) -> list[ResearchIntent]:
        statement = (
            select(ResearchIntentRecord)
            .where(ResearchIntentRecord.research_session_id == str(research_session_id))
            .order_by(ResearchIntentRecord.created_at, ResearchIntentRecord.id)
        )
        return [
            ResearchIntent.model_validate(row.payload) for row in self.session.scalars(statement)
        ]

    def list_by_step(self, research_step_id: UUID) -> list[ResearchIntent]:
        statement = (
            select(ResearchIntentRecord)
            .where(ResearchIntentRecord.research_step_id == str(research_step_id))
            .order_by(ResearchIntentRecord.created_at, ResearchIntentRecord.id)
        )
        return [
            ResearchIntent.model_validate(row.payload) for row in self.session.scalars(statement)
        ]


class KnowledgeSnapshotRepository(Repository[KnowledgeSnapshot, KnowledgeSnapshotRecord]):
    def list_by_session(self, research_session_id: UUID) -> list[KnowledgeSnapshot]:
        statement = (
            select(KnowledgeSnapshotRecord)
            .where(KnowledgeSnapshotRecord.research_session_id == str(research_session_id))
            .order_by(KnowledgeSnapshotRecord.created_at)
        )
        return [
            KnowledgeSnapshot.model_validate(row.payload) for row in self.session.scalars(statement)
        ]


class EvidenceGapRepository(Repository[EvidenceGap, EvidenceGapRecord]):
    def list_by_session(self, research_session_id: UUID) -> list[EvidenceGap]:
        statement = (
            select(EvidenceGapRecord)
            .where(EvidenceGapRecord.research_session_id == str(research_session_id))
            .order_by(EvidenceGapRecord.semantic_key)
        )
        return [EvidenceGap.model_validate(row.payload) for row in self.session.scalars(statement)]

    def get_by_semantic(self, research_session_id: UUID, semantic_key: str) -> EvidenceGap | None:
        statement = select(EvidenceGapRecord).where(
            EvidenceGapRecord.research_session_id == str(research_session_id),
            EvidenceGapRecord.semantic_key == semantic_key,
        )
        row = self.session.scalars(statement).first()
        return EvidenceGap.model_validate(row.payload) if row else None


class ResearchQuestionRepository(Repository[ResearchQuestion, ResearchQuestionRecord]):
    def list_by_session(self, research_session_id: UUID) -> list[ResearchQuestion]:
        statement = (
            select(ResearchQuestionRecord)
            .where(ResearchQuestionRecord.research_session_id == str(research_session_id))
            .order_by(ResearchQuestionRecord.semantic_key)
        )
        return [
            ResearchQuestion.model_validate(row.payload) for row in self.session.scalars(statement)
        ]

    def get_by_semantic(
        self, research_session_id: UUID, semantic_key: str
    ) -> ResearchQuestion | None:
        statement = select(ResearchQuestionRecord).where(
            ResearchQuestionRecord.research_session_id == str(research_session_id),
            ResearchQuestionRecord.semantic_key == semantic_key,
        )
        row = self.session.scalars(statement).first()
        return ResearchQuestion.model_validate(row.payload) if row else None


class StrategyRunRepository(Repository[StrategyRun, StrategyRunRecord]):
    def list_by_session(self, research_session_id: UUID) -> list[StrategyRun]:
        statement = (
            select(StrategyRunRecord)
            .where(StrategyRunRecord.research_session_id == str(research_session_id))
            .order_by(StrategyRunRecord.started_at)
        )
        return [StrategyRun.model_validate(row.payload) for row in self.session.scalars(statement)]


class ResearchBudgetRepository(Repository[ResearchBudget, ResearchBudgetRecord]):
    def get_by_session(self, research_session_id: UUID) -> ResearchBudget | None:
        statement = select(ResearchBudgetRecord).where(
            ResearchBudgetRecord.research_session_id == str(research_session_id)
        )
        row = self.session.scalars(statement).first()
        return ResearchBudget.model_validate(row.payload) if row else None


class ControllerStepRepository(Repository[ControllerStep, ControllerStepRecord]):
    def list_by_session(self, research_session_id: UUID) -> list[ControllerStep]:
        statement = (
            select(ControllerStepRecord)
            .where(ControllerStepRecord.research_session_id == str(research_session_id))
            .order_by(ControllerStepRecord.step_number)
        )
        return [
            ControllerStep.model_validate(row.payload) for row in self.session.scalars(statement)
        ]


class ResearchActionRepository(Repository[ResearchAction, ResearchActionRecord]):
    def list_by_session(self, research_session_id: UUID) -> list[ResearchAction]:
        statement = (
            select(ResearchActionRecord)
            .where(ResearchActionRecord.research_session_id == str(research_session_id))
            .order_by(ResearchActionRecord.created_at, ResearchActionRecord.id)
        )
        return [
            ResearchAction.model_validate(row.payload) for row in self.session.scalars(statement)
        ]

    def list_by_step(self, controller_step_id: UUID) -> list[ResearchAction]:
        statement = (
            select(ResearchActionRecord)
            .where(ResearchActionRecord.controller_step_id == str(controller_step_id))
            .order_by(ResearchActionRecord.created_at, ResearchActionRecord.id)
        )
        return [
            ResearchAction.model_validate(row.payload) for row in self.session.scalars(statement)
        ]

    def get_satisfied_by_hash(
        self, research_session_id: UUID, semantic_hash: str
    ) -> ResearchAction | None:
        statement = select(ResearchActionRecord).where(
            ResearchActionRecord.research_session_id == str(research_session_id),
            ResearchActionRecord.semantic_hash == semantic_hash,
            ResearchActionRecord.status.in_(("SATISFIED", "COMPLETED")),
        )
        row = self.session.scalars(statement).first()
        return ResearchAction.model_validate(row.payload) if row else None

    def count_by_hash(self, research_session_id: UUID, semantic_hash: str) -> int:
        statement = select(ResearchActionRecord).where(
            ResearchActionRecord.research_session_id == str(research_session_id),
            ResearchActionRecord.semantic_hash == semantic_hash,
        )
        return len(list(self.session.scalars(statement)))


class ResearchActionResultRepository(Repository[ResearchActionResult, ResearchActionResultRecord]):
    def get_by_action(self, action_id: UUID) -> ResearchActionResult | None:
        statement = select(ResearchActionResultRecord).where(
            ResearchActionResultRecord.action_id == str(action_id)
        )
        row = self.session.scalars(statement).first()
        return ResearchActionResult.model_validate(row.payload) if row else None


class ResearchProjectRepository(Repository[ResearchProject, ResearchProjectRecord]):
    pass


class ActionApprovalRepository(Repository[ActionApproval, ActionApprovalRecord]):
    def get_by_action(self, action_id: UUID) -> ActionApproval | None:
        statement = select(ActionApprovalRecord).where(
            ActionApprovalRecord.action_id == str(action_id)
        )
        row = self.session.scalars(statement).first()
        return ActionApproval.model_validate(row.payload) if row else None

    def list_by_session(self, session_id: UUID) -> list[ActionApproval]:
        statement = (
            select(ActionApprovalRecord)
            .where(ActionApprovalRecord.research_session_id == str(session_id))
            .order_by(ActionApprovalRecord.created_at, ActionApprovalRecord.id)
        )
        return [
            ActionApproval.model_validate(row.payload) for row in self.session.scalars(statement)
        ]


class ResearchEventRepository(Repository[ResearchEvent, ResearchEventRecord]):
    def list_by_session(
        self,
        session_id: UUID,
        *,
        offset: int = 0,
        limit: int = 100,
        event_type: str | None = None,
    ) -> list[ResearchEvent]:
        statement = select(ResearchEventRecord).where(
            ResearchEventRecord.research_session_id == str(session_id)
        )
        if event_type:
            statement = statement.where(ResearchEventRecord.event_type == event_type)
        statement = (
            statement.order_by(ResearchEventRecord.sequence_number).offset(offset).limit(limit)
        )
        return [
            ResearchEvent.model_validate(row.payload) for row in self.session.scalars(statement)
        ]

    def next_sequence(self, project_id: UUID, session_id: UUID | None) -> int:
        statement = select(ResearchEventRecord).where(
            ResearchEventRecord.project_id == str(project_id),
            ResearchEventRecord.research_session_id == (str(session_id) if session_id else None),
        )
        return len(list(self.session.scalars(statement))) + 1

    def get_by_idempotency(self, key: str) -> ResearchEvent | None:
        statement = select(ResearchEventRecord).where(ResearchEventRecord.idempotency_key == key)
        row = self.session.scalars(statement).first()
        return ResearchEvent.model_validate(row.payload) if row else None


class ReportMetadataRepository(Repository[ReportMetadata, ReportMetadataRecord]):
    def list_by_session(self, session_id: UUID) -> list[ReportMetadata]:
        statement = (
            select(ReportMetadataRecord)
            .where(ReportMetadataRecord.research_session_id == str(session_id))
            .order_by(ReportMetadataRecord.generated_at)
        )
        return [
            ReportMetadata.model_validate(row.payload) for row in self.session.scalars(statement)
        ]


class WebResourceRepository(Repository[WebResource, WebResourceRecord]):
    def get_by_canonical(self, session_id: UUID, canonical_key: str) -> WebResource | None:
        statement = select(WebResourceRecord).where(
            WebResourceRecord.research_session_id == str(session_id),
            WebResourceRecord.canonical_key == canonical_key,
        )
        row = self.session.scalars(statement).first()
        return WebResource.model_validate(row.payload) if row else None

    def list_by_session(self, session_id: UUID) -> list[WebResource]:
        statement = (
            select(WebResourceRecord)
            .where(WebResourceRecord.research_session_id == str(session_id))
            .order_by(WebResourceRecord.canonical_key)
        )
        return [WebResource.model_validate(row.payload) for row in self.session.scalars(statement)]

    def delete_by_session(self, session_id: UUID) -> None:
        self.session.execute(
            delete(WebResourceRecord).where(
                WebResourceRecord.research_session_id == str(session_id)
            )
        )


class WebResourceProvenanceRepository(
    Repository[WebResourceProvenance, WebResourceProvenanceRecord]
):
    def add(self, item: WebResourceProvenance) -> WebResourceProvenance:
        resource = self.session.get(WebResourceRecord, str(item.web_resource_id))
        observation = self.session.get(ObservationRecord, str(item.observation_id))
        if resource is None or observation is None:
            raise ValueError("web provenance references missing resource or observation")
        if resource.research_session_id != str(
            item.research_session_id
        ) or observation.research_session_id != str(item.research_session_id):
            raise ValueError("web provenance cannot cross research sessions")
        return super().add(item)

    def get_semantic(
        self, resource_id: UUID, observation_id: UUID, source: str
    ) -> WebResourceProvenance | None:
        statement = select(WebResourceProvenanceRecord).where(
            WebResourceProvenanceRecord.web_resource_id == str(resource_id),
            WebResourceProvenanceRecord.observation_id == str(observation_id),
            WebResourceProvenanceRecord.source == source,
        )
        row = self.session.scalars(statement).first()
        return WebResourceProvenance.model_validate(row.payload) if row else None

    def list_by_resource(self, resource_id: UUID) -> list[WebResourceProvenance]:
        statement = (
            select(WebResourceProvenanceRecord)
            .where(WebResourceProvenanceRecord.web_resource_id == str(resource_id))
            .order_by(WebResourceProvenanceRecord.observed_at)
        )
        return [
            WebResourceProvenance.model_validate(row.payload)
            for row in self.session.scalars(statement)
        ]

    def list_by_session(self, session_id: UUID) -> list[WebResourceProvenance]:
        statement = select(WebResourceProvenanceRecord).where(
            WebResourceProvenanceRecord.research_session_id == str(session_id)
        )
        return [
            WebResourceProvenance.model_validate(row.payload)
            for row in self.session.scalars(statement)
        ]

    def delete_by_session(self, session_id: UUID) -> None:
        self.session.execute(
            delete(WebResourceProvenanceRecord).where(
                WebResourceProvenanceRecord.research_session_id == str(session_id)
            )
        )


class WebParameterRepository(Repository[WebParameter, WebParameterRecord]):
    def _validate_session(self, item: WebParameter) -> None:
        resource = self.session.get(WebResourceRecord, str(item.web_resource_id))
        if resource is None or resource.research_session_id != str(item.research_session_id):
            raise ValueError("web parameter cannot cross research sessions")

    def add(self, item: WebParameter) -> WebParameter:
        self._validate_session(item)
        return super().add(item)

    def update(self, item: WebParameter) -> WebParameter:
        self._validate_session(item)
        return super().update(item)

    def get_semantic(self, resource_id: UUID, name: str, location: str) -> WebParameter | None:
        statement = select(WebParameterRecord).where(
            WebParameterRecord.web_resource_id == str(resource_id),
            WebParameterRecord.name == name,
            WebParameterRecord.location == location,
        )
        row = self.session.scalars(statement).first()
        return WebParameter.model_validate(row.payload) if row else None

    def list_by_session(self, session_id: UUID) -> list[WebParameter]:
        statement = (
            select(WebParameterRecord)
            .where(WebParameterRecord.research_session_id == str(session_id))
            .order_by(WebParameterRecord.name, WebParameterRecord.location)
        )
        return [WebParameter.model_validate(row.payload) for row in self.session.scalars(statement)]

    def list_by_resource(self, resource_id: UUID) -> list[WebParameter]:
        statement = select(WebParameterRecord).where(
            WebParameterRecord.web_resource_id == str(resource_id)
        )
        return [WebParameter.model_validate(row.payload) for row in self.session.scalars(statement)]

    def delete_by_session(self, session_id: UUID) -> None:
        self.session.execute(
            delete(WebParameterRecord).where(
                WebParameterRecord.research_session_id == str(session_id)
            )
        )


class HTTPRequestTemplateRepository(Repository[HTTPRequestTemplate, HTTPRequestTemplateRecord]):
    def _validate_session(self, item: HTTPRequestTemplate) -> None:
        resource = self.session.get(WebResourceRecord, str(item.web_resource_id))
        if resource is None or resource.research_session_id != str(item.research_session_id):
            raise ValueError("request template cannot cross research sessions")
        for observation_id in item.source_observation_ids:
            observation = self.session.get(ObservationRecord, str(observation_id))
            if observation is None or observation.research_session_id != str(
                item.research_session_id
            ):
                raise ValueError("request template observation cannot cross research sessions")

    def add(self, item: HTTPRequestTemplate) -> HTTPRequestTemplate:
        self._validate_session(item)
        return super().add(item)

    def update(self, item: HTTPRequestTemplate) -> HTTPRequestTemplate:
        self._validate_session(item)
        return super().update(item)

    def get_by_semantic(self, session_id: UUID, semantic_key: str) -> HTTPRequestTemplate | None:
        statement = select(HTTPRequestTemplateRecord).where(
            HTTPRequestTemplateRecord.research_session_id == str(session_id),
            HTTPRequestTemplateRecord.semantic_key == semantic_key,
        )
        row = self.session.scalars(statement).first()
        return HTTPRequestTemplate.model_validate(row.payload) if row else None

    def list_by_session(self, session_id: UUID) -> list[HTTPRequestTemplate]:
        statement = (
            select(HTTPRequestTemplateRecord)
            .where(HTTPRequestTemplateRecord.research_session_id == str(session_id))
            .order_by(HTTPRequestTemplateRecord.semantic_key)
        )
        return [
            HTTPRequestTemplate.model_validate(row.payload)
            for row in self.session.scalars(statement)
        ]

    def list_by_resource(self, resource_id: UUID) -> list[HTTPRequestTemplate]:
        statement = select(HTTPRequestTemplateRecord).where(
            HTTPRequestTemplateRecord.web_resource_id == str(resource_id)
        )
        return [
            HTTPRequestTemplate.model_validate(row.payload)
            for row in self.session.scalars(statement)
        ]

    def delete_by_session(self, session_id: UUID) -> None:
        self.session.execute(
            delete(HTTPRequestTemplateRecord).where(
                HTTPRequestTemplateRecord.research_session_id == str(session_id)
            )
        )


class WebTemplateCandidateRepository(Repository[WebTemplateCandidate, WebTemplateCandidateRecord]):
    def _validate_session(self, item: WebTemplateCandidate) -> None:
        session_id = str(item.research_session_id)
        resource = self.session.get(WebResourceRecord, str(item.web_resource_id))
        artifact = self.session.get(ToolArtifactRecord, str(item.tool_artifact_id))
        observation = self.session.get(ObservationRecord, str(item.observation_id))
        if any(
            row is None or row.research_session_id != session_id
            for row in (resource, artifact, observation)
        ):
            raise ValueError("web candidate cannot cross research sessions")

    def add(self, item: WebTemplateCandidate) -> WebTemplateCandidate:
        self._validate_session(item)
        return super().add(item)

    def update(self, item: WebTemplateCandidate) -> WebTemplateCandidate:
        self._validate_session(item)
        return super().update(item)

    def get_by_semantic(self, session_id: UUID, semantic_key: str) -> WebTemplateCandidate | None:
        statement = select(WebTemplateCandidateRecord).where(
            WebTemplateCandidateRecord.research_session_id == str(session_id),
            WebTemplateCandidateRecord.semantic_key == semantic_key,
        )
        row = self.session.scalars(statement).first()
        return WebTemplateCandidate.model_validate(row.payload) if row else None

    def list_by_session(self, session_id: UUID) -> list[WebTemplateCandidate]:
        statement = (
            select(WebTemplateCandidateRecord)
            .where(WebTemplateCandidateRecord.research_session_id == str(session_id))
            .order_by(WebTemplateCandidateRecord.semantic_key)
        )
        return [
            WebTemplateCandidate.model_validate(row.payload)
            for row in self.session.scalars(statement)
        ]

    def list_by_resource(self, resource_id: UUID) -> list[WebTemplateCandidate]:
        statement = select(WebTemplateCandidateRecord).where(
            WebTemplateCandidateRecord.web_resource_id == str(resource_id)
        )
        return [
            WebTemplateCandidate.model_validate(row.payload)
            for row in self.session.scalars(statement)
        ]

    def delete_by_session(self, session_id: UUID) -> None:
        self.session.execute(
            delete(WebTemplateCandidateRecord).where(
                WebTemplateCandidateRecord.research_session_id == str(session_id)
            )
        )


class WebCandidateProvenanceRepository(
    Repository[WebCandidateProvenance, WebCandidateProvenanceRecord]
):
    def add(self, item: WebCandidateProvenance) -> WebCandidateProvenance:
        candidate = self.session.get(
            WebTemplateCandidateRecord, str(item.web_template_candidate_id)
        )
        resource = self.session.get(WebResourceRecord, str(item.web_resource_id))
        artifact = self.session.get(ToolArtifactRecord, str(item.tool_artifact_id))
        observation = self.session.get(ObservationRecord, str(item.observation_id))
        run = self.session.get(ToolRunRecord, str(item.tool_run_id))
        expected_session = str(item.research_session_id)
        if any(row is None for row in (candidate, resource, artifact, observation, run)):
            raise ValueError("candidate provenance requires complete persisted lineage")
        if any(
            row.research_session_id != expected_session
            for row in (candidate, resource, artifact, observation, run)
        ):
            raise ValueError("candidate provenance cannot cross ResearchSession boundaries")
        if candidate.web_resource_id != str(item.web_resource_id):
            raise ValueError("candidate provenance resource does not match candidate")
        if artifact.tool_run_id != str(item.tool_run_id):
            raise ValueError("candidate provenance artifact does not match ToolRun")
        if observation.tool_artifact_id != str(item.tool_artifact_id):
            raise ValueError("candidate provenance Observation does not match artifact")
        return super().add(item)

    def get_semantic(
        self, candidate_id: UUID, observation_id: UUID, source: str
    ) -> WebCandidateProvenance | None:
        statement = select(WebCandidateProvenanceRecord).where(
            WebCandidateProvenanceRecord.web_template_candidate_id == str(candidate_id),
            WebCandidateProvenanceRecord.observation_id == str(observation_id),
            WebCandidateProvenanceRecord.source == source,
        )
        row = self.session.scalars(statement).first()
        return WebCandidateProvenance.model_validate(row.payload) if row else None

    def list_by_candidate(self, candidate_id: UUID) -> list[WebCandidateProvenance]:
        statement = (
            select(WebCandidateProvenanceRecord)
            .where(
                WebCandidateProvenanceRecord.web_template_candidate_id == str(candidate_id)
            )
            .order_by(WebCandidateProvenanceRecord.created_at, WebCandidateProvenanceRecord.id)
        )
        return [
            WebCandidateProvenance.model_validate(row.payload)
            for row in self.session.scalars(statement)
        ]

    def list_by_session(self, session_id: UUID) -> list[WebCandidateProvenance]:
        statement = (
            select(WebCandidateProvenanceRecord)
            .where(WebCandidateProvenanceRecord.research_session_id == str(session_id))
            .order_by(WebCandidateProvenanceRecord.created_at, WebCandidateProvenanceRecord.id)
        )
        return [
            WebCandidateProvenance.model_validate(row.payload)
            for row in self.session.scalars(statement)
        ]

    def delete_by_session(self, session_id: UUID) -> None:
        self.session.execute(
            delete(WebCandidateProvenanceRecord).where(
                WebCandidateProvenanceRecord.research_session_id == str(session_id)
            )
        )


class WebSurfaceSnapshotRepository(Repository[WebSurfaceSnapshot, WebSurfaceSnapshotRecord]):
    def list_by_session(self, session_id: UUID) -> list[WebSurfaceSnapshot]:
        statement = (
            select(WebSurfaceSnapshotRecord)
            .where(WebSurfaceSnapshotRecord.research_session_id == str(session_id))
            .order_by(WebSurfaceSnapshotRecord.created_at)
        )
        return [
            WebSurfaceSnapshot.model_validate(row.payload)
            for row in self.session.scalars(statement)
        ]


class RepositorySet:
    """Transaction-local access to all Phase 0 repositories."""

    def __init__(self, session: Session) -> None:
        self.assets = Repository(session, Asset, AssetRecord)
        self.research_policies = Repository(
            session,
            ResearchPolicy,
            ResearchPolicyRecord,
            lambda item: {
                "profile": item.profile.value,
                "created_at": item.created_at.isoformat(),
            },
        )
        self.research_projects = ResearchProjectRepository(
            session,
            ResearchProject,
            ResearchProjectRecord,
            lambda item: {
                "status": item.status.value,
                "research_policy_id": str(item.research_policy_id),
                "updated_at": item.updated_at.isoformat(),
            },
        )
        self.action_approvals = ActionApprovalRepository(
            session,
            ActionApproval,
            ActionApprovalRecord,
            lambda item: {
                "project_id": str(item.project_id),
                "research_session_id": str(item.research_session_id),
                "action_id": str(item.action_id),
                "status": item.status.value,
                "created_at": item.created_at.isoformat(),
            },
        )
        self.client_verification_runs = ClientVerificationRunRepository(
            session,
            ClientVerificationRun,
            ClientVerificationRunRecord,
            lambda item: {
                "research_session_id": str(item.research_session_id),
                "research_action_id": str(item.research_action_id),
                "action_approval_id": str(item.action_approval_id),
                "web_resource_id": str(item.web_resource_id),
                "hypothesis_id": str(item.hypothesis_id),
                "status": item.status.value,
                "created_at": item.created_at.isoformat(),
            },
        )
        self.verification_recommendations = VerificationRecommendationRepository(
            session, VerificationRecommendation, VerificationRecommendationRecord,
            lambda item: {"run_id": str(item.run_id), "research_session_id": str(item.research_session_id),
                          "verdict": item.verdict.value, "recommended_action": item.recommended_action.value,
                          "created_at": item.created_at.isoformat()},
        )
        self.generated_payloads = GeneratedPayloadRepository(
            session, GeneratedPayload, GeneratedPayloadRecord,
            lambda item: {"verification_run_id": str(item.verification_run_id), "research_session_id": str(item.research_session_id),
                          "vulnerability_class": item.vulnerability_class.value, "injection_context": item.injection_context.value,
                          "created_at": item.created_at.isoformat()},
        )
        self.research_events = ResearchEventRepository(
            session,
            ResearchEvent,
            ResearchEventRecord,
            lambda item: {
                "project_id": str(item.project_id),
                "research_session_id": (
                    str(item.research_session_id) if item.research_session_id else None
                ),
                "sequence_number": item.sequence_number,
                "event_type": item.event_type.value,
                "severity": item.severity.value,
                "idempotency_key": item.idempotency_key,
                "created_at": item.created_at.isoformat(),
            },
        )
        self.report_metadata = ReportMetadataRepository(
            session,
            ReportMetadata,
            ReportMetadataRecord,
            lambda item: {
                "project_id": str(item.project_id),
                "research_session_id": str(item.research_session_id),
                "status": item.status.value,
                "generated_at": item.generated_at.isoformat(),
            },
        )
        self.web_resources = WebResourceRepository(
            session,
            WebResource,
            WebResourceRecord,
            lambda item: {
                "research_session_id": str(item.research_session_id),
                "canonical_key": item.canonical_key,
                "method": item.method,
                "path": item.path,
                "resource_type": item.resource_type.value,
                "system_endpoint_id": (
                    str(item.system_endpoint_id) if item.system_endpoint_id else None
                ),
            },
        )
        self.web_resource_provenance = WebResourceProvenanceRepository(
            session,
            WebResourceProvenance,
            WebResourceProvenanceRecord,
            lambda item: {
                "research_session_id": str(item.research_session_id),
                "web_resource_id": str(item.web_resource_id),
                "observation_id": str(item.observation_id),
                "tool_artifact_id": (str(item.tool_artifact_id) if item.tool_artifact_id else None),
                "evidence_id": str(item.evidence_id) if item.evidence_id else None,
                "source": item.source.value,
                "observed_at": item.observed_at.isoformat(),
            },
        )
        self.web_parameters = WebParameterRepository(
            session,
            WebParameter,
            WebParameterRecord,
            lambda item: {
                "research_session_id": str(item.research_session_id),
                "web_resource_id": str(item.web_resource_id),
                "name": item.name,
                "location": item.location.value,
            },
        )
        self.http_request_templates = HTTPRequestTemplateRepository(
            session,
            HTTPRequestTemplate,
            HTTPRequestTemplateRecord,
            lambda item: {
                "research_session_id": str(item.research_session_id),
                "web_resource_id": str(item.web_resource_id),
                "semantic_key": item.semantic_key,
                "method": item.method,
            },
        )
        self.web_template_candidates = WebTemplateCandidateRepository(
            session,
            WebTemplateCandidate,
            WebTemplateCandidateRecord,
            lambda item: {
                "research_session_id": str(item.research_session_id),
                "web_resource_id": str(item.web_resource_id),
                "tool_artifact_id": str(item.tool_artifact_id),
                "observation_id": str(item.observation_id),
                "semantic_key": item.semantic_key,
                "classification": item.classification.value,
            },
        )
        self.web_candidate_provenance = WebCandidateProvenanceRepository(
            session,
            WebCandidateProvenance,
            WebCandidateProvenanceRecord,
            lambda item: {
                "research_session_id": str(item.research_session_id),
                "web_template_candidate_id": str(item.web_template_candidate_id),
                "web_resource_id": str(item.web_resource_id),
                "tool_artifact_id": str(item.tool_artifact_id),
                "observation_id": str(item.observation_id),
                "tool_run_id": str(item.tool_run_id),
                "source": item.source,
                "created_at": item.created_at.isoformat(),
            },
        )
        self.web_surface_snapshots = WebSurfaceSnapshotRepository(
            session,
            WebSurfaceSnapshot,
            WebSurfaceSnapshotRecord,
            lambda item: {
                "research_session_id": str(item.research_session_id),
                "web_surface_version": item.web_surface_version,
                "web_surface_sha256": item.web_surface_sha256,
                "created_at": item.created_at.isoformat(),
            },
        )
        self.research_steps = ResearchStepRepository(
            session,
            ResearchStep,
            ResearchStepRecord,
            lambda item: {
                "research_session_id": str(item.research_session_id),
                "step_number": item.step_number,
                "context_hash": item.context_hash,
                "status": item.status.value,
                "started_at": item.started_at.isoformat(),
            },
        )
        self.research_intents = ResearchIntentRepository(
            session,
            ResearchIntent,
            ResearchIntentRecord,
            lambda item: {
                "research_session_id": str(item.research_session_id),
                "research_step_id": str(item.research_step_id),
                "intent_type": item.intent_type.value,
                "semantic_key": item.semantic_key,
                "status": item.status.value,
                "created_at": item.created_at.isoformat(),
            },
        )
        self.knowledge_snapshots = KnowledgeSnapshotRepository(
            session,
            KnowledgeSnapshot,
            KnowledgeSnapshotRecord,
            lambda item: {
                "research_session_id": str(item.research_session_id),
                "system_model_hash": item.system_model_hash,
                "graph_hash": item.graph_hash,
                "sha256": item.sha256,
                "created_at": item.created_at.isoformat(),
            },
        )
        self.evidence_gaps = EvidenceGapRepository(
            session,
            EvidenceGap,
            EvidenceGapRecord,
            lambda item: {
                "research_session_id": str(item.research_session_id),
                "semantic_key": item.semantic_key,
                "gap_type": item.gap_type.value,
                "status": item.status.value,
                "created_at": item.created_at.isoformat(),
            },
        )
        self.research_questions = ResearchQuestionRepository(
            session,
            ResearchQuestion,
            ResearchQuestionRecord,
            lambda item: {
                "research_session_id": str(item.research_session_id),
                "gap_id": str(item.gap_id),
                "semantic_key": item.semantic_key,
                "question_type": item.question_type.value,
                "status": item.status.value,
            },
        )
        self.strategy_runs = StrategyRunRepository(
            session,
            StrategyRun,
            StrategyRunRecord,
            lambda item: {
                "research_session_id": str(item.research_session_id),
                "knowledge_snapshot_id": str(item.knowledge_snapshot_id),
                "mode": item.mode.value,
                "status": item.status.value,
                "started_at": item.started_at.isoformat(),
            },
        )
        self.research_budgets = ResearchBudgetRepository(
            session,
            ResearchBudget,
            ResearchBudgetRecord,
            lambda item: {
                "research_session_id": str(item.research_session_id),
                "controller_status": item.controller_status.value,
                "updated_at": item.updated_at.isoformat(),
            },
        )
        self.controller_steps = ControllerStepRepository(
            session,
            ControllerStep,
            ControllerStepRecord,
            lambda item: {
                "research_session_id": str(item.research_session_id),
                "step_number": item.step_number,
                "context_hash": item.context_hash,
                "status": item.status.value,
                "created_at": item.created_at.isoformat(),
            },
        )
        self.research_actions = ResearchActionRepository(
            session,
            ResearchAction,
            ResearchActionRecord,
            lambda item: {
                "research_session_id": str(item.research_session_id),
                "controller_step_id": str(item.controller_step_id),
                "action_type": item.action_type.value,
                "semantic_hash": item.semantic_hash,
                "status": item.status.value,
                "created_at": item.created_at.isoformat(),
            },
        )
        self.research_action_results = ResearchActionResultRepository(
            session,
            ResearchActionResult,
            ResearchActionResultRecord,
            lambda item: {
                "action_id": str(item.action_id),
                "research_session_id": str(item.research_session_id),
                "status": item.status.value,
                "started_at": item.started_at.isoformat(),
            },
        )
        self.research_sessions = ResearchSessionRepository(
            session,
            ResearchSession,
            ResearchSessionRecord,
            lambda item: {
                "asset_id": str(item.target.asset_id),
                "status": item.status.value,
                "project_id": str(item.project_id) if item.project_id else None,
                "project_scope_revision": item.project_scope_revision,
            },
        )
        self.observations = ObservationRepository(
            session,
            Observation,
            ObservationRecord,
            lambda item: {
                "asset_id": str(item.asset_id),
                "research_session_id": (
                    str(item.research_session_id) if item.research_session_id else None
                ),
                "evidence_id": str(item.evidence_id) if item.evidence_id else None,
                "tool_artifact_id": (str(item.tool_artifact_id) if item.tool_artifact_id else None),
                "request_id": item.request_id,
            },
        )
        self.llm_runs = LLMRunRepository(
            session,
            LLMRun,
            LLMRunRecord,
            lambda item: {
                "research_session_id": str(item.research_session_id),
                "provider": item.provider,
                "model": item.model,
                "prompt_version": item.prompt_version,
                "status": item.status.value,
                "purpose": item.purpose.value,
            },
        )
        self.hypotheses = HypothesisRepository(
            session,
            Hypothesis,
            HypothesisRecord,
            lambda item: {
                "status": item.status.value,
                "research_session_id": (
                    str(item.research_session_id) if item.research_session_id else None
                ),
                "llm_run_id": str(item.llm_run_id) if item.llm_run_id else None,
            },
        )
        self.experiments = ExperimentRepository(
            session,
            Experiment,
            ExperimentRecord,
            lambda item: {
                "hypothesis_id": str(item.hypothesis_id),
                "research_session_id": (
                    str(item.research_session_id) if item.research_session_id else None
                ),
                "llm_run_id": str(item.llm_run_id) if item.llm_run_id else None,
                "status": item.status.value,
            },
        )
        self.experiment_executions = ExperimentExecutionRepository(
            session,
            ExperimentExecution,
            ExperimentExecutionRecord,
            lambda item: {
                "experiment_id": str(item.experiment_id),
                "research_session_id": str(item.research_session_id),
                "status": item.status.value,
                "started_at": item.started_at.isoformat(),
            },
        )
        self.policy_decisions = PolicyDecisionRepository(
            session,
            PolicyDecisionAudit,
            PolicyDecisionRecord,
            lambda item: {
                "decision_id": item.decision_id,
                "research_session_id": str(item.research_session_id),
                "experiment_id": str(item.experiment_id),
                "experiment_execution_id": (
                    str(item.experiment_execution_id) if item.experiment_execution_id else None
                ),
                "action_role": item.action_role.value,
                "allowed": str(item.allowed).lower(),
                "reason_code": item.reason_code.value,
            },
        )
        self.verification_results = VerificationResultRepository(
            session,
            VerificationResult,
            VerificationResultRecord,
            lambda item: {
                "research_session_id": str(item.research_session_id),
                "hypothesis_id": str(item.hypothesis_id),
                "experiment_id": str(item.experiment_id),
                "execution_id": str(item.execution_id),
                "verdict": item.verdict.value,
                "verifier_version": item.verifier_version,
                "rule_id": item.rule_id,
                "rule_version": item.rule_version,
                "created_at": item.created_at.isoformat(),
            },
        )
        self.benchmark_runs = BenchmarkRunRepository(
            session,
            BenchmarkRun,
            BenchmarkRunRecord,
            lambda item: {
                "mode": item.mode.value,
                "status": item.status.value,
                "provider": item.provider,
                "model": item.model,
                "started_at": item.started_at.isoformat(),
            },
        )
        self.scenario_runs = ScenarioRunRepository(
            session,
            ScenarioRun,
            ScenarioRunRecord,
            lambda item: {
                "benchmark_run_id": str(item.benchmark_run_id),
                "scenario_id": item.scenario_id,
                "research_session_id": str(item.research_session_id),
                "status": item.status.value,
            },
        )
        self.scenario_evaluations = ScenarioEvaluationRepository(
            session,
            ScenarioEvaluation,
            ScenarioEvaluationRecord,
            lambda item: {
                "benchmark_run_id": str(item.benchmark_run_id),
                "scenario_run_id": str(item.scenario_run_id),
                "scenario_id": item.scenario_id,
                "research_session_id": str(item.research_session_id),
                "classification": item.classification.value,
            },
        )
        self.evidence = EvidenceRepository(
            session,
            Evidence,
            EvidenceRecord,
            lambda item: {
                "experiment_id": str(item.experiment_id) if item.experiment_id else None,
                "experiment_role": item.experiment_role.value if item.experiment_role else None,
                "research_session_id": (
                    str(item.research_session_id) if item.research_session_id else None
                ),
                "request_id": item.request_id,
                "executor": item.executor,
                "integrity_hash": item.integrity_hash,
            },
        )
        self.findings = FindingRepository(
            session,
            Finding,
            FindingRecord,
            lambda item: {
                "hypothesis_id": str(item.hypothesis_id),
                "verification_status": item.verification_status.value,
                "research_session_id": (
                    str(item.research_session_id) if item.research_session_id else None
                ),
                "experiment_id": str(item.experiment_id) if item.experiment_id else None,
            },
        )
        self.identities = Repository(
            session,
            Identity,
            IdentityRecord,
            lambda item: {"asset_id": str(item.asset_id)},
        )
        self.capabilities = Repository(
            session,
            Capability,
            CapabilityRecord,
            lambda item: {
                "asset_id": str(item.asset_id),
                "identity_id": str(item.identity_id) if item.identity_id else None,
            },
        )

        def common_fields(item: SystemFact) -> dict[str, object]:
            return {
                "research_session_id": str(item.research_session_id),
                "canonical_identifier": item.canonical_identifier,
            }

        self.system_assets = SystemAssetRepository(
            session,
            SystemAsset,
            SystemAssetRecord,
            lambda item: {
                **common_fields(item),
                "asset_type": item.asset_type.value,
                "parent_asset_id": str(item.parent_asset_id) if item.parent_asset_id else None,
            },
        )
        self.system_services = SystemServiceRepository(
            session,
            SystemService,
            SystemServiceRecord,
            lambda item: {**common_fields(item), "asset_id": str(item.asset_id)},
        )
        self.system_endpoints = SystemEndpointRepository(
            session,
            SystemEndpoint,
            SystemEndpointRecord,
            lambda item: {
                **common_fields(item),
                "service_id": str(item.service_id),
                "method": item.method,
                "path": item.path,
            },
        )
        self.system_roles = SystemFactRepository(
            session, SystemRole, SystemRoleRecord, common_fields
        )
        self.system_identities = SystemIdentityRepository(
            session,
            SystemIdentity,
            SystemIdentityRecord,
            lambda item: {
                **common_fields(item),
                "role_id": str(item.role_id) if item.role_id else None,
            },
        )
        self.system_data_objects = SystemFactRepository(
            session,
            SystemDataObject,
            SystemDataObjectRecord,
            lambda item: {**common_fields(item), "data_type": item.data_type.value},
        )
        self.system_permissions = SystemPermissionRepository(
            session,
            SystemPermission,
            SystemPermissionRecord,
            lambda item: {**common_fields(item), "effect": item.effect.value},
        )
        self.system_capabilities = SystemCapabilityRepository(
            session,
            SystemCapability,
            SystemCapabilityRecord,
            lambda item: {
                **common_fields(item),
                "capability_type": item.capability_type.value,
            },
        )
        self.system_trust_boundaries = SystemFactRepository(
            session,
            SystemTrustBoundary,
            SystemTrustBoundaryRecord,
            lambda item: {**common_fields(item), "boundary_type": item.boundary_type.value},
        )
        self.system_relationships = SystemRelationshipRepository(
            session,
            SystemRelationship,
            SystemRelationshipRecord,
            lambda item: {
                **common_fields(item),
                "source_entity_type": item.source_entity_type.value,
                "source_entity_id": str(item.source_entity_id),
                "relationship_type": item.relationship_type.value,
                "target_entity_type": item.target_entity_type.value,
                "target_entity_id": str(item.target_entity_id),
            },
        )
        self.system_model_builds = SystemModelBuildRepository(
            session,
            SystemModelBuild,
            SystemModelBuildRecord,
            lambda item: {
                "research_session_id": str(item.research_session_id),
                "status": item.status.value,
                "started_at": item.started_at.isoformat(),
            },
        )
        self.processed_model_observations = ProcessedModelObservationRepository(
            session,
            ProcessedModelObservation,
            ProcessedModelObservationRecord,
            lambda item: {
                "research_session_id": str(item.research_session_id),
                "observation_id": str(item.observation_id),
                "build_id": str(item.build_id),
            },
        )
        self.attack_graph_snapshots = AttackGraphSnapshotRepository(
            session,
            AttackGraphSnapshot,
            AttackGraphSnapshotRecord,
            lambda item: {
                "research_session_id": str(item.research_session_id),
                "system_model_build_id": (
                    str(item.system_model_build_id) if item.system_model_build_id else None
                ),
                "graph_hash": item.graph_hash,
                "system_model_hash": item.system_model_hash,
                "status": item.status.value,
                "created_at": item.created_at.isoformat(),
            },
        )
        self.candidate_signals = CandidateSignalRepository(
            session,
            CandidateSignal,
            CandidateSignalRecord,
            lambda item: {
                "graph_id": str(item.graph_id),
                "research_session_id": str(item.research_session_id),
                "signal_type": item.signal_type.value,
                "semantic_key": item.semantic_key,
                "subject_entity_id": str(item.subject_entity_id),
                "target_entity_id": str(item.target_entity_id),
            },
        )
        self.discovery_plans = DiscoveryPlanRepository(
            session,
            DiscoveryPlan,
            DiscoveryPlanRecord,
            lambda item: {
                "research_session_id": str(item.research_session_id),
                "profile": item.profile.value,
                "status": item.status.value,
                "created_at": item.created_at.isoformat(),
            },
        )
        self.tool_runs = ToolRunRepository(
            session,
            ToolRun,
            ToolRunRecord,
            lambda item: {
                "research_session_id": str(item.research_session_id),
                "discovery_plan_id": str(item.discovery_plan_id),
                "tool_id": item.tool_id,
                "profile": item.profile,
                "status": item.status.value,
                "started_at": item.started_at.isoformat(),
            },
        )
        self.tool_policy_decisions = ToolPolicyDecisionRepository(
            session,
            ToolPolicyDecision,
            ToolPolicyDecisionRecord,
            lambda item: {
                "research_session_id": str(item.research_session_id),
                "discovery_plan_id": str(item.discovery_plan_id),
                "tool_run_id": str(item.tool_run_id),
                "allowed": str(item.allowed).lower(),
                "reason": item.reason.value,
            },
        )
        self.tool_artifacts = ToolArtifactRepository(
            session,
            ToolArtifact,
            ToolArtifactRecord,
            lambda item: {
                "research_session_id": str(item.research_session_id),
                "tool_run_id": str(item.tool_run_id),
                "tool_id": item.tool_id,
                "artifact_type": item.artifact_type.value,
                "sha256": item.sha256,
                "created_at": item.created_at.isoformat(),
            },
        )
