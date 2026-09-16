from typing import Any

from sqlalchemy import ForeignKey, JSON, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.storage.database import Base


class PayloadMixin:
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class AssetRecord(PayloadMixin, Base):
    __tablename__ = "assets"


class ResearchSessionRecord(PayloadMixin, Base):
    __tablename__ = "research_sessions"

    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    status: Mapped[str] = mapped_column(String(20), index=True)
    project_id: Mapped[str | None] = mapped_column(
        ForeignKey("research_projects.id"), nullable=True, index=True
    )
    project_scope_revision: Mapped[int | None] = mapped_column(nullable=True)


class ObservationRecord(PayloadMixin, Base):
    __tablename__ = "observations"

    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    research_session_id: Mapped[str | None] = mapped_column(
        ForeignKey("research_sessions.id"), nullable=True, index=True
    )
    evidence_id: Mapped[str | None] = mapped_column(
        ForeignKey("evidence.id"), nullable=True, index=True
    )
    tool_artifact_id: Mapped[str | None] = mapped_column(
        ForeignKey("tool_artifacts.id"), nullable=True, index=True
    )
    request_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)


class LLMRunRecord(PayloadMixin, Base):
    __tablename__ = "llm_runs"

    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    provider: Mapped[str] = mapped_column(String(100), index=True)
    model: Mapped[str] = mapped_column(String(200), index=True)
    prompt_version: Mapped[str] = mapped_column(String(100), index=True)
    status: Mapped[str] = mapped_column(String(20), index=True)
    purpose: Mapped[str] = mapped_column(String(40), index=True, default="HYPOTHESIS_GENERATION")


class HypothesisRecord(PayloadMixin, Base):
    __tablename__ = "hypotheses"

    status: Mapped[str] = mapped_column(String(20), index=True)
    research_session_id: Mapped[str | None] = mapped_column(
        ForeignKey("research_sessions.id"), nullable=True, index=True
    )
    llm_run_id: Mapped[str | None] = mapped_column(
        ForeignKey("llm_runs.id"), nullable=True, index=True
    )


class ExperimentRecord(PayloadMixin, Base):
    __tablename__ = "experiments"

    hypothesis_id: Mapped[str] = mapped_column(ForeignKey("hypotheses.id"), index=True)
    research_session_id: Mapped[str | None] = mapped_column(
        ForeignKey("research_sessions.id"), nullable=True, index=True
    )
    llm_run_id: Mapped[str | None] = mapped_column(
        ForeignKey("llm_runs.id"), nullable=True, index=True
    )
    status: Mapped[str] = mapped_column(String(30), index=True, default="DRAFT")


class ExperimentExecutionRecord(PayloadMixin, Base):
    __tablename__ = "experiment_executions"

    experiment_id: Mapped[str] = mapped_column(ForeignKey("experiments.id"), index=True)
    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    status: Mapped[str] = mapped_column(String(30), index=True)
    started_at: Mapped[str] = mapped_column(String(64), index=True)


class PolicyDecisionRecord(PayloadMixin, Base):
    __tablename__ = "policy_decisions"
    __table_args__ = (UniqueConstraint("decision_id"),)

    decision_id: Mapped[str] = mapped_column(String(128), index=True)
    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    experiment_id: Mapped[str] = mapped_column(ForeignKey("experiments.id"), index=True)
    experiment_execution_id: Mapped[str | None] = mapped_column(
        ForeignKey("experiment_executions.id"), nullable=True, index=True
    )
    action_role: Mapped[str] = mapped_column(String(20), index=True)
    allowed: Mapped[str] = mapped_column(String(5), index=True)
    reason_code: Mapped[str] = mapped_column(String(50), index=True)


class EvidenceRecord(PayloadMixin, Base):
    __tablename__ = "evidence"
    __table_args__ = (
        UniqueConstraint("research_session_id", "request_id", name="uq_evidence_session_request"),
    )

    experiment_id: Mapped[str | None] = mapped_column(
        ForeignKey("experiments.id"), nullable=True, index=True
    )
    experiment_role: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)
    research_session_id: Mapped[str | None] = mapped_column(
        ForeignKey("research_sessions.id"), nullable=True, index=True
    )
    request_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    executor: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    integrity_hash: Mapped[str] = mapped_column(String(64), index=True)


class FindingRecord(PayloadMixin, Base):
    __tablename__ = "findings"

    hypothesis_id: Mapped[str] = mapped_column(ForeignKey("hypotheses.id"), index=True)
    verification_status: Mapped[str] = mapped_column(String(20), index=True)
    research_session_id: Mapped[str | None] = mapped_column(
        ForeignKey("research_sessions.id"), nullable=True, index=True
    )
    experiment_id: Mapped[str | None] = mapped_column(
        ForeignKey("experiments.id"), nullable=True, index=True
    )


class VerificationResultRecord(PayloadMixin, Base):
    __tablename__ = "verification_results"

    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    hypothesis_id: Mapped[str] = mapped_column(ForeignKey("hypotheses.id"), index=True)
    experiment_id: Mapped[str] = mapped_column(ForeignKey("experiments.id"), index=True)
    execution_id: Mapped[str] = mapped_column(ForeignKey("experiment_executions.id"), index=True)
    verdict: Mapped[str] = mapped_column(String(20), index=True)
    verifier_version: Mapped[str] = mapped_column(String(50), index=True)
    rule_id: Mapped[str] = mapped_column(String(100), index=True)
    rule_version: Mapped[str] = mapped_column(String(50), index=True)
    created_at: Mapped[str] = mapped_column(String(64), index=True)


class BenchmarkRunRecord(PayloadMixin, Base):
    __tablename__ = "benchmark_runs"

    mode: Mapped[str] = mapped_column(String(30), index=True)
    status: Mapped[str] = mapped_column(String(30), index=True)
    provider: Mapped[str] = mapped_column(String(100), index=True)
    model: Mapped[str] = mapped_column(String(200), index=True)
    started_at: Mapped[str] = mapped_column(String(64), index=True)


class ScenarioRunRecord(PayloadMixin, Base):
    __tablename__ = "scenario_runs"
    __table_args__ = (UniqueConstraint("benchmark_run_id", "scenario_id"),)

    benchmark_run_id: Mapped[str] = mapped_column(ForeignKey("benchmark_runs.id"), index=True)
    scenario_id: Mapped[str] = mapped_column(String(20), index=True)
    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    status: Mapped[str] = mapped_column(String(30), index=True)


class ScenarioEvaluationRecord(PayloadMixin, Base):
    __tablename__ = "scenario_evaluations"
    __table_args__ = (UniqueConstraint("benchmark_run_id", "scenario_id"),)

    benchmark_run_id: Mapped[str] = mapped_column(ForeignKey("benchmark_runs.id"), index=True)
    scenario_run_id: Mapped[str] = mapped_column(ForeignKey("scenario_runs.id"), index=True)
    scenario_id: Mapped[str] = mapped_column(String(20), index=True)
    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    classification: Mapped[str] = mapped_column(String(40), index=True)


class IdentityRecord(PayloadMixin, Base):
    __tablename__ = "identities"

    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)


class CapabilityRecord(PayloadMixin, Base):
    __tablename__ = "capabilities"

    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    identity_id: Mapped[str | None] = mapped_column(
        ForeignKey("identities.id"), nullable=True, index=True
    )


class SystemAssetRecord(PayloadMixin, Base):
    __tablename__ = "system_assets"
    __table_args__ = (UniqueConstraint("research_session_id", "canonical_identifier"),)

    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    canonical_identifier: Mapped[str] = mapped_column(String(2048), index=True)
    asset_type: Mapped[str] = mapped_column(String(30), index=True)
    parent_asset_id: Mapped[str | None] = mapped_column(
        ForeignKey("system_assets.id"), nullable=True, index=True
    )


class SystemServiceRecord(PayloadMixin, Base):
    __tablename__ = "system_services"
    __table_args__ = (UniqueConstraint("research_session_id", "canonical_identifier"),)

    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    canonical_identifier: Mapped[str] = mapped_column(String(2048), index=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("system_assets.id"), index=True)


class SystemEndpointRecord(PayloadMixin, Base):
    __tablename__ = "system_endpoints"
    __table_args__ = (UniqueConstraint("research_session_id", "canonical_identifier"),)

    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    canonical_identifier: Mapped[str] = mapped_column(String(2048), index=True)
    service_id: Mapped[str] = mapped_column(ForeignKey("system_services.id"), index=True)
    method: Mapped[str] = mapped_column(String(20), index=True)
    path: Mapped[str] = mapped_column(String(2048), index=True)


class SystemRoleRecord(PayloadMixin, Base):
    __tablename__ = "system_roles"
    __table_args__ = (UniqueConstraint("research_session_id", "canonical_identifier"),)

    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    canonical_identifier: Mapped[str] = mapped_column(String(2048), index=True)


class SystemIdentityRecord(PayloadMixin, Base):
    __tablename__ = "system_identities"
    __table_args__ = (UniqueConstraint("research_session_id", "canonical_identifier"),)

    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    canonical_identifier: Mapped[str] = mapped_column(String(2048), index=True)
    role_id: Mapped[str | None] = mapped_column(
        ForeignKey("system_roles.id"), nullable=True, index=True
    )


class SystemDataObjectRecord(PayloadMixin, Base):
    __tablename__ = "system_data_objects"
    __table_args__ = (UniqueConstraint("research_session_id", "canonical_identifier"),)

    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    canonical_identifier: Mapped[str] = mapped_column(String(2048), index=True)
    data_type: Mapped[str] = mapped_column(String(40), index=True)


class SystemPermissionRecord(PayloadMixin, Base):
    __tablename__ = "system_permissions"
    __table_args__ = (UniqueConstraint("research_session_id", "canonical_identifier"),)

    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    canonical_identifier: Mapped[str] = mapped_column(String(2048), index=True)
    effect: Mapped[str] = mapped_column(String(20), index=True)


class SystemCapabilityRecord(PayloadMixin, Base):
    __tablename__ = "system_capabilities"
    __table_args__ = (UniqueConstraint("research_session_id", "canonical_identifier"),)

    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    canonical_identifier: Mapped[str] = mapped_column(String(2048), index=True)
    capability_type: Mapped[str] = mapped_column(String(50), index=True)


class SystemTrustBoundaryRecord(PayloadMixin, Base):
    __tablename__ = "system_trust_boundaries"
    __table_args__ = (UniqueConstraint("research_session_id", "canonical_identifier"),)

    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    canonical_identifier: Mapped[str] = mapped_column(String(2048), index=True)
    boundary_type: Mapped[str] = mapped_column(String(50), index=True)


class SystemRelationshipRecord(PayloadMixin, Base):
    __tablename__ = "system_relationships"
    __table_args__ = (
        UniqueConstraint(
            "research_session_id",
            "source_entity_type",
            "source_entity_id",
            "relationship_type",
            "target_entity_type",
            "target_entity_id",
            name="uq_system_relationship_semantic_key",
        ),
    )

    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    canonical_identifier: Mapped[str] = mapped_column(String(2048), index=True)
    source_entity_type: Mapped[str] = mapped_column(String(40), index=True)
    source_entity_id: Mapped[str] = mapped_column(String(36), index=True)
    relationship_type: Mapped[str] = mapped_column(String(50), index=True)
    target_entity_type: Mapped[str] = mapped_column(String(40), index=True)
    target_entity_id: Mapped[str] = mapped_column(String(36), index=True)


class SystemModelBuildRecord(PayloadMixin, Base):
    __tablename__ = "system_model_builds"

    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    status: Mapped[str] = mapped_column(String(30), index=True)
    started_at: Mapped[str] = mapped_column(String(64), index=True)


class ProcessedModelObservationRecord(PayloadMixin, Base):
    __tablename__ = "system_model_observations"
    __table_args__ = (UniqueConstraint("research_session_id", "observation_id"),)

    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    observation_id: Mapped[str] = mapped_column(ForeignKey("observations.id"), index=True)
    build_id: Mapped[str] = mapped_column(ForeignKey("system_model_builds.id"), index=True)


class AttackGraphSnapshotRecord(PayloadMixin, Base):
    __tablename__ = "attack_graph_snapshots"

    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    system_model_build_id: Mapped[str | None] = mapped_column(
        ForeignKey("system_model_builds.id"), nullable=True, index=True
    )
    graph_hash: Mapped[str] = mapped_column(String(64), index=True)
    system_model_hash: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(20), index=True)
    created_at: Mapped[str] = mapped_column(String(64), index=True)


class CandidateSignalRecord(PayloadMixin, Base):
    __tablename__ = "candidate_signals"
    __table_args__ = (UniqueConstraint("graph_id", "semantic_key"),)

    graph_id: Mapped[str] = mapped_column(ForeignKey("attack_graph_snapshots.id"), index=True)
    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    signal_type: Mapped[str] = mapped_column(String(60), index=True)
    semantic_key: Mapped[str] = mapped_column(String(2048), index=True)
    subject_entity_id: Mapped[str] = mapped_column(String(36), index=True)
    target_entity_id: Mapped[str] = mapped_column(String(36), index=True)


class DiscoveryPlanRecord(PayloadMixin, Base):
    __tablename__ = "discovery_plans"

    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    profile: Mapped[str] = mapped_column(String(30), index=True)
    status: Mapped[str] = mapped_column(String(30), index=True)
    created_at: Mapped[str] = mapped_column(String(64), index=True)


class ToolRunRecord(PayloadMixin, Base):
    __tablename__ = "tool_runs"

    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    discovery_plan_id: Mapped[str] = mapped_column(ForeignKey("discovery_plans.id"), index=True)
    tool_id: Mapped[str] = mapped_column(String(50), index=True)
    profile: Mapped[str] = mapped_column(String(100), index=True)
    status: Mapped[str] = mapped_column(String(30), index=True)
    started_at: Mapped[str] = mapped_column(String(64), index=True)


class ToolPolicyDecisionRecord(PayloadMixin, Base):
    __tablename__ = "tool_policy_decisions"

    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    discovery_plan_id: Mapped[str] = mapped_column(ForeignKey("discovery_plans.id"), index=True)
    tool_run_id: Mapped[str] = mapped_column(ForeignKey("tool_runs.id"), index=True)
    allowed: Mapped[str] = mapped_column(String(5), index=True)
    reason: Mapped[str] = mapped_column(String(50), index=True)


class ToolArtifactRecord(PayloadMixin, Base):
    __tablename__ = "tool_artifacts"

    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    tool_run_id: Mapped[str] = mapped_column(ForeignKey("tool_runs.id"), index=True)
    tool_id: Mapped[str] = mapped_column(String(50), index=True)
    artifact_type: Mapped[str] = mapped_column(String(50), index=True)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[str] = mapped_column(String(64), index=True)


class ResearchStepRecord(PayloadMixin, Base):
    __tablename__ = "research_steps"
    __table_args__ = (UniqueConstraint("research_session_id", "step_number"),)

    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    step_number: Mapped[int] = mapped_column(index=True)
    context_hash: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(30), index=True)
    started_at: Mapped[str] = mapped_column(String(64), index=True)


class ResearchIntentRecord(PayloadMixin, Base):
    __tablename__ = "research_intents"

    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    research_step_id: Mapped[str] = mapped_column(ForeignKey("research_steps.id"), index=True)
    intent_type: Mapped[str] = mapped_column(String(60), index=True)
    semantic_key: Mapped[str] = mapped_column(String(2048), index=True)
    status: Mapped[str] = mapped_column(String(30), index=True)
    created_at: Mapped[str] = mapped_column(String(64), index=True)


class KnowledgeSnapshotRecord(PayloadMixin, Base):
    __tablename__ = "knowledge_snapshots"

    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    system_model_hash: Mapped[str] = mapped_column(String(64), index=True)
    graph_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[str] = mapped_column(String(64), index=True)


class EvidenceGapRecord(PayloadMixin, Base):
    __tablename__ = "evidence_gaps"
    __table_args__ = (UniqueConstraint("research_session_id", "semantic_key"),)

    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    semantic_key: Mapped[str] = mapped_column(String(2048), index=True)
    gap_type: Mapped[str] = mapped_column(String(80), index=True)
    status: Mapped[str] = mapped_column(String(30), index=True)
    created_at: Mapped[str] = mapped_column(String(64), index=True)


class ResearchQuestionRecord(PayloadMixin, Base):
    __tablename__ = "research_questions"
    __table_args__ = (UniqueConstraint("research_session_id", "semantic_key"),)

    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    gap_id: Mapped[str] = mapped_column(ForeignKey("evidence_gaps.id"), index=True)
    semantic_key: Mapped[str] = mapped_column(String(2048), index=True)
    question_type: Mapped[str] = mapped_column(String(80), index=True)
    status: Mapped[str] = mapped_column(String(30), index=True)


class StrategyRunRecord(PayloadMixin, Base):
    __tablename__ = "strategy_runs"

    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    knowledge_snapshot_id: Mapped[str] = mapped_column(
        ForeignKey("knowledge_snapshots.id"), index=True
    )
    mode: Mapped[str] = mapped_column(String(30), index=True)
    status: Mapped[str] = mapped_column(String(30), index=True)
    started_at: Mapped[str] = mapped_column(String(64), index=True)


class ResearchBudgetRecord(PayloadMixin, Base):
    __tablename__ = "research_budgets"
    __table_args__ = (UniqueConstraint("research_session_id"),)

    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    controller_status: Mapped[str] = mapped_column(String(30), index=True)
    updated_at: Mapped[str] = mapped_column(String(64), index=True)


class ControllerStepRecord(PayloadMixin, Base):
    __tablename__ = "controller_steps"
    __table_args__ = (UniqueConstraint("research_session_id", "step_number"),)

    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    step_number: Mapped[int] = mapped_column(index=True)
    context_hash: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(30), index=True)
    created_at: Mapped[str] = mapped_column(String(64), index=True)


class ResearchActionRecord(PayloadMixin, Base):
    __tablename__ = "research_actions"

    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    controller_step_id: Mapped[str] = mapped_column(ForeignKey("controller_steps.id"), index=True)
    action_type: Mapped[str] = mapped_column(String(50), index=True)
    semantic_hash: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(30), index=True)
    created_at: Mapped[str] = mapped_column(String(64), index=True)


class ResearchActionResultRecord(PayloadMixin, Base):
    __tablename__ = "research_action_results"
    __table_args__ = (UniqueConstraint("action_id"),)

    action_id: Mapped[str] = mapped_column(ForeignKey("research_actions.id"), index=True)
    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    status: Mapped[str] = mapped_column(String(30), index=True)
    started_at: Mapped[str] = mapped_column(String(64), index=True)


class ResearchPolicyRecord(PayloadMixin, Base):
    __tablename__ = "research_policies"

    profile: Mapped[str] = mapped_column(String(30), index=True)
    created_at: Mapped[str] = mapped_column(String(64), index=True)


class ResearchProjectRecord(PayloadMixin, Base):
    __tablename__ = "research_projects"

    status: Mapped[str] = mapped_column(String(30), index=True)
    research_policy_id: Mapped[str] = mapped_column(ForeignKey("research_policies.id"), index=True)
    updated_at: Mapped[str] = mapped_column(String(64), index=True)


class ActionApprovalRecord(PayloadMixin, Base):
    __tablename__ = "action_approvals"
    __table_args__ = (UniqueConstraint("action_id"),)

    project_id: Mapped[str] = mapped_column(ForeignKey("research_projects.id"), index=True)
    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    action_id: Mapped[str] = mapped_column(ForeignKey("research_actions.id"), index=True)
    status: Mapped[str] = mapped_column(String(30), index=True)
    created_at: Mapped[str] = mapped_column(String(64), index=True)


class ClientVerificationRunRecord(PayloadMixin, Base):
    __tablename__ = "client_verification_runs"

    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    research_action_id: Mapped[str] = mapped_column(ForeignKey("research_actions.id"), index=True)
    action_approval_id: Mapped[str] = mapped_column(ForeignKey("action_approvals.id"), index=True)
    web_resource_id: Mapped[str] = mapped_column(ForeignKey("web_resources.id"), index=True)
    hypothesis_id: Mapped[str] = mapped_column(ForeignKey("hypotheses.id"), index=True)
    status: Mapped[str] = mapped_column(String(30), index=True)
    created_at: Mapped[str] = mapped_column(String(64), index=True)


class VerificationRecommendationRecord(PayloadMixin, Base):
    __tablename__ = "verification_recommendations"
    __table_args__ = (UniqueConstraint("run_id"),)

    run_id: Mapped[str] = mapped_column(ForeignKey("client_verification_runs.id"), index=True)
    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    verdict: Mapped[str] = mapped_column(String(40), index=True)
    recommended_action: Mapped[str] = mapped_column(String(40), index=True)
    created_at: Mapped[str] = mapped_column(String(64), index=True)


class GeneratedPayloadRecord(PayloadMixin, Base):
    __tablename__ = "generated_payloads"
    __table_args__ = (UniqueConstraint("verification_run_id"),)
    verification_run_id: Mapped[str] = mapped_column(ForeignKey("client_verification_runs.id"), index=True)
    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    vulnerability_class: Mapped[str] = mapped_column(String(40), index=True)
    injection_context: Mapped[str] = mapped_column(String(40), index=True)
    created_at: Mapped[str] = mapped_column(String(64), index=True)


class ResearchEventRecord(PayloadMixin, Base):
    __tablename__ = "research_events"
    __table_args__ = (UniqueConstraint("idempotency_key"),)

    project_id: Mapped[str] = mapped_column(ForeignKey("research_projects.id"), index=True)
    research_session_id: Mapped[str | None] = mapped_column(
        ForeignKey("research_sessions.id"), nullable=True, index=True
    )
    sequence_number: Mapped[int] = mapped_column(index=True)
    event_type: Mapped[str] = mapped_column(String(60), index=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    idempotency_key: Mapped[str] = mapped_column(String(500), index=True)
    created_at: Mapped[str] = mapped_column(String(64), index=True)


class ReportMetadataRecord(PayloadMixin, Base):
    __tablename__ = "report_metadata"

    project_id: Mapped[str] = mapped_column(ForeignKey("research_projects.id"), index=True)
    research_session_id: Mapped[str] = mapped_column(ForeignKey("research_sessions.id"), index=True)
    status: Mapped[str] = mapped_column(String(30), index=True)
    generated_at: Mapped[str] = mapped_column(String(64), index=True)


class WebResourceRecord(PayloadMixin, Base):
    __tablename__ = "web_resources"
    __table_args__ = (UniqueConstraint("research_session_id", "canonical_key"),)

    research_session_id: Mapped[str] = mapped_column(
        ForeignKey("research_sessions.id"), index=True
    )
    canonical_key: Mapped[str] = mapped_column(String(4096), index=True)
    method: Mapped[str] = mapped_column(String(20), index=True)
    path: Mapped[str] = mapped_column(String(2048), index=True)
    resource_type: Mapped[str] = mapped_column(String(30), index=True)
    system_endpoint_id: Mapped[str | None] = mapped_column(
        ForeignKey("system_endpoints.id"), nullable=True, index=True
    )


class WebResourceProvenanceRecord(PayloadMixin, Base):
    __tablename__ = "web_resource_provenance"
    __table_args__ = (
        UniqueConstraint("web_resource_id", "observation_id", "source"),
    )

    research_session_id: Mapped[str] = mapped_column(
        ForeignKey("research_sessions.id"), index=True
    )
    web_resource_id: Mapped[str] = mapped_column(
        ForeignKey("web_resources.id"), index=True
    )
    observation_id: Mapped[str] = mapped_column(ForeignKey("observations.id"), index=True)
    tool_artifact_id: Mapped[str | None] = mapped_column(
        ForeignKey("tool_artifacts.id"), nullable=True, index=True
    )
    evidence_id: Mapped[str | None] = mapped_column(
        ForeignKey("evidence.id"), nullable=True, index=True
    )
    source: Mapped[str] = mapped_column(String(40), index=True)
    observed_at: Mapped[str] = mapped_column(String(64), index=True)


class WebParameterRecord(PayloadMixin, Base):
    __tablename__ = "web_parameters"
    __table_args__ = (
        UniqueConstraint("web_resource_id", "name", "location"),
    )

    research_session_id: Mapped[str] = mapped_column(
        ForeignKey("research_sessions.id"), index=True
    )
    web_resource_id: Mapped[str] = mapped_column(
        ForeignKey("web_resources.id"), index=True
    )
    name: Mapped[str] = mapped_column(String(300), index=True)
    location: Mapped[str] = mapped_column(String(30), index=True)


class HTTPRequestTemplateRecord(PayloadMixin, Base):
    __tablename__ = "http_request_templates"
    __table_args__ = (UniqueConstraint("research_session_id", "semantic_key"),)

    research_session_id: Mapped[str] = mapped_column(
        ForeignKey("research_sessions.id"), index=True
    )
    web_resource_id: Mapped[str] = mapped_column(
        ForeignKey("web_resources.id"), index=True
    )
    semantic_key: Mapped[str] = mapped_column(String(64), index=True)
    method: Mapped[str] = mapped_column(String(20), index=True)


class WebTemplateCandidateRecord(PayloadMixin, Base):
    __tablename__ = "web_template_candidates"
    __table_args__ = (UniqueConstraint("research_session_id", "semantic_key"),)

    research_session_id: Mapped[str] = mapped_column(
        ForeignKey("research_sessions.id"), index=True
    )
    web_resource_id: Mapped[str] = mapped_column(
        ForeignKey("web_resources.id"), index=True
    )
    tool_artifact_id: Mapped[str] = mapped_column(
        ForeignKey("tool_artifacts.id"), index=True
    )
    observation_id: Mapped[str] = mapped_column(ForeignKey("observations.id"), index=True)
    semantic_key: Mapped[str] = mapped_column(String(64), index=True)
    classification: Mapped[str] = mapped_column(String(30), index=True)


class WebCandidateProvenanceRecord(PayloadMixin, Base):
    __tablename__ = "web_candidate_provenance"
    __table_args__ = (
        UniqueConstraint("web_template_candidate_id", "observation_id", "source"),
    )

    research_session_id: Mapped[str] = mapped_column(
        ForeignKey("research_sessions.id"), index=True
    )
    web_template_candidate_id: Mapped[str] = mapped_column(
        ForeignKey("web_template_candidates.id"), index=True
    )
    web_resource_id: Mapped[str] = mapped_column(
        ForeignKey("web_resources.id"), index=True
    )
    tool_artifact_id: Mapped[str] = mapped_column(
        ForeignKey("tool_artifacts.id"), index=True
    )
    observation_id: Mapped[str] = mapped_column(ForeignKey("observations.id"), index=True)
    tool_run_id: Mapped[str] = mapped_column(ForeignKey("tool_runs.id"), index=True)
    source: Mapped[str] = mapped_column(String(40), index=True)
    created_at: Mapped[str] = mapped_column(String(64), index=True)


class WebSurfaceSnapshotRecord(PayloadMixin, Base):
    __tablename__ = "web_surface_snapshots"

    research_session_id: Mapped[str] = mapped_column(
        ForeignKey("research_sessions.id"), index=True
    )
    web_surface_version: Mapped[str] = mapped_column(String(50), index=True)
    web_surface_sha256: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[str] = mapped_column(String(64), index=True)
