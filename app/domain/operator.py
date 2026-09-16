import hashlib
import json
from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import Field, field_validator

from app.domain.common import DomainModel, EntityModel, Identifier, JsonObject, utc_now
from app.domain.controller import ResearchActionType
from app.domain.discovery import ToolCapability, ToolRisk
from app.domain.research import TargetScope

OPERATOR_API_VERSION = "operator-api-v1"
RESEARCH_POLICY_VERSION = "research-policy-v1"
RESEARCH_EVENT_VERSION = "research-event-v1"
REPORT_VERSION = "aegis-report-v1"


class ProjectStatus(StrEnum):
    CREATED = "CREATED"
    CONFIGURED = "CONFIGURED"
    READY = "READY"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    INCONCLUSIVE = "INCONCLUSIVE"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ControllerMode(StrEnum):
    SAFE = "SAFE"
    EXPERIMENTAL = "EXPERIMENTAL"


class ResearchPolicyProfile(StrEnum):
    CONSERVATIVE = "CONSERVATIVE"
    BALANCED = "BALANCED"
    EXPERIMENTAL = "EXPERIMENTAL"


class ApprovalMode(StrEnum):
    AUTO = "AUTO"
    APPROVE_HIGHER_COST = "APPROVE_HIGHER_COST"
    APPROVE_EVERY_ACTION = "APPROVE_EVERY_ACTION"


class EvidenceNovelty(StrEnum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class RepeatReason(StrEnum):
    REPRODUCTION = "REPRODUCTION"
    CONFLICT_RESOLUTION = "CONFLICT_RESOLUTION"
    TEMPORAL_RECHECK = "TEMPORAL_RECHECK"
    EXPERIMENTAL_EXPLORATION = "EXPERIMENTAL_EXPLORATION"


class ResearchPolicySettings(DomainModel):
    max_exploratory_actions: int = Field(ge=0, le=100)
    allow_closed_gap_revisit: bool
    allow_action_repetition: bool
    allow_off_gap_exploration: bool
    prefer_reproduction: bool
    stop_on_no_open_gaps: bool
    min_information_gain: int = Field(ge=0, le=100)
    max_repeated_semantic_action_count: int = Field(ge=1, le=20)


class ResearchPolicy(EntityModel):
    policy_version: Literal["research-policy-v1"] = RESEARCH_POLICY_VERSION
    profile: ResearchPolicyProfile
    settings: ResearchPolicySettings
    created_at: datetime = Field(default_factory=utc_now)


class ResearchBudgetTemplate(DomainModel):
    max_steps: int = Field(default=5, ge=1, le=100)
    max_actions: int = Field(default=10, ge=1, le=1000)
    max_tool_runs: int = Field(default=10, ge=0, le=1000)
    max_requests: int = Field(default=10, ge=0, le=10_000)
    max_duration_seconds: float = Field(default=300, ge=1, le=86_400)
    max_llm_calls: int = Field(default=5, ge=0, le=1000)
    allowed_capabilities: tuple[ToolCapability, ...] = ()


class ResearchProject(EntityModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    status: ProjectStatus = ProjectStatus.CREATED
    scope: TargetScope | None = None
    scope_revision: int = Field(default=0, ge=0)
    identity_names: tuple[str, ...] = ()
    default_provider: str = Field(default="fake", min_length=1, max_length=100)
    default_model: str = Field(min_length=1, max_length=300)
    model_configuration: JsonObject = Field(default_factory=dict)
    controller_mode: ControllerMode = ControllerMode.SAFE
    research_policy_id: Identifier
    approval_mode: ApprovalMode = ApprovalMode.AUTO
    blocked_action_types: tuple[ResearchActionType, ...] = ()
    budget: ResearchBudgetTemplate = Field(default_factory=ResearchBudgetTemplate)
    created_by: JsonObject = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    @field_validator("identity_names")
    @classmethod
    def valid_identity_names(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        allowed = {"anonymous", "alice", "bob", "admin"}
        normalized = tuple(dict.fromkeys(item.strip().lower() for item in values))
        if any(item not in allowed for item in normalized):
            raise ValueError("project identities must use configured logical identities")
        return normalized


class ApprovalStatus(StrEnum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class ActionApproval(EntityModel):
    project_id: Identifier
    research_session_id: Identifier
    action_id: Identifier
    policy_preview_allowed: bool
    policy_preview_reason: str = Field(min_length=1, max_length=1000)
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: datetime = Field(default_factory=utc_now)
    resolved_at: datetime | None = None
    reason: str | None = Field(default=None, max_length=1000)


class OperatorAction(StrEnum):
    PAUSE = "PAUSE"
    RESUME = "RESUME"
    STOP = "STOP"
    SKIP_ACTION = "SKIP_ACTION"
    BLOCK_ACTION_TYPE = "BLOCK_ACTION_TYPE"


class ResearchEventType(StrEnum):
    PROJECT_CREATED = "PROJECT_CREATED"
    PROJECT_CONFIGURED = "PROJECT_CONFIGURED"
    SESSION_STARTED = "SESSION_STARTED"
    OBSERVATION_CREATED = "OBSERVATION_CREATED"
    GAP_DETECTED = "GAP_DETECTED"
    ACTION_PROPOSED = "ACTION_PROPOSED"
    ACTION_VALIDATED = "ACTION_VALIDATED"
    ACTION_REJECTED = "ACTION_REJECTED"
    ACTION_APPROVED = "ACTION_APPROVED"
    TOOL_STARTED = "TOOL_STARTED"
    TOOL_COMPLETED = "TOOL_COMPLETED"
    EVIDENCE_CREATED = "EVIDENCE_CREATED"
    MODEL_REBUILT = "MODEL_REBUILT"
    GRAPH_REBUILT = "GRAPH_REBUILT"
    GAP_RESOLVED = "GAP_RESOLVED"
    HYPOTHESIS_CREATED = "HYPOTHESIS_CREATED"
    EXPERIMENT_EXECUTED = "EXPERIMENT_EXECUTED"
    VERIFICATION_COMPLETED = "VERIFICATION_COMPLETED"
    FINDING_CREATED = "FINDING_CREATED"
    CONTROLLER_PAUSED = "CONTROLLER_PAUSED"
    CONTROLLER_RESUMED = "CONTROLLER_RESUMED"
    CONTROLLER_STOPPED = "CONTROLLER_STOPPED"
    LLM_PROVIDER_ERROR = "LLM_PROVIDER_ERROR"
    REPORT_GENERATED = "REPORT_GENERATED"


class EventSeverity(StrEnum):
    INFO = "INFO"
    NOTICE = "NOTICE"
    WARNING = "WARNING"
    ERROR = "ERROR"


class ResearchEvent(EntityModel):
    event_version: Literal["research-event-v1"] = RESEARCH_EVENT_VERSION
    project_id: Identifier
    research_session_id: Identifier | None = None
    sequence_number: int = Field(ge=1)
    event_type: ResearchEventType
    entity_type: str = Field(min_length=1, max_length=100)
    entity_id: str = Field(min_length=1, max_length=200)
    severity: EventSeverity = EventSeverity.INFO
    message: str = Field(min_length=1, max_length=2000)
    structured_data: JsonObject = Field(default_factory=dict)
    idempotency_key: str = Field(min_length=1, max_length=500)
    created_at: datetime = Field(default_factory=utc_now)


class ReportStatus(StrEnum):
    CREATED = "CREATED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ReportMetadata(EntityModel):
    project_id: Identifier
    research_session_id: Identifier
    report_version: Literal["aegis-report-v1"] = REPORT_VERSION
    generated_at: datetime = Field(default_factory=utc_now)
    manifest_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    path: str = Field(min_length=1, max_length=4096)
    status: ReportStatus = ReportStatus.CREATED


class FileManifestEntry(DomainModel):
    path: str
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    size_bytes: int = Field(ge=0)


class ReportManifest(DomainModel):
    report_version: Literal["aegis-report-v1"] = REPORT_VERSION
    project_id: Identifier
    session_id: Identifier
    generated_at: datetime
    aegis_version: str
    scope_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    model_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    graph_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    knowledge_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    web_surface_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    finding_ids: tuple[Identifier, ...]
    files: tuple[FileManifestEntry, ...]

    @property
    def sha256(self) -> str:
        payload = self.model_dump(mode="json", exclude={"generated_at"})
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()


class SessionMetrics(DomainModel):
    controller_steps: int = 0
    actions_proposed: int = 0
    actions_executed: int = 0
    actions_rejected: int = 0
    experimental_actions: int = 0
    tool_runs: int = 0
    http_requests: int = 0
    evidence_records: int = 0
    gaps_detected: int = 0
    gaps_resolved: int = 0
    repeated_actions: int = 0
    redundant_actions_prevented: int = 0
    findings: int = 0
    inconclusive_hypotheses: int = 0
    policy_rejections: int = 0
    autonomous_actions: int = 0
    operator_approved_actions: int = 0
    operator_rejected_actions: int = 0
    actions_per_finding: float | None = None
    requests_per_finding: float | None = None
    gaps_resolved_per_action: float | None = None


class SessionOverview(DomainModel):
    api_version: Literal["operator-api-v1"] = OPERATOR_API_VERSION
    project_id: Identifier
    session_id: Identifier
    session_status: str
    scope: JsonObject
    controller_mode: ControllerMode
    research_policy: ResearchPolicyProfile
    approval_mode: ApprovalMode
    experimental_mode: bool
    budget: JsonObject
    counts: JsonObject
    open_gaps: int
    resolved_gaps: int
    last_action_id: Identifier | None = None
    stop_reason: str | None = None
    metrics: SessionMetrics


class FindingReport(DomainModel):
    finding_id: Identifier
    title: str | None = None
    claim: str
    verification_status: str
    verification_confidence: str
    affected_asset_ids: tuple[Identifier, ...] = ()
    affected_endpoint_ids: tuple[Identifier, ...] = ()
    affected_resource_ids: tuple[Identifier, ...] = ()
    involved_identity_ids: tuple[Identifier, ...] = ()
    hypothesis_id: Identifier
    experiment_id: Identifier | None = None
    verification_result_ids: tuple[Identifier, ...] = ()
    verification_rule: str | None = None
    evidence_ids: tuple[Identifier, ...]
    observation_ids: tuple[Identifier, ...]
    reproduction_summary: tuple[str, ...]
    impact: str | None = None
    limitations: tuple[str, ...] = ()
    observed_facts: tuple[JsonObject, ...] = ()
    deterministic_verification: JsonObject
    inferred_interpretation: JsonObject
    llm_generated_explanation: str | None = None
    created_at: datetime
    updated_at: datetime | None = None


def canonical_hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def novelty_weight(novelty: EvidenceNovelty) -> int:
    return {
        EvidenceNovelty.NONE: 0,
        EvidenceNovelty.LOW: 10,
        EvidenceNovelty.MEDIUM: 30,
        EvidenceNovelty.HIGH: 50,
    }[novelty]


def risk_cost(risk: ToolRisk) -> int:
    return {ToolRisk.PASSIVE: 5, ToolRisk.LOW: 15}[risk]
