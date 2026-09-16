import hashlib
import json
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field, model_validator

from app.domain.common import DomainModel, EntityModel, Identifier, utc_now
from app.domain.discovery import ToolCapability
from app.domain.research_planner import IntentPriority

CONTROLLER_VERSION = "closed-loop-controller-v1"
CONTROLLER_DECISION_VERSION = "controller-decision-v1"
RESEARCH_ACTION_VERSION = "research-action-v1"
CONTROLLER_PROMPT_VERSION = "closed-loop-controller-prompt-v1"


class ResearchActionType(StrEnum):
    HTTP_OBSERVE = "HTTP_OBSERVE"
    SERVICE_DISCOVERY = "SERVICE_DISCOVERY"
    DNS_RESOLVE = "DNS_RESOLVE"
    TLS_INSPECT = "TLS_INSPECT"
    REPRODUCE_EXPERIMENT = "REPRODUCE_EXPERIMENT"
    DISCOVER_WEB_CONTENT = "DISCOVER_WEB_CONTENT"
    ASSESS_WEB_TEMPLATES = "ASSESS_WEB_TEMPLATES"
    STOP_RESEARCH = "STOP_RESEARCH"


class ResearchActionPurpose(StrEnum):
    BASELINE = "BASELINE"
    OWNER_BASELINE = "OWNER_BASELINE"
    CANDIDATE_OBSERVATION = "CANDIDATE_OBSERVATION"
    ROLE_COMPARISON = "ROLE_COMPARISON"
    SERVICE_ENUMERATION = "SERVICE_ENUMERATION"
    PROTOCOL_CONFIRMATION = "PROTOCOL_CONFIRMATION"
    GAP_RESOLUTION = "GAP_RESOLUTION"
    EXPERIMENT_REPRODUCTION = "EXPERIMENT_REPRODUCTION"
    GENERAL_OBSERVATION = "GENERAL_OBSERVATION"
    WEB_CONTENT_ENUMERATION = "WEB_CONTENT_ENUMERATION"
    WEB_TEMPLATE_ASSESSMENT = "WEB_TEMPLATE_ASSESSMENT"


class ExpectedEvidenceType(StrEnum):
    STATUS_CODE = "STATUS_CODE"
    CONTENT_TYPE = "CONTENT_TYPE"
    REDIRECT_LOCATION = "REDIRECT_LOCATION"
    JSON_VALIDITY = "JSON_VALIDITY"
    JSON_FIELD = "JSON_FIELD"
    BODY_HASH = "BODY_HASH"
    RESOURCE_ID = "RESOURCE_ID"
    RESOURCE_OWNER = "RESOURCE_OWNER"
    SERVICE_STATE = "SERVICE_STATE"
    SERVICE_NAME = "SERVICE_NAME"
    DNS_RESULT = "DNS_RESULT"
    TLS_METADATA = "TLS_METADATA"
    WEB_RESOURCE = "WEB_RESOURCE"
    TEMPLATE_CANDIDATE = "TEMPLATE_CANDIDATE"


class JsonFieldSelector(DomainModel):
    segments: tuple[str, ...] = Field(min_length=1, max_length=8)

    @model_validator(mode="after")
    def safe_segments(self) -> "JsonFieldSelector":
        if any(
            not segment
            or len(segment) > 80
            or not all(character.isalnum() or character in {"_", "-"} for character in segment)
            for segment in self.segments
        ):
            raise ValueError("JSON field selectors contain only bounded name segments")
        return self


class ExpectedEvidence(DomainModel):
    information: ExpectedEvidenceType
    field_selector: JsonFieldSelector | None = None

    @model_validator(mode="after")
    def selector_matches_type(self) -> "ExpectedEvidence":
        if self.information is ExpectedEvidenceType.JSON_FIELD and self.field_selector is None:
            raise ValueError("JSON_FIELD requires a field selector")
        if (
            self.information is not ExpectedEvidenceType.JSON_FIELD
            and self.field_selector is not None
        ):
            raise ValueError("field selectors are only valid for JSON_FIELD")
        return self


class ResearchActionStatus(StrEnum):
    PROPOSED = "PROPOSED"
    VALIDATED = "VALIDATED"
    WAITING_FOR_APPROVAL = "WAITING_FOR_APPROVAL"
    REJECTED = "REJECTED"
    AUTHORIZED = "AUTHORIZED"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    SATISFIED = "SATISFIED"
    UNSATISFIED = "UNSATISFIED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ActionSatisfaction(StrEnum):
    SATISFIED = "SATISFIED"
    UNSATISFIED = "UNSATISFIED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class _ActionProposalBase(DomainModel):
    action_version: Literal["research-action-v1"] = RESEARCH_ACTION_VERSION
    research_session_id: Identifier
    purpose: ResearchActionPurpose
    subject_entity_id: Identifier
    target_entity_id: Identifier | None = None
    resource_entity_id: Identifier | None = None
    identity_entity_id: Identifier | None = None
    supporting_gap_ids: tuple[Identifier, ...] = ()
    supporting_question_ids: tuple[Identifier, ...] = ()
    supporting_signal_ids: tuple[Identifier, ...] = ()
    supporting_hypothesis_ids: tuple[Identifier, ...] = ()
    supporting_observation_ids: tuple[Identifier, ...] = ()
    expected_information: tuple[ExpectedEvidence, ...] = Field(min_length=1)
    priority: IntentPriority = IntentPriority.NORMAL
    rationale: str = Field(min_length=1, max_length=1000)
    repeat_reason: Literal[
        "REPRODUCTION",
        "CONFLICT_RESOLUTION",
        "TEMPORAL_RECHECK",
        "EXPERIMENTAL_EXPLORATION",
    ] | None = None
    depends_on: tuple[int, ...] = ()


class HttpObserveActionProposal(_ActionProposalBase):
    action_type: Literal[ResearchActionType.HTTP_OBSERVE]
    endpoint_entity_id: Identifier
    identity_entity_id: Identifier
    method: Literal["GET", "HEAD", "OPTIONS"] = "GET"


class ServiceDiscoveryActionProposal(_ActionProposalBase):
    action_type: Literal[ResearchActionType.SERVICE_DISCOVERY]


class DNSResolveActionProposal(_ActionProposalBase):
    action_type: Literal[ResearchActionType.DNS_RESOLVE]


class TLSInspectActionProposal(_ActionProposalBase):
    action_type: Literal[ResearchActionType.TLS_INSPECT]


class ReproduceExperimentActionProposal(_ActionProposalBase):
    action_type: Literal[ResearchActionType.REPRODUCE_EXPERIMENT]
    experiment_id: Identifier
    reproduction_number: int = Field(ge=1, le=100)


class DiscoverWebContentActionProposal(_ActionProposalBase):
    action_type: Literal[ResearchActionType.DISCOVER_WEB_CONTENT]
    web_resource_id: Identifier
    profile: Literal["web_content_small", "web_content_standard"] = "web_content_small"


class AssessWebTemplatesActionProposal(_ActionProposalBase):
    action_type: Literal[ResearchActionType.ASSESS_WEB_TEMPLATES]
    web_resource_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=100)
    profile: Literal["safe_templates"] = "safe_templates"


class StopResearchActionProposal(_ActionProposalBase):
    action_type: Literal[ResearchActionType.STOP_RESEARCH]


TypedResearchActionProposal = Annotated[
    HttpObserveActionProposal
    | ServiceDiscoveryActionProposal
    | DNSResolveActionProposal
    | TLSInspectActionProposal
    | ReproduceExperimentActionProposal
    | DiscoverWebContentActionProposal
    | AssessWebTemplatesActionProposal
    | StopResearchActionProposal,
    Field(discriminator="action_type"),
]


class ControllerDecisionType(StrEnum):
    CONTINUE = "CONTINUE"
    STOP_SUFFICIENT_EVIDENCE = "STOP_SUFFICIENT_EVIDENCE"
    STOP_NO_HIGH_VALUE_ACTION = "STOP_NO_HIGH_VALUE_ACTION"
    STOP_NO_SAFE_ACTION = "STOP_NO_SAFE_ACTION"
    STOP_POLICY_BLOCKED = "STOP_POLICY_BLOCKED"
    STOP_LIMIT_REACHED = "STOP_LIMIT_REACHED"
    STOP_USER_REQUEST = "STOP_USER_REQUEST"
    INCONCLUSIVE = "INCONCLUSIVE"


class ControllerDecision(DomainModel):
    decision_version: Literal["controller-decision-v1"] = CONTROLLER_DECISION_VERSION
    session_id: Identifier
    decision_type: ControllerDecisionType
    actions: tuple[TypedResearchActionProposal, ...] = ()
    stop_reason: str | None = Field(default=None, max_length=1000)
    limitations: tuple[str, ...] = ()

    @model_validator(mode="after")
    def decision_shape(self) -> "ControllerDecision":
        if self.decision_type is ControllerDecisionType.CONTINUE and not self.actions:
            raise ValueError("CONTINUE requires at least one typed action")
        if self.decision_type is not ControllerDecisionType.CONTINUE and self.actions:
            raise ValueError("stop decisions cannot contain actions")
        return self

    @property
    def sha256(self) -> str:
        return _semantic_hash(self.model_dump(mode="json"))


class HTTPAuthorization(DomainModel):
    decision_id: str
    allowed: bool
    reason_code: str
    message: str
    policy_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    policy_engine: str
    policy_engine_version: str


class EvidenceAcquisitionContract(DomainModel):
    action_version: Literal["research-action-v1"] = RESEARCH_ACTION_VERSION
    research_session_id: Identifier
    action_type: ResearchActionType
    purpose: ResearchActionPurpose
    endpoint_entity_id: Identifier | None = None
    identity_entity_id: Identifier | None = None
    resource_entity_id: Identifier | None = None
    method: str | None = None
    path: str | None = None
    capability: ToolCapability | None = None
    expected_information: tuple[ExpectedEvidence, ...]
    timeout_ms: int = Field(ge=1, le=60_000)
    max_response_bytes: int = Field(ge=1, le=10_000_000)
    follow_redirects: bool = False
    policy_decision: HTTPAuthorization | None = None


class ResearchAction(EntityModel):
    controller_step_id: Identifier
    research_session_id: Identifier
    action_type: ResearchActionType
    purpose: ResearchActionPurpose
    proposal: TypedResearchActionProposal
    semantic_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    status: ResearchActionStatus = ResearchActionStatus.PROPOSED
    contract: EvidenceAcquisitionContract | None = None
    validation_reason: str | None = None
    research_intent_id: Identifier | None = None
    discovery_plan_id: Identifier | None = None
    experiment_execution_id: Identifier | None = None
    tool_run_ids: tuple[Identifier, ...] = ()
    evidence_ids: tuple[Identifier, ...] = ()
    observation_ids: tuple[Identifier, ...] = ()
    verification_result_ids: tuple[Identifier, ...] = ()
    satisfaction: ActionSatisfaction | None = None
    failure_reason: str | None = None
    operator_initiated: bool = False
    created_at: datetime = Field(default_factory=utc_now)
    finished_at: datetime | None = None


class ResearchActionResult(EntityModel):
    action_id: Identifier
    research_session_id: Identifier
    status: ResearchActionStatus
    tool_run_ids: tuple[Identifier, ...] = ()
    evidence_ids: tuple[Identifier, ...] = ()
    observation_ids: tuple[Identifier, ...] = ()
    verification_result_ids: tuple[Identifier, ...] = ()
    request_cost: int = Field(default=0, ge=0)
    started_at: datetime = Field(default_factory=utc_now)
    finished_at: datetime | None = None
    satisfaction: ActionSatisfaction
    failure_reason: str | None = None


class ControllerStatus(StrEnum):
    CREATED = "CREATED"
    READY = "READY"
    RUNNING = "RUNNING"
    WAITING_FOR_APPROVAL = "WAITING_FOR_APPROVAL"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    INCONCLUSIVE = "INCONCLUSIVE"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ResearchBudget(EntityModel):
    research_session_id: Identifier
    max_steps: int = Field(ge=1, le=100)
    max_actions: int = Field(ge=1, le=1000)
    max_tool_runs: int = Field(ge=0, le=1000)
    max_requests: int = Field(ge=0, le=10_000)
    max_duration_seconds: float = Field(ge=1, le=86_400)
    max_llm_calls: int = Field(ge=0, le=1000)
    allowed_capabilities: tuple[ToolCapability, ...] = ()
    consumed_steps: int = Field(default=0, ge=0)
    consumed_actions: int = Field(default=0, ge=0)
    consumed_tool_runs: int = Field(default=0, ge=0)
    consumed_requests: int = Field(default=0, ge=0)
    consumed_duration_seconds: float = Field(default=0, ge=0)
    consumed_llm_calls: int = Field(default=0, ge=0)
    controller_status: ControllerStatus = ControllerStatus.READY
    stop_reason: str | None = None
    pause_requested: bool = False
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    def exhausted_reason(self) -> str | None:
        checks = (
            (self.consumed_steps >= self.max_steps, "max_steps"),
            (self.consumed_actions >= self.max_actions, "max_actions"),
            (self.consumed_tool_runs >= self.max_tool_runs, "max_tool_runs"),
            (self.consumed_requests >= self.max_requests, "max_requests"),
            (self.consumed_duration_seconds >= self.max_duration_seconds, "max_duration_seconds"),
            (self.consumed_llm_calls >= self.max_llm_calls, "max_llm_calls"),
        )
        return next((name for exhausted, name in checks if exhausted), None)


class ControllerStepStatus(StrEnum):
    CREATED = "CREATED"
    PLANNED = "PLANNED"
    WAITING_FOR_APPROVAL = "WAITING_FOR_APPROVAL"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ControllerStep(EntityModel):
    research_session_id: Identifier
    step_number: int = Field(ge=1)
    context_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    knowledge_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    model_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    graph_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    provider: str
    model: str
    prompt_version: str = CONTROLLER_PROMPT_VERSION
    decision: ControllerDecision | None = None
    decision_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    decision_type: ControllerDecisionType | None = None
    action_ids: tuple[Identifier, ...] = ()
    budget_before: dict[str, object]
    budget_after: dict[str, object] | None = None
    status: ControllerStepStatus = ControllerStepStatus.CREATED
    stop_reason: str | None = None
    provider_request_id: str | None = None
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    latency_ms: int | None = Field(default=None, ge=0)
    created_at: datetime = Field(default_factory=utc_now)
    finished_at: datetime | None = None


class ControllerContext(DomainModel):
    session_id: Identifier
    scope: dict[str, object]
    budget_remaining: dict[str, object]
    knowledge_hash: str
    model_hash: str
    graph_hash: str | None
    open_gaps: tuple[dict[str, object], ...]
    questions: tuple[dict[str, object], ...]
    strategy_candidates: tuple[dict[str, object], ...]
    entities: tuple[dict[str, object], ...]
    signals: tuple[dict[str, object], ...]
    hypotheses: tuple[dict[str, object], ...]
    recent_actions: tuple[dict[str, object], ...]
    recent_policy_rejections: tuple[dict[str, object], ...]
    web_surface: dict[str, object] = Field(default_factory=dict)
    limitations: tuple[str, ...] = ()

    @property
    def sha256(self) -> str:
        payload = self.model_dump(mode="json")
        payload.pop("session_id", None)
        return _semantic_hash(payload)


def action_semantic_hash(proposal: TypedResearchActionProposal) -> str:
    payload = proposal.model_dump(mode="json")
    payload.pop("rationale", None)
    payload.pop("depends_on", None)
    payload.pop("repeat_reason", None)
    payload["supporting_gap_ids"] = sorted(payload["supporting_gap_ids"])
    payload["supporting_question_ids"] = sorted(payload["supporting_question_ids"])
    payload["supporting_signal_ids"] = sorted(payload["supporting_signal_ids"])
    payload["supporting_hypothesis_ids"] = sorted(payload["supporting_hypothesis_ids"])
    payload["supporting_observation_ids"] = sorted(payload["supporting_observation_ids"])
    return _semantic_hash(payload)


def _semantic_hash(payload: object) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
