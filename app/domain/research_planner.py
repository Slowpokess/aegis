import hashlib
import json
from datetime import datetime
from enum import StrEnum

from pydantic import Field, model_validator

from app.domain.common import DomainModel, EntityModel, Identifier, utc_now
from app.domain.discovery import ToolCapability

PLANNER_DECISION_VERSION = "planner-decision-v1"
RESEARCH_PLANNER_PROMPT_VERSION = "research-planner-v1"


class ResearchIntentType(StrEnum):
    DISCOVER_SERVICES = "DISCOVER_SERVICES"
    RESOLVE_HOST = "RESOLVE_HOST"
    INSPECT_TLS = "INSPECT_TLS"
    OBSERVE_HTTP = "OBSERVE_HTTP"
    VERIFY_CANDIDATE_SIGNAL = "VERIFY_CANDIDATE_SIGNAL"
    DISCOVER_WEB_CONTENT = "DISCOVER_WEB_CONTENT"
    ASSESS_WEB_TEMPLATES = "ASSESS_WEB_TEMPLATES"


class ExpectedInformation(StrEnum):
    SERVICES = "services"
    DNS_ADDRESSES = "dns_addresses"
    TLS_METADATA = "tls_metadata"
    HTTP_METADATA = "http_metadata"
    CANDIDATE_EVIDENCE = "candidate_evidence"
    WEB_RESOURCES = "web_resources"
    TEMPLATE_CANDIDATES = "template_candidates"


class IntentPriority(StrEnum):
    LOW = "LOW"
    NORMAL = "NORMAL"
    HIGH = "HIGH"


class IntentSource(StrEnum):
    USER = "USER"
    LLM = "LLM"
    DETERMINISTIC = "DETERMINISTIC"


class ResearchIntentStatus(StrEnum):
    PROPOSED = "PROPOSED"
    VALIDATED = "VALIDATED"
    REJECTED = "REJECTED"
    PLANNED = "PLANNED"
    EXECUTING = "EXECUTING"
    SATISFIED = "SATISFIED"
    UNSATISFIED = "UNSATISFIED"
    FAILED = "FAILED"


class PlannerState(StrEnum):
    CONTINUE = "CONTINUE"
    STOP_SUFFICIENT_EVIDENCE = "STOP_SUFFICIENT_EVIDENCE"
    STOP_NO_SAFE_ACTION = "STOP_NO_SAFE_ACTION"
    STOP_LIMIT_REACHED = "STOP_LIMIT_REACHED"
    INCONCLUSIVE = "INCONCLUSIVE"


class ResearchStepStatus(StrEnum):
    CREATED = "CREATED"
    PLANNED = "PLANNED"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ContextTrust(StrEnum):
    SYSTEM = "SYSTEM"
    DERIVED_TRUSTED = "DERIVED_TRUSTED"
    UNTRUSTED_TARGET_DATA = "UNTRUSTED_TARGET_DATA"
    UNTRUSTED_TOOL_DATA = "UNTRUSTED_TOOL_DATA"
    LLM_PROPOSAL = "LLM_PROPOSAL"


class IntentSatisfaction(StrEnum):
    SATISFIED = "SATISFIED"
    UNSATISFIED = "UNSATISFIED"
    ENOUGH_EVIDENCE_FOR_HYPOTHESIS = "ENOUGH_EVIDENCE_FOR_HYPOTHESIS"
    MORE_EVIDENCE_REQUIRED = "MORE_EVIDENCE_REQUIRED"
    NO_SAFE_OBSERVATION_AVAILABLE = "NO_SAFE_OBSERVATION_AVAILABLE"


class ResearchContextItem(DomainModel):
    kind: str = Field(min_length=1, max_length=80)
    entity_id: Identifier | None = None
    semantic_id: str = Field(min_length=1, max_length=2048)
    trust: ContextTrust
    data: dict[str, object] = Field(default_factory=dict)


class ResearchContext(DomainModel):
    session_id: Identifier
    target_asset_id: Identifier
    scope: dict[str, object]
    system_model_hash: str
    attack_graph_id: Identifier | None = None
    attack_graph_hash: str | None = None
    entities: tuple[ResearchContextItem, ...] = ()
    candidate_signals: tuple[ResearchContextItem, ...] = ()
    observations: tuple[ResearchContextItem, ...] = ()
    history: tuple[ResearchContextItem, ...] = ()
    research_records: tuple[ResearchContextItem, ...] = ()
    limitations: tuple[str, ...] = ()

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

    @property
    def sha256(self) -> str:
        payload = self.model_dump(mode="json")
        for field in ("session_id", "target_asset_id", "attack_graph_id"):
            payload.pop(field, None)
        for collection in (
            "entities",
            "candidate_signals",
            "observations",
            "history",
            "research_records",
        ):
            for item in payload[collection]:
                item.pop("entity_id", None)
        semantic = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(semantic).hexdigest()


class ResearchIntentProposal(DomainModel):
    intent_type: ResearchIntentType
    subject_entity_id: Identifier
    target_entity_id: Identifier | None = None
    reason: str = Field(min_length=1, max_length=1000)
    expected_information: tuple[ExpectedInformation, ...] = Field(min_length=1)
    priority: IntentPriority = IntentPriority.NORMAL
    supporting_observation_ids: tuple[Identifier, ...] = ()
    supporting_evidence_ids: tuple[Identifier, ...] = ()
    supporting_signal_ids: tuple[Identifier, ...] = ()
    evidence_gap_ids: tuple[Identifier, ...] = ()


class PlannerDecision(DomainModel):
    decision_version: str = PLANNER_DECISION_VERSION
    session_id: Identifier
    state: PlannerState
    intents: tuple[ResearchIntentProposal, ...] = ()
    stop_reason: str | None = Field(default=None, max_length=1000)
    limitations: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_decision(self) -> "PlannerDecision":
        if self.decision_version != PLANNER_DECISION_VERSION:
            raise ValueError("unsupported planner decision version")
        if self.state is not PlannerState.CONTINUE and self.intents:
            raise ValueError("stop decisions cannot contain research intents")
        return self

    @property
    def sha256(self) -> str:
        payload = self.model_dump(mode="json")
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()


class ResearchIntent(EntityModel):
    research_session_id: Identifier
    research_step_id: Identifier
    context_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    intent_type: ResearchIntentType
    subject_entity_id: Identifier
    target_entity_id: Identifier | None = None
    reason: str = Field(min_length=1, max_length=1000)
    expected_information: tuple[ExpectedInformation, ...]
    priority: IntentPriority
    source: IntentSource
    supporting_observation_ids: tuple[Identifier, ...] = ()
    supporting_evidence_ids: tuple[Identifier, ...] = ()
    supporting_signal_ids: tuple[Identifier, ...] = ()
    evidence_gap_ids: tuple[Identifier, ...] = ()
    semantic_key: str = Field(min_length=1, max_length=2048)
    status: ResearchIntentStatus = ResearchIntentStatus.PROPOSED
    capability: ToolCapability | None = None
    selected_tool_id: str | None = None
    selected_profile: str | None = None
    selection_reason: str | None = None
    policy_allowed: bool | None = None
    policy_reason: str | None = None
    discovery_plan_id: Identifier | None = None
    tool_run_ids: tuple[Identifier, ...] = ()
    resulting_observation_ids: tuple[Identifier, ...] = ()
    satisfaction: IntentSatisfaction | None = None
    created_at: datetime = Field(default_factory=utc_now)
    finished_at: datetime | None = None


class ResearchStep(EntityModel):
    research_session_id: Identifier
    step_number: int = Field(ge=1)
    context_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    planner_provider: str
    planner_model: str
    prompt_version: str = RESEARCH_PLANNER_PROMPT_VERSION
    decision: PlannerDecision | None = None
    decision_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    status: ResearchStepStatus = ResearchStepStatus.CREATED
    intent_ids: tuple[Identifier, ...] = ()
    discovery_plan_ids: tuple[Identifier, ...] = ()
    model_hash_before: str | None = None
    model_hash_after: str | None = None
    graph_hash_before: str | None = None
    graph_hash_after: str | None = None
    stop_reason: str | None = None
    provider_request_id: str | None = None
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    latency_ms: int | None = Field(default=None, ge=0)
    error: str | None = None
    started_at: datetime = Field(default_factory=utc_now)
    finished_at: datetime | None = None


class ResearchRunResult(DomainModel):
    research_session_id: Identifier
    steps: tuple[ResearchStep, ...]
    stop_state: PlannerState
    stop_reason: str
    total_intents: int = Field(ge=0)
    total_tool_runs: int = Field(ge=0)
