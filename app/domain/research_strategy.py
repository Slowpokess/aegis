import hashlib
import json
from datetime import datetime
from enum import StrEnum

from pydantic import Field

from app.domain.common import DomainModel, EntityModel, Identifier, utc_now
from app.domain.discovery import ToolRisk
from app.domain.research_planner import ResearchIntentProposal

KNOWLEDGE_VERSION = "knowledge-v1"
STRATEGY_VERSION = "research-strategy-v1"


class KnowledgeClassification(StrEnum):
    KNOWN = "KNOWN"
    ASSUMED = "ASSUMED"
    UNKNOWN = "UNKNOWN"
    CONFLICTING = "CONFLICTING"
    UNTESTED = "UNTESTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class GapType(StrEnum):
    MISSING_BASELINE = "MISSING_BASELINE"
    MISSING_COMPARISON = "MISSING_COMPARISON"
    MISSING_IDENTITY_OBSERVATION = "MISSING_IDENTITY_OBSERVATION"
    MISSING_SERVICE_INFORMATION = "MISSING_SERVICE_INFORMATION"
    MISSING_RESOURCE_OWNERSHIP = "MISSING_RESOURCE_OWNERSHIP"
    MISSING_ROLE_BEHAVIOR = "MISSING_ROLE_BEHAVIOR"
    MISSING_PROTOCOL_INFORMATION = "MISSING_PROTOCOL_INFORMATION"
    CONFLICTING_OBSERVATIONS = "CONFLICTING_OBSERVATIONS"
    INSUFFICIENT_REPRODUCTION = "INSUFFICIENT_REPRODUCTION"
    UNKNOWN = "UNKNOWN"


class GapStatus(StrEnum):
    OPEN = "OPEN"
    PARTIALLY_RESOLVED = "PARTIALLY_RESOLVED"
    RESOLVED = "RESOLVED"
    BLOCKED = "BLOCKED"
    STALE = "STALE"


class GapPriority(StrEnum):
    LOW = "LOW"
    NORMAL = "NORMAL"
    HIGH = "HIGH"


class QuestionType(StrEnum):
    ACCESS_COMPARISON = "ACCESS_COMPARISON"
    OWNERSHIP_CONFIRMATION = "OWNERSHIP_CONFIRMATION"
    ROLE_COMPARISON = "ROLE_COMPARISON"
    SERVICE_IDENTIFICATION = "SERVICE_IDENTIFICATION"
    DNS_RESOLUTION = "DNS_RESOLUTION"
    TLS_PRESENCE = "TLS_PRESENCE"
    REPRODUCTION = "REPRODUCTION"


class QuestionStatus(StrEnum):
    OPEN = "OPEN"
    ANSWERED = "ANSWERED"
    BLOCKED = "BLOCKED"
    STALE = "STALE"


class InformationGainLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class StrategyMode(StrEnum):
    DETERMINISTIC = "DETERMINISTIC"
    LLM_ASSISTED = "LLM_ASSISTED"


class StrategyRunStatus(StrEnum):
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    NO_SAFE_ACTION = "NO_SAFE_ACTION"
    FAILED = "FAILED"


class SufficiencyState(StrEnum):
    INSUFFICIENT = "INSUFFICIENT"
    SUFFICIENT_FOR_HYPOTHESIS = "SUFFICIENT_FOR_HYPOTHESIS"
    SUFFICIENT_FOR_EXPERIMENT = "SUFFICIENT_FOR_EXPERIMENT"
    SUFFICIENT_FOR_VERIFICATION = "SUFFICIENT_FOR_VERIFICATION"


class HypothesisRelationshipType(StrEnum):
    ALTERNATIVE_TO = "ALTERNATIVE_TO"
    COMPETES_WITH = "COMPETES_WITH"
    DEPENDS_ON_GAP = "DEPENDS_ON_GAP"


class KnowledgeFact(DomainModel):
    semantic_key: str = Field(min_length=1, max_length=2048)
    statement: str = Field(min_length=1, max_length=3000)
    classification: KnowledgeClassification
    subject_entity_id: Identifier | None = None
    target_entity_id: Identifier | None = None
    observation_ids: tuple[Identifier, ...] = ()
    evidence_ids: tuple[Identifier, ...] = ()


class KnowledgeState(DomainModel):
    session_id: Identifier
    facts: tuple[KnowledgeFact, ...]

    def count(self, classification: KnowledgeClassification) -> int:
        return sum(item.classification is classification for item in self.facts)


class EvidenceGap(EntityModel):
    research_session_id: Identifier
    semantic_key: str = Field(min_length=1, max_length=2048)
    gap_type: GapType
    subject_entity_id: Identifier
    target_entity_id: Identifier | None = None
    resource_entity_id: Identifier | None = None
    description: str = Field(min_length=1, max_length=3000)
    current_state: KnowledgeClassification
    required_information: tuple[str, ...] = Field(min_length=1)
    supporting_observation_ids: tuple[Identifier, ...] = ()
    supporting_evidence_ids: tuple[Identifier, ...] = ()
    supporting_signal_ids: tuple[Identifier, ...] = ()
    supporting_hypothesis_ids: tuple[Identifier, ...] = ()
    priority: GapPriority = GapPriority.NORMAL
    status: GapStatus = GapStatus.OPEN
    blocked_reason: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    resolved_at: datetime | None = None


class ResearchQuestion(EntityModel):
    research_session_id: Identifier
    gap_id: Identifier
    semantic_key: str = Field(min_length=1, max_length=2048)
    question_type: QuestionType
    subject_entity_id: Identifier
    target_entity_id: Identifier | None = None
    resource_entity_id: Identifier | None = None
    expected_information: tuple[str, ...] = Field(min_length=1)
    candidate_answers: tuple[str, ...] = Field(min_length=1)
    status: QuestionStatus = QuestionStatus.OPEN
    created_at: datetime = Field(default_factory=utc_now)


class InformationGainEstimate(DomainModel):
    level: InformationGainLevel
    score: int = Field(ge=0, le=100)
    factors: tuple[str, ...]


class ResearchCost(DomainModel):
    tool_runs: int = Field(ge=0)
    network_requests: int = Field(ge=0)
    estimated_duration_seconds: float = Field(ge=0)
    llm_tokens: int | None = Field(default=None, ge=0)
    risk_class: ToolRisk


class StrategyCandidate(DomainModel):
    gap_ids: tuple[Identifier, ...] = Field(min_length=1)
    research_question_ids: tuple[Identifier, ...] = Field(min_length=1)
    proposed_intent: ResearchIntentProposal
    information_gain: InformationGainEstimate
    cost: ResearchCost
    priority_score: int = Field(ge=0, le=100)
    expected_resolution: str
    selection_reason: str
    selected: bool = False
    policy_allowed: bool | None = None
    policy_reason: str | None = None


class KnowledgeSnapshot(EntityModel):
    research_session_id: Identifier
    system_model_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    graph_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    knowledge_version: str = KNOWLEDGE_VERSION
    known_count: int = Field(ge=0)
    assumed_count: int = Field(ge=0)
    unknown_count: int = Field(ge=0)
    conflicting_count: int = Field(ge=0)
    untested_count: int = Field(ge=0)
    inconclusive_count: int = Field(ge=0)
    open_gap_count: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    created_at: datetime = Field(default_factory=utc_now)


class StrategyRun(EntityModel):
    research_session_id: Identifier
    knowledge_snapshot_id: Identifier
    strategy_version: str = STRATEGY_VERSION
    mode: StrategyMode = StrategyMode.DETERMINISTIC
    started_at: datetime = Field(default_factory=utc_now)
    finished_at: datetime | None = None
    candidates: tuple[StrategyCandidate, ...] = ()
    candidate_count: int = Field(default=0, ge=0)
    selected_intent_count: int = Field(default=0, ge=0)
    redundant_intents_prevented: int = Field(default=0, ge=0)
    status: StrategyRunStatus = StrategyRunStatus.RUNNING


class HypothesisAlternative(DomainModel):
    hypothesis_id: Identifier
    related_hypothesis_id: Identifier | None = None
    gap_id: Identifier | None = None
    relationship: HypothesisRelationshipType
    rationale: str = Field(min_length=1, max_length=1000)


class AccessMatrixCell(DomainModel):
    identity_id: Identifier
    endpoint_id: Identifier
    observed: bool
    result: str | None = None
    observation_ids: tuple[Identifier, ...] = ()


class AccessMatrix(DomainModel):
    session_id: Identifier
    cells: tuple[AccessMatrixCell, ...]


def knowledge_sha256(
    *,
    system_model_hash: str,
    graph_hash: str | None,
    facts: tuple[KnowledgeFact, ...],
    gaps: tuple[EvidenceGap, ...],
) -> str:
    payload = {
        "version": KNOWLEDGE_VERSION,
        "system_model_hash": system_model_hash,
        "graph_hash": graph_hash,
        "facts": [item.model_dump(mode="json") for item in facts],
        "gaps": [
            {
                "semantic_key": item.semantic_key,
                "gap_type": item.gap_type.value,
                "current_state": item.current_state.value,
                "required_information": item.required_information,
                "status": item.status.value,
            }
            for item in gaps
        ],
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()
