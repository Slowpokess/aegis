from datetime import datetime
from enum import StrEnum

from pydantic import Field, model_validator

from app.domain.common import (
    DomainModel,
    EntityModel,
    FactClassification,
    Identifier,
    JsonObject,
    utc_now,
)
from app.domain.system_model import SystemEntityType

ATTACK_GRAPH_VERSION = "attack-graph-v1"


class EdgeDisposition(StrEnum):
    TRAVERSABLE = "TRAVERSABLE"
    INFORMATIONAL = "INFORMATIONAL"
    BLOCKING = "BLOCKING"


class GraphMode(StrEnum):
    OBSERVED_ONLY = "OBSERVED_ONLY"
    ALLOW_INFERRED = "ALLOW_INFERRED"


class GraphSnapshotStatus(StrEnum):
    CURRENT = "CURRENT"
    STALE = "STALE"


class GraphEdgeType(StrEnum):
    HOSTS = "HOSTS"
    EXPOSES = "EXPOSES"
    CALLS = "CALLS"
    CAN_ACCESS = "CAN_ACCESS"
    CANNOT_ACCESS = "CANNOT_ACCESS"
    AUTHENTICATES_AS = "AUTHENTICATES_AS"
    HAS_ROLE = "HAS_ROLE"
    OWNS = "OWNS"
    READS = "READS"
    RETURNS = "RETURNS"
    CONTAINS = "CONTAINS"
    TRUSTS = "TRUSTS"
    CROSSES_BOUNDARY = "CROSSES_BOUNDARY"
    RESOLVES_TO = "RESOLVES_TO"
    HAS_CAPABILITY = "HAS_CAPABILITY"
    APPLIES_TO = "APPLIES_TO"


class PathType(StrEnum):
    ACCESS_PATH = "ACCESS_PATH"
    RESOURCE_PATH = "RESOURCE_PATH"
    ROLE_PATH = "ROLE_PATH"


class CandidateSignalType(StrEnum):
    CROSS_IDENTITY_RESOURCE_ACCESS = "CROSS_IDENTITY_RESOURCE_ACCESS"
    ROLE_ACCESS_DIFFERENCE = "ROLE_ACCESS_DIFFERENCE"


class GraphErrorCode(StrEnum):
    MODEL_NOT_FOUND = "MODEL_NOT_FOUND"
    MODEL_STALE = "MODEL_STALE"
    NODE_NOT_FOUND = "NODE_NOT_FOUND"
    GRAPH_LIMIT_EXCEEDED = "GRAPH_LIMIT_EXCEEDED"
    INVALID_RELATIONSHIP = "INVALID_RELATIONSHIP"
    PROVENANCE_INVALID = "PROVENANCE_INVALID"
    CROSS_SESSION_REFERENCE = "CROSS_SESSION_REFERENCE"


class GraphNode(DomainModel):
    node_id: str = Field(min_length=1, max_length=2200)
    node_type: SystemEntityType
    system_entity_id: Identifier
    canonical_identifier: str = Field(min_length=1, max_length=2048)
    classification: FactClassification
    confidence: float = Field(ge=0.0, le=1.0)
    observation_ids: list[Identifier] = Field(default_factory=list)
    evidence_ids: list[Identifier] = Field(default_factory=list)


class GraphEdge(DomainModel):
    edge_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_node_id: str
    target_node_id: str
    edge_type: GraphEdgeType
    disposition: EdgeDisposition
    classification: FactClassification
    confidence: float = Field(ge=0.0, le=1.0)
    system_relationship_ids: list[Identifier] = Field(default_factory=list)
    system_entity_ids: list[Identifier] = Field(default_factory=list)
    observation_ids: list[Identifier] = Field(default_factory=list)
    evidence_ids: list[Identifier] = Field(default_factory=list)

    @model_validator(mode="after")
    def observed_edge_has_lineage(self) -> "GraphEdge":
        if self.classification is FactClassification.OBSERVED:
            if not self.observation_ids or not self.evidence_ids:
                raise ValueError("observed graph edges require observation and evidence lineage")
        return self


class AttackGraph(DomainModel):
    graph_id: Identifier
    research_session_id: Identifier
    graph_version: str = ATTACK_GRAPH_VERSION
    system_model_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    graph_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    mode: GraphMode = GraphMode.OBSERVED_ONLY
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    truncated: bool = False
    truncation_reason: str | None = None


class AttackPath(DomainModel):
    id: str = Field(pattern=r"^[a-f0-9]{64}$")
    graph_id: Identifier
    path_type: PathType
    source_node_id: str
    target_node_id: str
    node_ids: list[str]
    edge_ids: list[str]
    hop_count: int = Field(ge=0)
    confidence: float = Field(ge=0.0, le=1.0)
    contains_inferred_edges: bool
    blocking_reason: str | None = None
    system_relationship_ids: list[Identifier] = Field(default_factory=list)
    observation_ids: list[Identifier] = Field(default_factory=list)
    evidence_ids: list[Identifier] = Field(default_factory=list)
    explanation: str


class PathQueryResult(DomainModel):
    paths: list[AttackPath]
    truncated: bool = False
    reason: str | None = None


class CrossIdentityAccess(DomainModel):
    accessor_identity_id: Identifier
    owner_identity_id: Identifier
    resource_id: Identifier
    endpoint_id: Identifier
    access_relationship_id: Identifier
    return_relationship_id: Identifier
    ownership_relationship_id: Identifier
    observation_ids: list[Identifier]
    evidence_ids: list[Identifier]
    classification: FactClassification


class RoleAccessDifference(DomainModel):
    endpoint_id: Identifier
    identity_a_id: Identifier
    role_a_id: Identifier
    result_a: str
    identity_b_id: Identifier
    role_b_id: Identifier
    result_b: str
    system_relationship_ids: list[Identifier]
    observation_ids: list[Identifier]
    evidence_ids: list[Identifier]


class AttackGraphSnapshot(EntityModel):
    research_session_id: Identifier
    system_model_build_id: Identifier | None = None
    graph_version: str = ATTACK_GRAPH_VERSION
    system_model_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    graph_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    node_count: int = Field(ge=0)
    edge_count: int = Field(ge=0)
    traversable_edge_count: int = Field(ge=0)
    blocking_edge_count: int = Field(ge=0)
    status: GraphSnapshotStatus = GraphSnapshotStatus.CURRENT
    truncated: bool = False
    truncation_reason: str | None = None
    created_at: datetime = Field(default_factory=utc_now)


class CandidateSignal(EntityModel):
    graph_id: Identifier
    research_session_id: Identifier
    signal_type: CandidateSignalType
    semantic_key: str = Field(min_length=1, max_length=2048)
    subject_entity_id: Identifier
    target_entity_id: Identifier
    resource_entity_id: Identifier | None = None
    endpoint_entity_id: Identifier | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    classification: FactClassification
    system_relationship_ids: list[Identifier]
    observation_ids: list[Identifier]
    evidence_ids: list[Identifier]
    details: JsonObject = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)
