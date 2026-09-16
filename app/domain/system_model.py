from datetime import datetime
from enum import StrEnum

from pydantic import Field, model_validator

from app.domain.common import EntityModel, FactClassification, Identifier, JsonObject, utc_now

SYSTEM_MODEL_VERSION = "system-model-v1"


class SystemEntityType(StrEnum):
    ASSET = "ASSET"
    SERVICE = "SERVICE"
    ENDPOINT = "ENDPOINT"
    IDENTITY = "IDENTITY"
    ROLE = "ROLE"
    PERMISSION = "PERMISSION"
    CAPABILITY = "CAPABILITY"
    DATA_OBJECT = "DATA_OBJECT"
    TRUST_BOUNDARY = "TRUST_BOUNDARY"


class SystemAssetType(StrEnum):
    HOST = "HOST"
    APPLICATION = "APPLICATION"
    API = "API"
    SERVICE_CONTAINER = "SERVICE_CONTAINER"
    DOMAIN = "DOMAIN"


class SystemIdentityType(StrEnum):
    ANONYMOUS = "ANONYMOUS"
    USER = "USER"
    ADMINISTRATOR = "ADMINISTRATOR"
    SERVICE = "SERVICE"


class PermissionEffect(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    UNKNOWN = "UNKNOWN"


class CapabilityType(StrEnum):
    READ_ENDPOINT = "READ_ENDPOINT"
    ACCESS_RESOURCE = "ACCESS_RESOURCE"


class DataObjectType(StrEnum):
    JSON_RESOURCE = "JSON_RESOURCE"
    PROFILE = "PROFILE"
    ORDER = "ORDER"
    ACCOUNT_SETTINGS = "ACCOUNT_SETTINGS"
    STATISTICS = "STATISTICS"
    RESOURCE = "RESOURCE"


class BoundaryType(StrEnum):
    CLIENT_TO_APPLICATION = "CLIENT_TO_APPLICATION"
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION = "AUTHORIZATION"


class RelationshipType(StrEnum):
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


class ModelBuildStatus(StrEnum):
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class SystemFact(EntityModel):
    research_session_id: Identifier
    canonical_identifier: str = Field(min_length=1, max_length=2048)
    source_type: str = Field(min_length=1, max_length=100)
    observation_ids: list[Identifier] = Field(default_factory=list)
    evidence_ids: list[Identifier] = Field(default_factory=list)
    classification: FactClassification
    confidence: float = Field(ge=0.0, le=1.0)
    first_seen: datetime = Field(default_factory=utc_now)
    last_seen: datetime = Field(default_factory=utc_now)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def observed_fact_has_lineage(self) -> "SystemFact":
        if self.classification is FactClassification.OBSERVED:
            if not self.observation_ids or not self.evidence_ids:
                raise ValueError("observed system facts require observation and evidence lineage")
            if self.confidence != 1.0:
                raise ValueError("deterministic observed system facts use confidence 1.0")
        elif self.confidence >= 1.0:
            raise ValueError("inferred system facts must use confidence below 1.0")
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen cannot precede first_seen")
        return self


class SystemAsset(SystemFact):
    asset_type: SystemAssetType
    name: str = Field(min_length=1, max_length=200)
    parent_asset_id: Identifier | None = None
    metadata: JsonObject = Field(default_factory=dict)


class SystemService(SystemFact):
    asset_id: Identifier
    protocol: str = Field(min_length=1, max_length=30)
    port: int = Field(ge=1, le=65535)
    service_type: str = Field(min_length=1, max_length=100)
    observed_state: str = Field(min_length=1, max_length=30)


class SystemEndpoint(SystemFact):
    service_id: Identifier
    scheme: str = Field(pattern=r"^https?$")
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    method: str = Field(pattern=r"^[A-Z]+$", max_length=20)
    path: str = Field(min_length=1, max_length=2048)
    authentication_observed: bool | None = None


class SystemRole(SystemFact):
    name: str = Field(min_length=1, max_length=100)


class SystemIdentity(SystemFact):
    name: str = Field(min_length=1, max_length=200)
    identity_type: SystemIdentityType
    role_id: Identifier | None = None


class SystemPermission(SystemFact):
    subject_entity_type: SystemEntityType
    subject_entity_id: Identifier
    action: str = Field(min_length=1, max_length=100)
    resource_type: SystemEntityType
    resource_id: Identifier
    effect: PermissionEffect


class SystemCapability(SystemFact):
    subject_entity_type: SystemEntityType
    subject_entity_id: Identifier
    capability_type: CapabilityType
    resource_entity_type: SystemEntityType
    resource_entity_id: Identifier


class SystemDataObject(SystemFact):
    data_type: DataObjectType
    name: str = Field(min_length=1, max_length=200)
    resource_identifier: str = Field(min_length=1, max_length=500)
    metadata: JsonObject = Field(default_factory=dict)


class SystemTrustBoundary(SystemFact):
    source_zone: str = Field(min_length=1, max_length=200)
    target_zone: str = Field(min_length=1, max_length=200)
    boundary_type: BoundaryType


class SystemRelationship(SystemFact):
    source_entity_type: SystemEntityType
    source_entity_id: Identifier
    relationship_type: RelationshipType
    target_entity_type: SystemEntityType
    target_entity_id: Identifier


class ProcessedModelObservation(EntityModel):
    research_session_id: Identifier
    observation_id: Identifier
    build_id: Identifier
    processed_at: datetime = Field(default_factory=utc_now)


class SystemModelBuild(EntityModel):
    research_session_id: Identifier
    model_version: str = SYSTEM_MODEL_VERSION
    status: ModelBuildStatus = ModelBuildStatus.RUNNING
    started_at: datetime = Field(default_factory=utc_now)
    finished_at: datetime | None = None
    observations_processed: int = Field(default=0, ge=0)
    unsupported_observations: int = Field(default=0, ge=0)
    entities_created: int = Field(default=0, ge=0)
    entities_updated: int = Field(default=0, ge=0)
    relationships_created: int = Field(default=0, ge=0)
    relationships_updated: int = Field(default=0, ge=0)
    model_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    error: str | None = Field(default=None, max_length=3000)
