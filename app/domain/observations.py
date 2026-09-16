from datetime import datetime
from enum import StrEnum

from pydantic import Field

from app.domain.common import (
    EntityModel,
    Identifier,
    JsonObject,
    TrustClassification,
    utc_now,
)


class ObservationSource(StrEnum):
    HTTP = "HTTP"
    SOURCE_CODE = "SOURCE_CODE"
    TOOL = "TOOL"
    MANUAL = "MANUAL"
    RUNTIME = "RUNTIME"


class Observation(EntityModel):
    asset_id: Identifier
    research_session_id: Identifier | None = None
    request_id: str | None = Field(default=None, max_length=128)
    evidence_id: Identifier | None = None
    tool_artifact_id: Identifier | None = None
    source: ObservationSource
    raw_data: JsonObject
    normalized_data: JsonObject = Field(default_factory=dict)
    trust: TrustClassification = TrustClassification.UNKNOWN
    normalized_data_trust: TrustClassification = TrustClassification.TRUSTED
    timestamp: datetime = Field(default_factory=utc_now)
