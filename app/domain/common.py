from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

Identifier = UUID
JsonObject = dict[str, Any]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class DomainModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, use_enum_values=False)


class FactClassification(StrEnum):
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"


class TrustClassification(StrEnum):
    TRUSTED = "TRUSTED"
    UNTRUSTED = "UNTRUSTED"
    UNKNOWN = "UNKNOWN"


class Provenance(DomainModel):
    source_type: str = Field(min_length=1, max_length=100)
    source_reference: str = Field(min_length=1, max_length=2048)
    collector: str | None = Field(default=None, max_length=200)
    collected_at: datetime = Field(default_factory=utc_now)
    classification: FactClassification = FactClassification.OBSERVED
    metadata: JsonObject = Field(default_factory=dict)


class EntityModel(DomainModel):
    id: UUID = Field(default_factory=uuid4)
    provenance: Provenance
