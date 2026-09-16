from enum import StrEnum

from pydantic import Field

from app.domain.common import EntityModel, JsonObject


class AssetKind(StrEnum):
    APPLICATION = "APPLICATION"
    SERVICE = "SERVICE"
    HOST = "HOST"
    API = "API"
    DATA_STORE = "DATA_STORE"
    AI_SYSTEM = "AI_SYSTEM"
    OTHER = "OTHER"


class Asset(EntityModel):
    name: str = Field(min_length=1, max_length=200)
    kind: AssetKind
    description: str | None = Field(default=None, max_length=2000)
    metadata: JsonObject = Field(default_factory=dict)
