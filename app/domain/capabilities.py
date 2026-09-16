from pydantic import Field

from app.domain.common import EntityModel, Identifier, JsonObject


class Capability(EntityModel):
    asset_id: Identifier
    identity_id: Identifier | None = None
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    constraints: JsonObject = Field(default_factory=dict)
