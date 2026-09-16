from pydantic import Field

from app.domain.common import EntityModel, Identifier, JsonObject, TrustClassification


class Identity(EntityModel):
    asset_id: Identifier
    name: str = Field(min_length=1, max_length=200)
    roles: list[str] = Field(default_factory=list)
    attributes: JsonObject = Field(default_factory=dict)
    trust: TrustClassification = TrustClassification.UNKNOWN
