from datetime import datetime

from pydantic import Field, field_validator

from app.domain.common import DomainModel, EntityModel, Identifier, utc_now
from app.domain.experiments import ExperimentRole


class HTTPRequestRecord(DomainModel):
    method: str = Field(min_length=1, max_length=20)
    url: str = Field(min_length=1, max_length=4096)
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None


class HTTPResponseRecord(DomainModel):
    status_code: int = Field(ge=100, le=599)
    headers: dict[str, str] = Field(default_factory=dict)
    body: str
    body_base64: str | None = None
    body_bytes: int | None = Field(default=None, ge=0)
    effective_url: str | None = None
    elapsed_ms: float = Field(ge=0)
    truncated: bool = False


class Evidence(EntityModel):
    experiment_id: Identifier | None = None
    experiment_role: ExperimentRole | None = None
    research_session_id: Identifier | None = None
    request_id: str | None = Field(default=None, max_length=128)
    request: HTTPRequestRecord
    response: HTTPResponseRecord
    executor: str | None = None
    executor_version: str | None = None
    protocol_version: int | None = Field(default=None, ge=1)
    timestamp: datetime = Field(default_factory=utc_now)
    integrity_hash: str = Field(pattern=r"^[a-f0-9]{64}$")

    @field_validator("integrity_hash")
    @classmethod
    def normalize_hash(cls, value: str) -> str:
        return value.lower()
