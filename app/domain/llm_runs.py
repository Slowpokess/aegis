from datetime import datetime
from enum import StrEnum

from pydantic import Field, model_validator

from app.domain.common import EntityModel, Identifier, JsonObject, utc_now


class LLMRunStatus(StrEnum):
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class LLMRunPurpose(StrEnum):
    HYPOTHESIS_GENERATION = "HYPOTHESIS_GENERATION"
    EXPERIMENT_GENERATION = "EXPERIMENT_GENERATION"


class LLMRun(EntityModel):
    research_session_id: Identifier
    provider: str = Field(min_length=1, max_length=100)
    model: str = Field(min_length=1, max_length=200)
    prompt_version: str = Field(min_length=1, max_length=100)
    purpose: LLMRunPurpose = LLMRunPurpose.HYPOTHESIS_GENERATION
    provider_request_id: str | None = Field(default=None, max_length=200)
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None
    status: LLMRunStatus = LLMRunStatus.RUNNING
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    total_tokens: int | None = Field(default=None, ge=0)
    latency_ms: int | None = Field(default=None, ge=0)
    attempts: int = Field(default=0, ge=0)
    generated_count: int = Field(default=0, ge=0)
    accepted_count: int = Field(default=0, ge=0)
    rejected_count: int = Field(default=0, ge=0)
    error_code: str | None = Field(default=None, max_length=100)
    context_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    context_observation_ids: list[Identifier] = Field(default_factory=list)
    validation_rejections: list[JsonObject] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_completion(self) -> "LLMRun":
        if self.status is LLMRunStatus.RUNNING and self.completed_at is not None:
            raise ValueError("RUNNING LLM run cannot have completed_at")
        if self.status is not LLMRunStatus.RUNNING and self.completed_at is None:
            raise ValueError("finished LLM run requires completed_at")
        if (
            self.input_tokens is not None
            and self.output_tokens is not None
            and self.total_tokens is not None
            and self.total_tokens != self.input_tokens + self.output_tokens
        ):
            raise ValueError("total_tokens must equal reported input_tokens plus output_tokens")
        return self
