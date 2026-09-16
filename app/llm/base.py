from datetime import datetime
from enum import StrEnum
from typing import Generic, Protocol, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from app.domain.common import Identifier

T = TypeVar("T", bound=BaseModel)


class LLMModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class LLMRole(StrEnum):
    SYSTEM = "SYSTEM"
    USER = "USER"


class LLMMessage(LLMModel):
    role: LLMRole
    content: str = Field(min_length=1)


class LLMRequestMetadata(LLMModel):
    run_id: Identifier
    prompt_version: str = Field(min_length=1, max_length=100)
    context_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class LLMTokenUsage(LLMModel):
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    total_tokens: int | None = Field(default=None, ge=0)


class LLMGenerationMetadata(LLMModel):
    provider: str
    model: str
    provider_request_id: str | None = None
    prompt_version: str
    started_at: datetime
    completed_at: datetime
    latency_ms: int = Field(ge=0)
    usage: LLMTokenUsage = Field(default_factory=LLMTokenUsage)
    finish_reason: str | None = None
    attempts: int = Field(ge=1)


class LLMGenerationResult(LLMModel, Generic[T]):
    output: T
    metadata: LLMGenerationMetadata


class LLMProviderErrorCode(StrEnum):
    AUTHENTICATION_ERROR = "AUTHENTICATION_ERROR"
    RATE_LIMIT = "RATE_LIMIT"
    TIMEOUT = "TIMEOUT"
    INVALID_RESPONSE = "INVALID_RESPONSE"
    STRUCTURED_OUTPUT_ERROR = "STRUCTURED_OUTPUT_ERROR"
    PROVIDER_ERROR = "PROVIDER_ERROR"


class LLMProviderError(RuntimeError):
    def __init__(
        self,
        code: LLMProviderErrorCode,
        message: str,
        *,
        attempts: int = 1,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.attempts = attempts


class LLMProvider(Protocol):
    @property
    def provider_name(self) -> str: ...

    @property
    def model_name(self) -> str: ...

    async def structured_generate(
        self,
        *,
        messages: list[LLMMessage],
        response_model: type[T],
        metadata: LLMRequestMetadata,
    ) -> LLMGenerationResult[T]: ...
