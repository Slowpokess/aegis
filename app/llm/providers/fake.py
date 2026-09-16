from collections import deque
from datetime import timedelta
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from app.domain.common import utc_now
from app.llm.base import (
    LLMGenerationMetadata,
    LLMGenerationResult,
    LLMMessage,
    LLMProviderError,
    LLMProviderErrorCode,
    LLMRequestMetadata,
    LLMTokenUsage,
)

T = TypeVar("T", bound=BaseModel)


class FakeLLMProvider:
    """Deterministic provider whose responses are supplied explicitly by the caller."""

    def __init__(
        self,
        responses: list[BaseModel | dict[str, Any] | LLMProviderError],
        *,
        model: str = "fake-hypothesis-v1",
        input_tokens: int | None = None,
        output_tokens: int | None = None,
    ) -> None:
        self._responses = deque(responses)
        self._model = model
        self._input_tokens = input_tokens
        self._output_tokens = output_tokens
        self.requests: list[tuple[list[LLMMessage], LLMRequestMetadata]] = []

    @property
    def provider_name(self) -> str:
        return "fake"

    @property
    def model_name(self) -> str:
        return self._model

    async def structured_generate(
        self,
        *,
        messages: list[LLMMessage],
        response_model: type[T],
        metadata: LLMRequestMetadata,
    ) -> LLMGenerationResult[T]:
        self.requests.append((messages, metadata))
        if not self._responses:
            raise LLMProviderError(
                LLMProviderErrorCode.PROVIDER_ERROR,
                "fake provider has no configured response",
            )
        response = self._responses.popleft()
        if isinstance(response, LLMProviderError):
            raise response
        started_at = utc_now()
        try:
            output = response_model.model_validate(response)
        except ValidationError as error:
            raise LLMProviderError(
                LLMProviderErrorCode.STRUCTURED_OUTPUT_ERROR,
                "fake provider response failed structured validation",
            ) from error
        completed_at = started_at + timedelta(milliseconds=1)
        total = None
        if self._input_tokens is not None and self._output_tokens is not None:
            total = self._input_tokens + self._output_tokens
        return LLMGenerationResult[T](
            output=output,
            metadata=LLMGenerationMetadata(
                provider=self.provider_name,
                model=self.model_name,
                provider_request_id=f"FAKE-{metadata.run_id}",
                prompt_version=metadata.prompt_version,
                started_at=started_at,
                completed_at=completed_at,
                latency_ms=1,
                usage=LLMTokenUsage(
                    input_tokens=self._input_tokens,
                    output_tokens=self._output_tokens,
                    total_tokens=total,
                ),
                finish_reason="structured",
                attempts=1,
            ),
        )
