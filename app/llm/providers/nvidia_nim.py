import asyncio
import json
from datetime import datetime
from time import monotonic
from typing import Any, TypeVar
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ValidationError

from app.domain.common import utc_now
from app.llm.base import (
    LLMGenerationMetadata,
    LLMGenerationResult,
    LLMMessage,
    LLMProviderError,
    LLMProviderErrorCode,
    LLMRequestMetadata,
    LLMRole,
    LLMTokenUsage,
)

T = TypeVar("T", bound=BaseModel)


class NvidiaNIMLLMProvider:
    """OpenAI-compatible NVIDIA NIM adapter with strict local validation."""

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        base_url: str = "https://integrate.api.nvidia.com/v1",
        timeout_seconds: float = 30.0,
        max_retries: int = 2,
        max_output_tokens: int = 4096,
        reasoning_budget: int = 2048,
        temperature: float = 0.1,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not api_key:
            raise ValueError("NVIDIA API key is required")
        parsed = urlsplit(base_url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("NVIDIA NIM base URL must be a credential-free HTTPS URL")
        self._api_key = api_key
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._timeout_seconds = timeout_seconds
        self._max_retries = max_retries
        self._max_output_tokens = max_output_tokens
        self._reasoning_budget = min(reasoning_budget, max_output_tokens)
        self._temperature = temperature
        self._client = client

    @property
    def provider_name(self) -> str:
        return "nvidia_nim"

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
        if not any(message.role is LLMRole.SYSTEM for message in messages):
            raise LLMProviderError(
                LLMProviderErrorCode.INVALID_RESPONSE,
                "NVIDIA NIM request requires a system message",
            )
        schema = response_model.model_json_schema()
        payload = {
            "model": self._model,
            "messages": [
                {"role": message.role.value.lower(), "content": message.content}
                for message in messages
            ],
            "temperature": self._temperature,
            "top_p": 0.95,
            "max_tokens": self._max_output_tokens,
            "stream": False,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": response_model.__name__,
                    "strict": True,
                    "schema": schema,
                },
            },
            "chat_template_kwargs": {"enable_thinking": True, "low_effort": True},
            "reasoning_budget": self._reasoning_budget,
        }
        started_at = utc_now()
        started_clock = monotonic()
        response, attempts = await self._post_with_retries(payload)
        return self._parse_response(
            response,
            response_model,
            metadata,
            started_at,
            utc_now(),
            round((monotonic() - started_clock) * 1000),
            attempts,
        )

    async def _post_with_retries(self, payload: dict[str, Any]) -> tuple[httpx.Response, int]:
        owns_client = self._client is None
        client = self._client or httpx.AsyncClient(timeout=self._timeout_seconds)
        try:
            for attempt in range(1, self._max_retries + 2):
                try:
                    response = await client.post(
                        f"{self._base_url}/chat/completions",
                        headers={
                            "authorization": f"Bearer {self._api_key}",
                            "content-type": "application/json",
                        },
                        json=payload,
                    )
                except httpx.TimeoutException as error:
                    if attempt <= self._max_retries:
                        await asyncio.sleep(0.1 * attempt)
                        continue
                    raise LLMProviderError(
                        LLMProviderErrorCode.TIMEOUT,
                        "NVIDIA NIM request timed out",
                        attempts=attempt,
                    ) from error
                except httpx.HTTPError as error:
                    if attempt <= self._max_retries:
                        await asyncio.sleep(0.1 * attempt)
                        continue
                    raise LLMProviderError(
                        LLMProviderErrorCode.PROVIDER_ERROR,
                        "NVIDIA NIM transport failed",
                        attempts=attempt,
                    ) from error
                if response.status_code in {408, 429} or response.status_code >= 500:
                    if attempt <= self._max_retries:
                        await asyncio.sleep(0.1 * attempt)
                        continue
                if response.status_code in {401, 403}:
                    raise LLMProviderError(
                        LLMProviderErrorCode.AUTHENTICATION_ERROR,
                        "NVIDIA NIM authentication failed",
                        attempts=attempt,
                    )
                if response.status_code == 429:
                    raise LLMProviderError(
                        LLMProviderErrorCode.RATE_LIMIT,
                        "NVIDIA NIM rate limit exceeded",
                        attempts=attempt,
                    )
                if response.is_error:
                    raise LLMProviderError(
                        LLMProviderErrorCode.PROVIDER_ERROR,
                        f"NVIDIA NIM API returned HTTP {response.status_code}",
                        attempts=attempt,
                    )
                return response, attempt
        finally:
            if owns_client:
                await client.aclose()
        raise LLMProviderError(LLMProviderErrorCode.PROVIDER_ERROR, "NVIDIA NIM request failed")

    def _parse_response(
        self,
        response: httpx.Response,
        response_model: type[T],
        request_metadata: LLMRequestMetadata,
        started_at: datetime,
        completed_at: datetime,
        latency_ms: int,
        attempts: int,
    ) -> LLMGenerationResult[T]:
        try:
            payload = response.json()
            choice = payload["choices"][0]
            content = choice["message"]["content"]
            if not isinstance(content, str):
                raise ValueError("completion content is not text")
            output = response_model.model_validate(json.loads(content))
        except (IndexError, KeyError, TypeError, ValueError, ValidationError) as error:
            raise LLMProviderError(
                LLMProviderErrorCode.STRUCTURED_OUTPUT_ERROR,
                "NVIDIA NIM response failed structured validation",
                attempts=attempts,
            ) from error
        usage = payload.get("usage", {})
        input_tokens = usage.get("prompt_tokens")
        output_tokens = usage.get("completion_tokens")
        total_tokens = usage.get("total_tokens")
        return LLMGenerationResult[T](
            output=output,
            metadata=LLMGenerationMetadata(
                provider=self.provider_name,
                model=self.model_name,
                provider_request_id=payload.get("id"),
                prompt_version=request_metadata.prompt_version,
                started_at=started_at,
                completed_at=completed_at,
                latency_ms=latency_ms,
                usage=LLMTokenUsage(
                    input_tokens=input_tokens if isinstance(input_tokens, int) else None,
                    output_tokens=output_tokens if isinstance(output_tokens, int) else None,
                    total_tokens=total_tokens if isinstance(total_tokens, int) else None,
                ),
                finish_reason=choice.get("finish_reason"),
                attempts=attempts,
            ),
        )
