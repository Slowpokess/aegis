import asyncio
import json
from datetime import datetime
from time import monotonic
from typing import Any, TypeVar

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

_UNSUPPORTED_SCHEMA_KEYS = {
    "default",
    "exclusiveMaximum",
    "exclusiveMinimum",
    "format",
    "maxItems",
    "maxLength",
    "maximum",
    "minItems",
    "minLength",
    "minimum",
    "multipleOf",
    "pattern",
    "uniqueItems",
}


def _anthropic_schema(value: Any) -> Any:
    if isinstance(value, dict):
        transformed = {
            key: _anthropic_schema(item)
            for key, item in value.items()
            if key not in _UNSUPPORTED_SCHEMA_KEYS
        }
        if transformed.get("type") == "object":
            transformed["additionalProperties"] = False
        return transformed
    if isinstance(value, list):
        return [_anthropic_schema(item) for item in value]
    return value


class AnthropicLLMProvider:
    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        timeout_seconds: float = 30.0,
        max_retries: int = 2,
        max_output_tokens: int = 4096,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not api_key:
            raise ValueError("Anthropic API key is required")
        self._api_key = api_key
        self._model = model
        self._timeout_seconds = timeout_seconds
        self._max_retries = max_retries
        self._max_output_tokens = max_output_tokens
        self._client = client

    @property
    def provider_name(self) -> str:
        return "anthropic"

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
        system_messages = [message.content for message in messages if message.role is LLMRole.SYSTEM]
        user_messages = [message.content for message in messages if message.role is LLMRole.USER]
        if not system_messages or not user_messages:
            raise LLMProviderError(
                LLMProviderErrorCode.INVALID_RESPONSE,
                "Anthropic request requires system and user messages",
            )
        payload = {
            "model": self._model,
            "max_tokens": self._max_output_tokens,
            "system": "\n\n".join(system_messages),
            "messages": [{"role": "user", "content": content} for content in user_messages],
            "output_config": {
                "format": {
                    "type": "json_schema",
                    "schema": _anthropic_schema(response_model.model_json_schema()),
                }
            },
        }
        started_at = utc_now()
        started_clock = monotonic()
        response, attempts = await self._post_with_retries(payload)
        completed_at = utc_now()
        return self._parse_response(
            response,
            response_model,
            metadata,
            started_at,
            completed_at,
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
                        "https://api.anthropic.com/v1/messages",
                        headers={
                            "anthropic-version": "2023-06-01",
                            "content-type": "application/json",
                            "x-api-key": self._api_key,
                        },
                        json=payload,
                    )
                except httpx.TimeoutException as error:
                    if attempt <= self._max_retries:
                        await asyncio.sleep(0.1 * attempt)
                        continue
                    raise LLMProviderError(
                        LLMProviderErrorCode.TIMEOUT,
                        "Anthropic request timed out",
                        attempts=attempt,
                    ) from error
                except httpx.HTTPError as error:
                    if attempt <= self._max_retries:
                        await asyncio.sleep(0.1 * attempt)
                        continue
                    raise LLMProviderError(
                        LLMProviderErrorCode.PROVIDER_ERROR,
                        "Anthropic transport failed",
                        attempts=attempt,
                    ) from error
                if response.status_code in {408, 429} or response.status_code >= 500:
                    if attempt <= self._max_retries:
                        await asyncio.sleep(0.1 * attempt)
                        continue
                if response.status_code == 401:
                    raise LLMProviderError(
                        LLMProviderErrorCode.AUTHENTICATION_ERROR,
                        "Anthropic authentication failed",
                        attempts=attempt,
                    )
                if response.status_code == 429:
                    raise LLMProviderError(
                        LLMProviderErrorCode.RATE_LIMIT,
                        "Anthropic rate limit exceeded",
                        attempts=attempt,
                    )
                if response.is_error:
                    raise LLMProviderError(
                        LLMProviderErrorCode.PROVIDER_ERROR,
                        f"Anthropic API returned HTTP {response.status_code}",
                        attempts=attempt,
                    )
                return response, attempt
        finally:
            if owns_client:
                await client.aclose()
        raise LLMProviderError(LLMProviderErrorCode.PROVIDER_ERROR, "Anthropic request failed")

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
            text_blocks = [
                block["text"]
                for block in payload["content"]
                if block.get("type") == "text" and isinstance(block.get("text"), str)
            ]
            if len(text_blocks) != 1:
                raise ValueError("expected exactly one structured text block")
            structured = json.loads(text_blocks[0])
            output = response_model.model_validate(structured)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError, ValidationError) as error:
            raise LLMProviderError(
                LLMProviderErrorCode.STRUCTURED_OUTPUT_ERROR,
                "Anthropic response failed structured validation",
                attempts=attempts,
            ) from error
        usage = payload.get("usage", {})
        input_tokens = usage.get("input_tokens")
        output_tokens = usage.get("output_tokens")
        total_tokens = None
        if isinstance(input_tokens, int) and isinstance(output_tokens, int):
            total_tokens = input_tokens + output_tokens
        return LLMGenerationResult[T](
            output=output,
            metadata=LLMGenerationMetadata(
                provider=self.provider_name,
                model=self.model_name,
                provider_request_id=response.headers.get("request-id") or payload.get("id"),
                prompt_version=request_metadata.prompt_version,
                started_at=started_at,
                completed_at=completed_at,
                latency_ms=latency_ms,
                usage=LLMTokenUsage(
                    input_tokens=input_tokens if isinstance(input_tokens, int) else None,
                    output_tokens=output_tokens if isinstance(output_tokens, int) else None,
                    total_tokens=total_tokens,
                ),
                finish_reason=payload.get("stop_reason"),
                attempts=attempts,
            ),
        )
