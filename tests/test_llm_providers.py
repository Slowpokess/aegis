import json
from uuid import uuid4

import httpx
import pytest
from pydantic import BaseModel, ConfigDict, Field

from app.llm.base import (
    LLMMessage,
    LLMProviderError,
    LLMProviderErrorCode,
    LLMRequestMetadata,
    LLMRole,
)
from app.llm.providers.anthropic import AnthropicLLMProvider
from app.llm.providers.fake import FakeLLMProvider
from app.llm.providers.nvidia_nim import NvidiaNIMLLMProvider


class SampleOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    value: str = Field(min_length=1)


def metadata() -> LLMRequestMetadata:
    return LLMRequestMetadata(
        run_id=uuid4(), prompt_version="hypothesis-v1", context_sha256="a" * 64
    )


def messages() -> list[LLMMessage]:
    return [
        LLMMessage(role=LLMRole.SYSTEM, content="system"),
        LLMMessage(role=LLMRole.USER, content="user"),
    ]


@pytest.mark.asyncio
async def test_fake_provider_is_deterministic_and_preserves_reported_usage() -> None:
    provider = FakeLLMProvider(
        [{"value": "fixed"}], input_tokens=11, output_tokens=7
    )

    result = await provider.structured_generate(
        messages=messages(), response_model=SampleOutput, metadata=metadata()
    )

    assert result.output.value == "fixed"
    assert result.metadata.provider == "fake"
    assert result.metadata.usage.total_tokens == 18
    assert len(provider.requests) == 1


@pytest.mark.asyncio
async def test_fake_provider_rejects_malformed_structured_response() -> None:
    provider = FakeLLMProvider([{"unexpected": True}])

    with pytest.raises(LLMProviderError) as captured:
        await provider.structured_generate(
            messages=messages(), response_model=SampleOutput, metadata=metadata()
        )

    assert captured.value.code is LLMProviderErrorCode.STRUCTURED_OUTPUT_ERROR


@pytest.mark.asyncio
async def test_fake_provider_returns_explicit_typed_timeout() -> None:
    provider = FakeLLMProvider(
        [LLMProviderError(LLMProviderErrorCode.TIMEOUT, "fixture timeout", attempts=2)]
    )

    with pytest.raises(LLMProviderError) as captured:
        await provider.structured_generate(
            messages=messages(), response_model=SampleOutput, metadata=metadata()
        )

    assert captured.value.code is LLMProviderErrorCode.TIMEOUT
    assert captured.value.attempts == 2


@pytest.mark.asyncio
async def test_anthropic_adapter_uses_structured_output_and_normalizes_metadata() -> None:
    captured_request: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured_request.update(json.loads(request.content))
        return httpx.Response(
            200,
            headers={"request-id": "req-provider"},
            json={
                "id": "msg-provider",
                "content": [{"type": "text", "text": '{"value":"structured"}'}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 12, "output_tokens": 4},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = AnthropicLLMProvider(
            api_key="test-key",
            model="claude-haiku-4-5-20251001",
            client=client,
        )
        result = await provider.structured_generate(
            messages=messages(), response_model=SampleOutput, metadata=metadata()
        )

    assert result.output.value == "structured"
    assert result.metadata.provider_request_id == "req-provider"
    assert result.metadata.usage.total_tokens == 16
    assert captured_request["output_config"] == {
        "format": {
            "type": "json_schema",
            "schema": {
                "additionalProperties": False,
                "properties": {"value": {"title": "Value", "type": "string"}},
                "required": ["value"],
                "title": "SampleOutput",
                "type": "object",
            },
        }
    }


@pytest.mark.asyncio
async def test_anthropic_timeout_is_typed_and_bounded() -> None:
    attempts = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        raise httpx.ConnectTimeout("timeout")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = AnthropicLLMProvider(
            api_key="test-key", model="test-model", max_retries=1, client=client
        )
        with pytest.raises(LLMProviderError) as captured:
            await provider.structured_generate(
                messages=messages(), response_model=SampleOutput, metadata=metadata()
            )

    assert captured.value.code is LLMProviderErrorCode.TIMEOUT
    assert captured.value.attempts == 2
    assert attempts == 2


@pytest.mark.asyncio
async def test_nvidia_nim_adapter_uses_fixed_endpoint_and_structured_output() -> None:
    captured_request: dict[str, object] = {}
    captured_authorization = ""

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal captured_authorization
        captured_request.update(json.loads(request.content))
        captured_authorization = request.headers["authorization"]
        assert request.url == "https://integrate.api.nvidia.com/v1/chat/completions"
        return httpx.Response(
            200,
            json={
                "id": "nim-request",
                "choices": [
                    {
                        "message": {"role": "assistant", "content": '{"value":"nim"}'},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 20,
                    "completion_tokens": 5,
                    "total_tokens": 25,
                },
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = NvidiaNIMLLMProvider(
            api_key="test-nvidia-key",
            model="nvidia/nemotron-3-super-120b-a12b",
            client=client,
        )
        result = await provider.structured_generate(
            messages=messages(), response_model=SampleOutput, metadata=metadata()
        )

    assert captured_authorization == "Bearer test-nvidia-key"
    assert captured_request["model"] == "nvidia/nemotron-3-super-120b-a12b"
    assert captured_request["stream"] is False
    assert captured_request["temperature"] == 0.1
    assert captured_request["response_format"] == {
        "type": "json_schema",
        "json_schema": {
            "name": "SampleOutput",
            "strict": True,
            "schema": SampleOutput.model_json_schema(),
        },
    }
    assert result.output.value == "nim"
    assert result.metadata.provider == "nvidia_nim"
    assert result.metadata.usage.total_tokens == 25


def test_nvidia_nim_adapter_rejects_unsafe_endpoint_and_empty_key() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        NvidiaNIMLLMProvider(api_key="key", model="model", base_url="http://example.test/v1")
    with pytest.raises(ValueError, match="API key"):
        NvidiaNIMLLMProvider(api_key="", model="model")
