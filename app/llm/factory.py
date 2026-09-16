from app.config import Settings
from app.llm.base import LLMProvider
from app.llm.providers import AnthropicLLMProvider, FakeLLMProvider, NvidiaNIMLLMProvider
from app.reasoning.schemas import HypothesisBatch
from pydantic import BaseModel


def create_llm_provider(
    settings: Settings,
    *,
    fake_response: BaseModel | None = None,
) -> LLMProvider:
    if settings.llm_provider == "fake":
        response = fake_response or HypothesisBatch(hypotheses=[])
        return FakeLLMProvider([response], model="fake-hypothesis-v1")
    if settings.llm_provider == "anthropic":
        if settings.anthropic_api_key is None:
            raise ValueError("ANTHROPIC_API_KEY is required for the Anthropic provider")
        return AnthropicLLMProvider(
            api_key=settings.anthropic_api_key.get_secret_value(),
            model=settings.llm_model,
            timeout_seconds=settings.llm_timeout_seconds,
            max_retries=settings.llm_max_retries,
            max_output_tokens=settings.llm_max_output_tokens,
        )
    if settings.llm_provider == "nvidia_nim":
        if settings.nvidia_api_key is None:
            raise ValueError("NVIDIA_API_KEY is required for the NVIDIA NIM provider")
        return NvidiaNIMLLMProvider(
            api_key=settings.nvidia_api_key.get_secret_value(),
            model=settings.llm_model,
            base_url=settings.nvidia_nim_base_url,
            timeout_seconds=settings.llm_timeout_seconds,
            max_retries=settings.llm_max_retries,
            max_output_tokens=settings.llm_max_output_tokens,
            reasoning_budget=settings.nvidia_reasoning_budget,
            temperature=settings.nvidia_temperature,
        )
    raise ValueError(f"unsupported LLM provider: {settings.llm_provider}")
