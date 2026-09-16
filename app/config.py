from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import AliasChoices, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.domain.discovery import ToolCapability


class Settings(BaseSettings):
    """Runtime configuration loaded from AEGIS_* environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="AEGIS_",
        extra="ignore",
    )

    environment: Literal["development", "test", "production"] = "development"
    database_url: str = "sqlite:///./aegis.db"
    auto_create_schema: bool = True
    log_level: str = Field(default="INFO", pattern=r"^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    executor_path: Path = Path("native/rust/target/debug/aegis-executor")
    executor_process_grace_seconds: float = Field(default=2.0, ge=0.1, le=30.0)
    policy_path: Path = Path("native/rust/target/debug/aegis-policy")
    policy_process_timeout_seconds: float = Field(default=3.0, ge=0.1, le=30.0)
    policy_max_requests_per_minute: int = Field(default=30, ge=1, le=10_000)
    policy_max_response_bytes: int = Field(default=100_000, ge=1, le=10_000_000)
    policy_max_timeout_ms: int = Field(default=10_000, ge=1, le=60_000)
    min_verification_runs: int = Field(default=1, ge=1, le=100)
    eval_target_host: str = "127.0.0.1"
    eval_target_port: int = Field(default=8001, ge=1, le=65535)
    eval_target_scheme: Literal["http", "https"] = "http"
    eval_report_directory: Path = Path("reports/evals")
    project_report_directory: Path = Path("reports/projects")
    graph_max_depth: int = Field(default=6, ge=1, le=50)
    graph_max_paths: int = Field(default=100, ge=1, le=10_000)
    graph_max_nodes: int = Field(default=10_000, ge=1, le=1_000_000)
    tool_max_concurrency: int = Field(default=2, ge=1, le=16)
    tool_max_runs_per_plan: int = Field(default=8, ge=1, le=64)
    tool_artifact_max_bytes: int = Field(default=1_000_000, ge=1_024, le=10_000_000)
    web_import_max_bytes: int = Field(default=10_000_000, ge=1_024, le=50_000_000)
    web_import_max_entries: int = Field(default=10_000, ge=1, le=100_000)
    web_import_max_request_bytes: int = Field(default=1_000_000, ge=1_024, le=10_000_000)
    web_import_max_response_bytes: int = Field(default=1_000_000, ge=1_024, le=10_000_000)
    web_import_max_html_references: int = Field(default=1_000, ge=1, le=100_000)
    web_import_max_template_records: int = Field(default=10_000, ge=1, le=100_000)
    nmap_enabled: bool = True
    ffuf_enabled: bool = True
    nuclei_enabled: bool = True
    ffuf_small_wordlist: Path = Path("app/active_web/wordlists/small.txt")
    ffuf_standard_wordlist: Path = Path("app/active_web/wordlists/standard.txt")
    nuclei_safe_template: Path = Path("app/active_web/nuclei/aegis-safe-lab.yaml")
    active_web_output_max_bytes: int = Field(default=1_000_000, ge=1_024, le=10_000_000)
    active_web_max_results: int = Field(default=2_000, ge=1, le=100_000)
    client_verification_enabled: bool = False
    client_verification_browser_executable: Path | None = None
    client_verification_navigation_timeout_ms: int = Field(default=10_000, ge=1, le=60_000)
    client_verification_max_dom_characters: int = Field(default=20_000, ge=1_000, le=200_000)
    llm_provider: Literal["fake", "anthropic", "nvidia_nim"] = "fake"
    llm_model: str = "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning"
    llm_timeout_seconds: float = Field(default=30.0, ge=1.0, le=300.0)
    llm_max_retries: int = Field(default=2, ge=0, le=3)
    llm_max_output_tokens: int = Field(default=4096, ge=256, le=64_000)
    max_hypotheses_per_run: int = Field(default=5, ge=1, le=20)
    llm_context_max_observations: int = Field(default=50, ge=1, le=500)
    llm_context_max_body_characters: int = Field(default=2000, ge=0, le=20_000)
    llm_context_max_total_characters: int = Field(default=50_000, ge=1000, le=1_000_000)
    anthropic_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("ANTHROPIC_API_KEY", "AEGIS_ANTHROPIC_API_KEY"),
    )
    nvidia_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("NVIDIA_API_KEY", "AEGIS_NVIDIA_API_KEY"),
    )
    nvidia_nim_base_url: str = "https://integrate.api.nvidia.com/v1"
    nvidia_reasoning_budget: int = Field(default=2048, ge=0, le=32_768)
    nvidia_temperature: float = Field(default=0.1, ge=0.0, le=2.0)
    planner_max_context_bytes: int = Field(default=50_000, ge=1_000, le=1_000_000)
    planner_max_entities: int = Field(default=100, ge=1, le=10_000)
    planner_max_signals: int = Field(default=50, ge=1, le=1_000)
    planner_max_history: int = Field(default=25, ge=1, le=1_000)
    planner_max_intents_per_step: int = Field(default=3, ge=1, le=10)
    research_max_steps: int = Field(default=5, ge=1, le=50)
    research_max_tool_runs: int = Field(default=10, ge=1, le=100)
    research_max_duration_seconds: float = Field(default=300.0, ge=1.0, le=3_600.0)
    strategy_max_selected_intents: int = Field(default=3, ge=1, le=10)
    controller_max_context_bytes: int = Field(default=50_000, ge=1_000, le=1_000_000)
    controller_max_entities: int = Field(default=100, ge=1, le=10_000)
    controller_max_gaps: int = Field(default=50, ge=1, le=1_000)
    controller_max_signals: int = Field(default=50, ge=1, le=1_000)
    controller_max_history: int = Field(default=25, ge=1, le=1_000)
    controller_max_hypotheses: int = Field(default=25, ge=1, le=1_000)
    controller_max_actions_per_step: int = Field(default=2, ge=1, le=10)
    controller_max_steps: int = Field(default=5, ge=1, le=100)
    controller_max_actions: int = Field(default=10, ge=1, le=1_000)
    controller_max_tool_runs: int = Field(default=10, ge=0, le=1_000)
    controller_max_requests: int = Field(default=10, ge=0, le=10_000)
    controller_max_duration_seconds: float = Field(default=300.0, ge=1.0, le=86_400)
    controller_max_llm_calls: int = Field(default=5, ge=0, le=1_000)
    controller_experimental_mode: bool = False
    controller_max_semantic_repeats: int = Field(default=3, ge=1, le=20)
    controller_allowed_capabilities: tuple[ToolCapability, ...] = (
        ToolCapability.HTTP_REQUEST,
        ToolCapability.SERVICE_DISCOVERY,
        ToolCapability.DNS_LOOKUP,
        ToolCapability.TLS_INSPECTION,
        ToolCapability.WEB_CONTENT_DISCOVERY,
        ToolCapability.TEMPLATE_ASSESSMENT,
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
