import hashlib
import json
from datetime import datetime
from enum import StrEnum

from pydantic import Field

from app.domain.common import DomainModel, EntityModel, Identifier, utc_now
from app.domain.discovery import ToolCapability, ToolErrorCode, ToolRunStatus

ACTIVE_WEB_ASSESSMENT_VERSION = "active-web-assessment-v1"
FFUF_PARSER_VERSION = "ffuf-parser-v1"
NUCLEI_PARSER_VERSION = "nuclei-parser-v1"


class ActiveWebProfile(StrEnum):
    WEB_CONTENT_SMALL = "web_content_small"
    WEB_CONTENT_STANDARD = "web_content_standard"
    SAFE_TEMPLATES = "safe_templates"


class TemplatePolicyClass(StrEnum):
    PASSIVE = "PASSIVE"
    SAFE_ACTIVE = "SAFE_ACTIVE"
    RESTRICTED = "RESTRICTED"


class FfufResultRecord(DomainModel):
    url: str = Field(min_length=1, max_length=4096)
    status_code: int = Field(ge=100, le=599)
    content_length: int = Field(default=0, ge=0)
    content_words: int = Field(default=0, ge=0)
    content_lines: int = Field(default=0, ge=0)
    redirect_location: str | None = Field(default=None, max_length=4096)
    content_type: str | None = Field(default=None, max_length=300)


class ActiveWebRunResult(DomainModel):
    assessment_version: str = ACTIVE_WEB_ASSESSMENT_VERSION
    research_session_id: Identifier
    web_resource_ids: tuple[Identifier, ...]
    capability: ToolCapability
    tool_run_id: Identifier
    tool_id: str
    tool_version: str | None
    profile: ActiveWebProfile
    status: ToolRunStatus
    policy_allowed: bool
    policy_reason: str
    estimated_requests: int = Field(ge=0)
    actual_requests: int | None = Field(default=None, ge=0)
    timeout_seconds: float = Field(ge=0)
    artifact_ids: tuple[Identifier, ...] = ()
    observation_ids: tuple[Identifier, ...] = ()
    new_resource_count: int = Field(default=0, ge=0)
    deduplicated_resource_count: int = Field(default=0, ge=0)
    candidate_count: int = Field(default=0, ge=0)
    finding_delta: int = 0
    surface_hash_before: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    surface_hash_after: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    system_model_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    attack_graph_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    error_code: ToolErrorCode | None = None
    error: str | None = None


class ActiveWebPreview(DomainModel):
    assessment_version: str = ACTIVE_WEB_ASSESSMENT_VERSION
    research_session_id: Identifier
    web_resource_ids: tuple[Identifier, ...]
    capability: ToolCapability
    tool: str
    profile: ActiveWebProfile
    target: str
    estimated_requests: int = Field(ge=0)
    timeout_seconds: float = Field(gt=0)
    max_concurrency: int = Field(ge=1)
    policy_allowed: bool
    policy_reason: str
    approval_required: bool
    wordlist_id: str | None = None
    wordlist_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    word_count: int | None = Field(default=None, ge=0)
    template_inventory_sha256: str | None = Field(
        default=None, pattern=r"^[a-f0-9]{64}$"
    )
    template_ids: tuple[str, ...] = ()
    template_policy_class: TemplatePolicyClass | None = None


class WebCandidateProvenance(EntityModel):
    research_session_id: Identifier
    web_template_candidate_id: Identifier
    web_resource_id: Identifier
    tool_artifact_id: Identifier
    observation_id: Identifier
    tool_run_id: Identifier
    source: str
    created_at: datetime = Field(default_factory=utc_now)


def semantic_config_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()
