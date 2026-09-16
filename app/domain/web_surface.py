import hashlib
import json
from datetime import datetime
from enum import StrEnum

from pydantic import Field, model_validator

from app.domain.common import (
    DomainModel,
    EntityModel,
    FactClassification,
    Identifier,
    utc_now,
)

WEB_SURFACE_VERSION = "web-surface-v1"
BURP_PARSER_VERSION = "burp-export-parser-v1"
TEMPLATE_ASSESSMENT_PARSER_VERSION = "template-assessment-parser-v1"


class ContentSource(StrEnum):
    TRAFFIC = "TRAFFIC"
    HTTP_EXECUTOR = "HTTP_EXECUTOR"
    HTML_LINK = "HTML_LINK"
    HTML_RESOURCE = "HTML_RESOURCE"
    HTML_FORM = "HTML_FORM"
    TEMPLATE_RESULT = "TEMPLATE_RESULT"
    FFUF_DISCOVERY = "FFUF_DISCOVERY"
    NUCLEI_ASSESSMENT = "NUCLEI_ASSESSMENT"


class WebResourceType(StrEnum):
    PAGE = "PAGE"
    API_ROUTE = "API_ROUTE"
    STATIC_RESOURCE = "STATIC_RESOURCE"
    DIRECTORY = "DIRECTORY"
    REDIRECT = "REDIRECT"
    FORM_TARGET = "FORM_TARGET"
    UNKNOWN = "UNKNOWN"


class WebParameterLocation(StrEnum):
    QUERY = "QUERY"
    PATH = "PATH"
    FORM_FIELD = "FORM_FIELD"
    BODY_FIELD = "BODY_FIELD"
    HEADER_METADATA = "HEADER_METADATA"


class AssessmentSeverity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class WebCandidateClassification(StrEnum):
    TOOL_REPORTED = "TOOL_REPORTED"


class ParameterDescriptor(DomainModel):
    name: str = Field(min_length=1, max_length=300)
    location: WebParameterLocation


class WebTrafficRecord(DomainModel):
    exchange_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    url: str = Field(min_length=1, max_length=4096)
    scheme: str = Field(pattern=r"^https?$")
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    method: str = Field(pattern=r"^[A-Z]+$", max_length=20)
    path: str = Field(min_length=1, max_length=2048)
    status_code: int = Field(ge=100, le=599)
    mime_type: str | None = Field(default=None, max_length=200)
    request_headers: dict[str, str] = Field(default_factory=dict)
    response_headers: dict[str, str] = Field(default_factory=dict)
    query_parameter_names: tuple[str, ...] = ()
    body_parameter_names: tuple[str, ...] = ()
    request_content_type: str | None = Field(default=None, max_length=300)
    request_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    response_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    response_body: str | None = None
    captured_at: datetime | None = None


class DiscoveredContent(DomainModel):
    semantic_key: str = Field(pattern=r"^[a-f0-9]{64}$")
    url: str = Field(min_length=1, max_length=4096)
    scheme: str = Field(pattern=r"^https?$")
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    method: str = Field(pattern=r"^[A-Z]+$", max_length=20)
    path: str = Field(min_length=1, max_length=2048)
    resource_type: WebResourceType
    source: ContentSource
    observed_status_code: int | None = Field(default=None, ge=100, le=599)
    content_type: str | None = Field(default=None, max_length=300)
    parameter_names: tuple[ParameterDescriptor, ...] = ()
    exchange_ids: tuple[str, ...] = ()

    @model_validator(mode="after")
    def traffic_content_has_exchange(self) -> "DiscoveredContent":
        if self.source is ContentSource.TRAFFIC and not self.exchange_ids:
            raise ValueError("traffic-derived content requires exchange lineage")
        return self


class TemplateAssessment(DomainModel):
    assessment_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    template_id: str = Field(min_length=1, max_length=300)
    template_name: str = Field(min_length=1, max_length=500)
    matcher_name: str | None = Field(default=None, max_length=300)
    matched_url: str = Field(min_length=1, max_length=4096)
    severity: AssessmentSeverity | None = None
    assessment_type: str | None = Field(default=None, max_length=100)
    tool_metadata: dict[str, object] = Field(default_factory=dict)
    observed_at: datetime | None = None
    raw_line_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    candidate_only: bool = True

    @model_validator(mode="after")
    def cannot_become_finding(self) -> "TemplateAssessment":
        if not self.candidate_only:
            raise ValueError("template assessments are candidate signals, not Findings")
        return self


class WebSurfaceIntake(DomainModel):
    version: str = WEB_SURFACE_VERSION
    traffic: tuple[WebTrafficRecord, ...]
    content: tuple[DiscoveredContent, ...]
    assessments: tuple[TemplateAssessment, ...]
    input_entries: int = Field(ge=0)
    ignored_out_of_scope: int = Field(ge=0)
    redacted_sensitive_fields: int = Field(ge=0)
    created_at: datetime = Field(default_factory=utc_now)


class WebResource(EntityModel):
    research_session_id: Identifier
    canonical_key: str = Field(min_length=1, max_length=4096)
    scheme: str = Field(pattern=r"^https?$")
    host: str = Field(min_length=1, max_length=253)
    effective_port: int = Field(ge=1, le=65535)
    method: str = Field(pattern=r"^[A-Z]+$", max_length=20)
    path: str = Field(min_length=1, max_length=2048)
    resource_type: WebResourceType
    latest_status_code: int | None = Field(default=None, ge=100, le=599)
    content_type: str | None = Field(default=None, max_length=300)
    classification: FactClassification
    system_endpoint_id: Identifier | None = None
    first_seen: datetime = Field(default_factory=utc_now)
    last_seen: datetime = Field(default_factory=utc_now)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def valid_times(self) -> "WebResource":
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen cannot precede first_seen")
        return self


class WebResourceProvenance(EntityModel):
    research_session_id: Identifier
    web_resource_id: Identifier
    observation_id: Identifier
    tool_artifact_id: Identifier | None = None
    evidence_id: Identifier | None = None
    source: ContentSource
    classification: FactClassification
    observed_at: datetime
    created_at: datetime = Field(default_factory=utc_now)


class WebParameter(EntityModel):
    research_session_id: Identifier
    web_resource_id: Identifier
    name: str = Field(min_length=1, max_length=300)
    location: WebParameterLocation
    classification: FactClassification
    first_seen: datetime = Field(default_factory=utc_now)
    last_seen: datetime = Field(default_factory=utc_now)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class HTTPRequestTemplate(EntityModel):
    research_session_id: Identifier
    web_resource_id: Identifier
    semantic_key: str = Field(pattern=r"^[a-f0-9]{64}$")
    method: str = Field(pattern=r"^[A-Z]+$", max_length=20)
    content_type: str | None = Field(default=None, max_length=300)
    parameters: tuple[ParameterDescriptor, ...] = ()
    logical_identity_reference: str | None = Field(default=None, max_length=200)
    source_observation_ids: tuple[Identifier, ...] = ()
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class WebTemplateCandidate(EntityModel):
    research_session_id: Identifier
    web_resource_id: Identifier
    semantic_key: str = Field(pattern=r"^[a-f0-9]{64}$")
    tool_artifact_id: Identifier
    observation_id: Identifier
    template_id: str = Field(min_length=1, max_length=300)
    template_name: str = Field(min_length=1, max_length=500)
    matcher_name: str | None = Field(default=None, max_length=300)
    tool_reported_severity: AssessmentSeverity | None = None
    tool_metadata: dict[str, object] = Field(default_factory=dict)
    classification: WebCandidateClassification = WebCandidateClassification.TOOL_REPORTED
    finding_created: bool = False
    created_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def candidate_is_not_finding(self) -> "WebTemplateCandidate":
        if self.finding_created:
            raise ValueError("tool-reported web candidate cannot directly create a Finding")
        return self


class WebSurfaceSnapshot(EntityModel):
    research_session_id: Identifier
    web_surface_version: str = WEB_SURFACE_VERSION
    resource_count: int = Field(ge=0)
    parameter_count: int = Field(ge=0)
    request_template_count: int = Field(ge=0)
    candidate_count: int = Field(ge=0)
    source_observation_count: int = Field(ge=0)
    web_surface_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    created_at: datetime = Field(default_factory=utc_now)


class WebImportResult(DomainModel):
    research_session_id: Identifier
    discovery_plan_id: Identifier
    tool_run_id: Identifier
    burp_artifact_id: Identifier
    template_artifact_id: Identifier | None = None
    artifact_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    input_entries: int = Field(ge=0)
    parsed_entries: int = Field(ge=0)
    in_scope_entries: int = Field(ge=0)
    ignored_out_of_scope: int = Field(ge=0)
    redacted_sensitive_fields: int = Field(ge=0)
    observation_ids: tuple[Identifier, ...]
    resources_created: int = Field(ge=0)
    resources_updated: int = Field(ge=0)
    resource_count: int = Field(ge=0)
    parameter_count: int = Field(ge=0)
    request_template_count: int = Field(ge=0)
    candidate_count: int = Field(ge=0)
    web_surface_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class WebTemplateImportResult(DomainModel):
    research_session_id: Identifier
    discovery_plan_id: Identifier
    tool_run_id: Identifier
    artifact_id: Identifier
    artifact_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    input_entries: int = Field(ge=0)
    in_scope_entries: int = Field(ge=0)
    ignored_out_of_scope: int = Field(ge=0)
    observation_ids: tuple[Identifier, ...]
    resources_created: int = Field(ge=0)
    candidate_count: int = Field(ge=0)
    finding_count: int = Field(ge=0)
    web_surface_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


def web_surface_sha256(
    resources: list[WebResource],
    parameters: list[WebParameter],
    templates: list[HTTPRequestTemplate],
    candidates: list[WebTemplateCandidate],
    provenance: list[WebResourceProvenance],
) -> str:
    key_by_id = {item.id: item.canonical_key for item in resources}
    payload = {
        "version": WEB_SURFACE_VERSION,
        "resources": sorted(
            (
                item.canonical_key,
                item.resource_type.value,
                item.latest_status_code,
                item.content_type,
                item.classification.value,
            )
            for item in resources
        ),
        "parameters": sorted(
            (
                key_by_id[item.web_resource_id],
                item.name,
                item.location.value,
                item.classification.value,
            )
            for item in parameters
        ),
        "templates": sorted(
            (
                key_by_id[item.web_resource_id],
                item.method,
                item.content_type,
                tuple(sorted((value.name, value.location.value) for value in item.parameters)),
                item.logical_identity_reference,
            )
            for item in templates
        ),
        "candidates": sorted(
            (
                key_by_id[item.web_resource_id],
                item.template_id,
                item.template_name,
                item.matcher_name,
                item.tool_reported_severity.value if item.tool_reported_severity else None,
                json.dumps(item.tool_metadata, sort_keys=True, separators=(",", ":")),
                item.classification.value,
                item.finding_created,
            )
            for item in candidates
        ),
        "sources": sorted(
            {
                (
                    key_by_id[item.web_resource_id],
                    item.source.value,
                    item.classification.value,
                )
                for item in provenance
            }
        ),
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
