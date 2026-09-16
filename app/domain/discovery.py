import base64
import hashlib
import ipaddress
import json
from datetime import datetime
from enum import StrEnum

from pydantic import Field, field_validator, model_validator

from app.domain.common import DomainModel, EntityModel, Identifier, utc_now

TOOL_REGISTRY_VERSION = "tool-registry-v1"
TOOL_INTEGRATION_VERSION = "tool-integration-v1"
DISCOVERY_VERSION = "discovery-v1"
NMAP_PARSER_VERSION = "nmap-parser-v1"
FFUF_PARSER_VERSION = "ffuf-parser-v1"
NUCLEI_PARSER_VERSION = "nuclei-parser-v1"


class ToolType(StrEnum):
    HTTP = "HTTP"
    DNS = "DNS"
    TLS = "TLS"
    NMAP = "NMAP"
    FFUF = "FFUF"
    NUCLEI = "NUCLEI"


class ToolCapability(StrEnum):
    HTTP_REQUEST = "HTTP_REQUEST"
    HOST_DISCOVERY = "HOST_DISCOVERY"
    PORT_DISCOVERY = "PORT_DISCOVERY"
    SERVICE_DISCOVERY = "SERVICE_DISCOVERY"
    DNS_LOOKUP = "DNS_LOOKUP"
    TLS_INSPECTION = "TLS_INSPECTION"
    WEB_CONTENT_DISCOVERY = "WEB_CONTENT_DISCOVERY"
    WEB_PROXY_ANALYSIS = "WEB_PROXY_ANALYSIS"
    TEMPLATE_ASSESSMENT = "TEMPLATE_ASSESSMENT"
    NETWORK_CAPTURE_ANALYSIS = "NETWORK_CAPTURE_ANALYSIS"
    DIRECTORY_GRAPH_COLLECTION = "DIRECTORY_GRAPH_COLLECTION"
    CERTIFICATE_SERVICE_ASSESSMENT = "CERTIFICATE_SERVICE_ASSESSMENT"
    AUTHENTICATED_HOST_ENUMERATION = "AUTHENTICATED_HOST_ENUMERATION"
    OFFLINE_ARTIFACT_ANALYSIS = "OFFLINE_ARTIFACT_ANALYSIS"


class ToolCategory(StrEnum):
    DISCOVERY = "DISCOVERY"
    WEB_ASSESSMENT = "WEB_ASSESSMENT"
    NETWORK_ANALYSIS = "NETWORK_ANALYSIS"
    IDENTITY_ASSESSMENT = "IDENTITY_ASSESSMENT"
    OFFLINE_COMPUTE = "OFFLINE_COMPUTE"
    VALIDATION = "VALIDATION"


class ExecutionBackend(StrEnum):
    RUST_HTTP = "RUST_HTTP"
    PYTHON_STDLIB = "PYTHON_STDLIB"
    FIXED_BINARY = "FIXED_BINARY"
    EXTERNAL_BINARY = "EXTERNAL_BINARY"
    PYTHON_NATIVE = "PYTHON_NATIVE"
    OFFLINE_JOB = "OFFLINE_JOB"


class ToolRisk(StrEnum):
    PASSIVE = "PASSIVE"
    LOW = "LOW"


class TargetType(StrEnum):
    IP = "IP"
    HOSTNAME = "HOSTNAME"


class DiscoveryProfile(StrEnum):
    PASSIVE = "PASSIVE"
    STANDARD = "STANDARD"


class PlanItemRequirement(StrEnum):
    REQUIRED = "REQUIRED"
    OPTIONAL = "OPTIONAL"


class DiscoveryPlanStatus(StrEnum):
    CREATED = "CREATED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class ToolRunStatus(StrEnum):
    CREATED = "CREATED"
    VALIDATED = "VALIDATED"
    POLICY_APPROVED = "POLICY_APPROVED"
    POLICY_REJECTED = "POLICY_REJECTED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ToolPolicyReason(StrEnum):
    ALLOWED = "ALLOWED"
    TOOL_NOT_AVAILABLE = "TOOL_NOT_AVAILABLE"
    TOOL_DISABLED = "TOOL_DISABLED"
    PROFILE_NOT_ALLOWED = "PROFILE_NOT_ALLOWED"
    TARGET_OUT_OF_SCOPE = "TARGET_OUT_OF_SCOPE"
    PORT_OUT_OF_SCOPE = "PORT_OUT_OF_SCOPE"
    RISK_NOT_ALLOWED = "RISK_NOT_ALLOWED"
    BINARY_NOT_ALLOWED = "BINARY_NOT_ALLOWED"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    RESEARCH_BUDGET_EXCEEDED = "RESEARCH_BUDGET_EXCEEDED"


class ToolErrorCode(StrEnum):
    TOOL_NOT_AVAILABLE = "TOOL_NOT_AVAILABLE"
    TOOL_DISABLED = "TOOL_DISABLED"
    PROFILE_NOT_ALLOWED = "PROFILE_NOT_ALLOWED"
    TARGET_OUT_OF_SCOPE = "TARGET_OUT_OF_SCOPE"
    PORT_OUT_OF_SCOPE = "PORT_OUT_OF_SCOPE"
    POLICY_REJECTED = "POLICY_REJECTED"
    PROCESS_TIMEOUT = "PROCESS_TIMEOUT"
    PROCESS_FAILED = "PROCESS_FAILED"
    OUTPUT_TOO_LARGE = "OUTPUT_TOO_LARGE"
    PARSER_FAILED = "PARSER_FAILED"
    ARTIFACT_INVALID = "ARTIFACT_INVALID"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    RESEARCH_BUDGET_EXCEEDED = "RESEARCH_BUDGET_EXCEEDED"


class ArtifactType(StrEnum):
    HTTP_RESPONSE = "HTTP_RESPONSE"
    NMAP_XML = "NMAP_XML"
    DNS_JSON = "DNS_JSON"
    TLS_JSON = "TLS_JSON"
    TLS_CERTIFICATE = "TLS_CERTIFICATE"
    PCAP = "PCAP"
    BURP_EXPORT = "BURP_EXPORT"
    FFUF_JSON = "FFUF_JSON"
    NUCLEI_JSON = "NUCLEI_JSON"
    DIRECTORY_GRAPH = "DIRECTORY_GRAPH"
    OFFLINE_COMPUTE_RESULT = "OFFLINE_COMPUTE_RESULT"


class ParserStatus(StrEnum):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    PENDING = "PENDING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ToolDescriptor(DomainModel):
    id: str = Field(min_length=1, max_length=50, pattern=r"^[a-z][a-z0-9_-]*$")
    name: str
    version: str | None = None
    tool_type: ToolType
    capabilities: tuple[ToolCapability, ...]
    execution_backend: ExecutionBackend
    supported_profiles: tuple[str, ...]
    input_schema_version: str
    output_schema_version: str
    requires_binary: bool
    binary_name: str | None = None
    executable_path: str | None = None
    available: bool
    risk_class: ToolRisk
    enabled: bool = True
    max_timeout_seconds: float = Field(default=15.0, ge=0.1, le=300.0)
    max_runs_per_plan: int = Field(default=1, ge=1, le=16)
    integration_version: str = TOOL_INTEGRATION_VERSION
    category: ToolCategory = ToolCategory.DISCOVERY
    artifact_types: tuple[ArtifactType, ...] = ()
    parser_version: str | None = None
    mapper_version: str | None = None
    supports_progress: bool = False
    supports_cancellation: bool = False
    documentation_url: str | None = None
    documentation_summary: str | None = None

    @model_validator(mode="after")
    def binary_fields_are_consistent(self) -> "ToolDescriptor":
        if self.requires_binary and not self.binary_name:
            raise ValueError("binary tools require a fixed binary name")
        if not self.requires_binary and self.executable_path is not None:
            raise ValueError("library tools cannot expose an executable path")
        return self


class ToolTarget(DomainModel):
    host: str = Field(min_length=1, max_length=253)
    ports: tuple[int, ...] = Field(min_length=1)
    scheme: str = Field(pattern=r"^https?$")
    target_type: TargetType

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, ports: tuple[int, ...]) -> tuple[int, ...]:
        if any(port < 1 or port > 65535 for port in ports):
            raise ValueError("tool target ports must be between 1 and 65535")
        return tuple(sorted(set(ports)))

    @classmethod
    def from_scope(cls, host: str, ports: tuple[int, ...], scheme: str) -> "ToolTarget":
        try:
            ipaddress.ip_address(host)
        except ValueError:
            target_type = TargetType.HOSTNAME
        else:
            target_type = TargetType.IP
        return cls(host=host.lower(), ports=ports, scheme=scheme, target_type=target_type)


class ToolRequest(DomainModel):
    tool: str = Field(pattern=r"^[a-z][a-z0-9_-]*$")
    profile: str = Field(pattern=r"^[a-z][a-z0-9_-]*$")
    target: ToolTarget
    timeout_seconds: float = Field(default=10.0, ge=0.1, le=300.0)
    requirement: PlanItemRequirement = PlanItemRequirement.REQUIRED


class DiscoveryPlan(EntityModel):
    research_session_id: Identifier
    discovery_version: str = DISCOVERY_VERSION
    registry_version: str = TOOL_REGISTRY_VERSION
    profile: DiscoveryProfile
    requested_capabilities: tuple[ToolCapability, ...]
    planned_tool_runs: tuple[ToolRequest, ...]
    status: DiscoveryPlanStatus = DiscoveryPlanStatus.CREATED
    created_at: datetime = Field(default_factory=utc_now)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: str | None = None


class ToolPolicyDecision(EntityModel):
    research_session_id: Identifier
    discovery_plan_id: Identifier
    tool_run_id: Identifier
    allowed: bool
    reason: ToolPolicyReason
    message: str
    policy_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    created_at: datetime = Field(default_factory=utc_now)


class ToolRun(EntityModel):
    research_session_id: Identifier
    discovery_plan_id: Identifier
    tool_id: str
    tool_version: str | None = None
    profile: str
    profile_version: str
    requested_target: ToolTarget
    normalized_target: ToolTarget
    status: ToolRunStatus = ToolRunStatus.CREATED
    started_at: datetime = Field(default_factory=utc_now)
    finished_at: datetime | None = None
    exit_code: int | None = None
    policy_decision_id: Identifier | None = None
    artifact_ids: list[Identifier] = Field(default_factory=list)
    observation_ids: list[Identifier] = Field(default_factory=list)
    error_code: ToolErrorCode | None = None
    error: str | None = None
    normalized_argv: tuple[str, ...] = ()
    parser_version: str | None = None
    config_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class ToolArtifact(EntityModel):
    research_session_id: Identifier
    tool_run_id: Identifier
    tool_id: str
    tool_version: str | None = None
    artifact_type: ArtifactType
    content_type: str
    content_base64: str
    size_bytes: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    parser_version: str | None = None
    parser_status: ParserStatus = ParserStatus.PENDING
    parser_error: str | None = None
    created_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def content_matches_metadata(self) -> "ToolArtifact":
        try:
            raw = base64.b64decode(self.content_base64, validate=True)
        except ValueError as error:
            raise ValueError("artifact content is not valid base64") from error
        if len(raw) != self.size_bytes:
            raise ValueError("artifact size does not match content")
        if hashlib.sha256(raw).hexdigest() != self.sha256:
            raise ValueError("artifact hash does not match content")
        return self

    def content_bytes(self) -> bytes:
        return base64.b64decode(self.content_base64)

    @classmethod
    def from_bytes(
        cls,
        *,
        raw: bytes,
        research_session_id: Identifier,
        tool_run_id: Identifier,
        tool_id: str,
        tool_version: str | None,
        artifact_type: ArtifactType,
        content_type: str,
        parser_version: str | None,
        provenance: object,
    ) -> "ToolArtifact":
        return cls(
            research_session_id=research_session_id,
            tool_run_id=tool_run_id,
            tool_id=tool_id,
            tool_version=tool_version,
            artifact_type=artifact_type,
            content_type=content_type,
            content_base64=base64.b64encode(raw).decode(),
            size_bytes=len(raw),
            sha256=hashlib.sha256(raw).hexdigest(),
            parser_version=parser_version,
            provenance=provenance,
        )


class NmapServiceRecord(DomainModel):
    host: str
    address: str
    port: int = Field(ge=1, le=65535)
    protocol: str
    state: str
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None


class DNSResult(DomainModel):
    requested_hostname: str
    addresses: tuple[str, ...]
    resolved_at: datetime = Field(default_factory=utc_now)


class TLSResult(DomainModel):
    host: str
    port: int
    tls_available: bool
    protocol: str | None = None
    certificate_presented: bool = False
    subject: str | None = None
    issuer: str | None = None
    valid_from: str | None = None
    valid_to: str | None = None
    san_names: tuple[str, ...] = ()
    fingerprint_sha256: str | None = None


def tool_run_config_sha256(request: ToolRequest, descriptor: ToolDescriptor) -> str:
    payload = {
        "registry_version": TOOL_REGISTRY_VERSION,
        "tool": descriptor.id,
        "tool_version": descriptor.version,
        "profile": request.profile,
        "target": request.target.model_dump(mode="json"),
        "timeout_seconds": request.timeout_seconds,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
