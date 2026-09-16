import hashlib
import struct
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

PROTOCOL_VERSION = 1
SENSITIVE_HEADERS = frozenset({"authorization", "cookie", "set-cookie", "proxy-authorization"})


class ProtocolModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class HttpMethod(StrEnum):
    GET = "GET"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class ExecutorRequest(ProtocolModel):
    protocol_version: Literal[1] = PROTOCOL_VERSION
    request_id: str = Field(min_length=1, max_length=128)
    method: HttpMethod
    url: str = Field(min_length=1, max_length=4096)
    headers: dict[str, str] = Field(default_factory=dict)
    timeout_ms: int = Field(default=5000, ge=1, le=60_000)
    max_response_bytes: int = Field(default=100_000, ge=1, le=10_000_000)
    follow_redirects: bool = False


class ErrorCode(StrEnum):
    INVALID_INPUT = "INVALID_INPUT"
    UNSUPPORTED_PROTOCOL_VERSION = "UNSUPPORTED_PROTOCOL_VERSION"
    INVALID_URL = "INVALID_URL"
    METHOD_NOT_SUPPORTED = "METHOD_NOT_SUPPORTED"
    NETWORK_ERROR = "NETWORK_ERROR"
    TIMEOUT = "TIMEOUT"
    RESPONSE_TOO_LARGE = "RESPONSE_TOO_LARGE"
    SERIALIZATION_ERROR = "SERIALIZATION_ERROR"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    EXECUTOR_NOT_FOUND = "EXECUTOR_NOT_FOUND"
    EXECUTOR_PROCESS_ERROR = "EXECUTOR_PROCESS_ERROR"


class ProtocolError(ProtocolModel):
    code: ErrorCode
    message: str


class ExecutionResult(ProtocolModel):
    effective_url: str
    status_code: int = Field(ge=100, le=599)
    headers: dict[str, str]
    body: str
    body_base64: str
    body_bytes: int = Field(ge=0)
    truncated: bool
    elapsed_ms: int = Field(ge=0)
    evidence_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class ExecutorSuccess(ProtocolModel):
    protocol_version: Literal[1]
    ok: Literal[True]
    request_id: str
    executor: str
    executor_version: str
    result: ExecutionResult
    error: None = None


class ExecutorFailure(ProtocolModel):
    protocol_version: Literal[1]
    ok: Literal[False]
    request_id: str | None
    executor: str
    executor_version: str
    result: None = None
    error: ProtocolError


ExecutorResponse = Annotated[ExecutorSuccess | ExecutorFailure, Field(discriminator="ok")]
EXECUTOR_RESPONSE_ADAPTER = TypeAdapter(ExecutorResponse)


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        name: "<redacted>" if name.lower() in SENSITIVE_HEADERS else value
        for name, value in headers.items()
    }


def canonical_evidence_sha256(
    *,
    method: str,
    url: str,
    request_headers: dict[str, str],
    status_code: int,
    response_headers: dict[str, str],
    body: bytes,
) -> str:
    """Python verifier for the Rust AEGIS-EVIDENCE-V1 canonical encoding."""
    digest = hashlib.sha256()

    def write_field(value: bytes) -> None:
        digest.update(struct.pack(">Q", len(value)))
        digest.update(value)

    def write_headers(headers: dict[str, str]) -> None:
        normalized = {name.lower(): value.strip() for name, value in headers.items()}
        digest.update(struct.pack(">Q", len(normalized)))
        for name, value in sorted(normalized.items()):
            write_field(name.encode())
            write_field(value.encode())

    write_field(b"AEGIS-EVIDENCE-V1")
    write_field(method.upper().encode())
    write_field(url.encode())
    write_headers(request_headers)
    digest.update(struct.pack(">H", status_code))
    write_headers(response_headers)
    write_field(body)
    return digest.hexdigest()
