import hashlib
import json
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

PROTOCOL_VERSION = 1


class PolicyModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class PolicyConfig(PolicyModel):
    protocol_version: Literal[1] = 1
    allowed_hosts: list[str]
    allowed_ports: list[int]
    allowed_schemes: list[str]
    allowed_methods: list[str]
    allowed_headers: list[str] = Field(default_factory=lambda: ["accept", "accept-language"])
    max_requests_per_minute: int = Field(default=30, ge=1)
    max_response_bytes: int = Field(default=100_000, ge=1)
    max_timeout_ms: int = Field(default=10_000, ge=1)
    follow_redirects: bool = False

    def canonical_sha256(self) -> str:
        payload = self.model_dump(mode="json")
        for field in (
            "allowed_hosts",
            "allowed_schemes",
            "allowed_headers",
        ):
            payload[field] = sorted({value.lower() for value in payload[field]})
        payload["allowed_methods"] = sorted({value.upper() for value in payload["allowed_methods"]})
        payload["allowed_ports"] = sorted(set(payload["allowed_ports"]))
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(canonical).hexdigest()


class PolicyAction(PolicyModel):
    method: str
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    timeout_ms: int
    max_response_bytes: int
    follow_redirects: bool


class PolicyRequest(PolicyModel):
    protocol_version: Literal[1] = 1
    decision_id: str
    policy: PolicyConfig
    action: PolicyAction


class PolicyReasonCode(StrEnum):
    WITHIN_SCOPE = "WITHIN_SCOPE"
    INVALID_ACTION = "INVALID_ACTION"
    INVALID_URL = "INVALID_URL"
    SCHEME_NOT_ALLOWED = "SCHEME_NOT_ALLOWED"
    HOST_NOT_ALLOWED = "HOST_NOT_ALLOWED"
    PORT_NOT_ALLOWED = "PORT_NOT_ALLOWED"
    METHOD_NOT_ALLOWED = "METHOD_NOT_ALLOWED"
    TIMEOUT_EXCEEDS_LIMIT = "TIMEOUT_EXCEEDS_LIMIT"
    RESPONSE_LIMIT_EXCEEDS_POLICY = "RESPONSE_LIMIT_EXCEEDS_POLICY"
    REDIRECT_NOT_ALLOWED = "REDIRECT_NOT_ALLOWED"
    HEADER_NOT_ALLOWED = "HEADER_NOT_ALLOWED"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    UNSUPPORTED_PROTOCOL_VERSION = "UNSUPPORTED_PROTOCOL_VERSION"


class PolicyResponse(PolicyModel):
    protocol_version: Literal[1]
    decision_id: str | None
    allowed: bool
    reason_code: PolicyReasonCode
    message: str
    policy_sha256: str | None
    policy_engine: str
    policy_engine_version: str
