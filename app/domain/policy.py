from datetime import datetime
from enum import StrEnum

from pydantic import Field

from app.domain.common import EntityModel, Identifier, utc_now
from app.domain.experiments import ExperimentRole


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
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    HEADER_NOT_ALLOWED = "HEADER_NOT_ALLOWED"
    RESOLVED_ADDRESS_NOT_ALLOWED = "RESOLVED_ADDRESS_NOT_ALLOWED"
    UNSUPPORTED_PROTOCOL_VERSION = "UNSUPPORTED_PROTOCOL_VERSION"


class PolicyDecisionAudit(EntityModel):
    decision_id: str = Field(min_length=1, max_length=128)
    research_session_id: Identifier
    experiment_id: Identifier
    experiment_execution_id: Identifier | None = None
    action_role: ExperimentRole
    allowed: bool
    reason_code: PolicyReasonCode
    message: str = Field(min_length=1, max_length=1000)
    policy_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    policy_engine: str = Field(min_length=1, max_length=100)
    policy_engine_version: str = Field(min_length=1, max_length=100)
    created_at: datetime = Field(default_factory=utc_now)
