"""Typed, non-executable proposals for controlled client-side verification."""

from enum import StrEnum
from urllib.parse import urlsplit

from pydantic import Field, model_validator

from app.domain.common import DomainModel, EntityModel, Identifier, utc_now
from datetime import datetime


class ClientSideContext(StrEnum):
    HTML_TEXT = "HTML_TEXT"
    HTML_ATTRIBUTE = "HTML_ATTRIBUTE"
    URL_ATTRIBUTE = "URL_ATTRIBUTE"
    DOM_SINK = "DOM_SINK"
    UNKNOWN = "UNKNOWN"


class BrowserTargetEnvironment(StrEnum):
    ISOLATED_LAB = "ISOLATED_LAB"
    STAGING = "STAGING"


class CsrfTokenSource(StrEnum):
    NOT_REQUIRED = "NOT_REQUIRED"
    OBSERVED_FORM_FIELD = "OBSERVED_FORM_FIELD"
    OBSERVED_META_TAG = "OBSERVED_META_TAG"
    SAME_ORIGIN_BOOTSTRAP = "SAME_ORIGIN_BOOTSTRAP"


class CsrfHandling(DomainModel):
    """Token metadata only; a token value is never accepted or persisted here."""

    required: bool
    source: CsrfTokenSource
    field_name: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.-]{1,100}$")
    observed_evidence_id: Identifier | None = None

    @model_validator(mode="after")
    def validate_metadata(self) -> "CsrfHandling":
        if not self.required and (
            self.source is not CsrfTokenSource.NOT_REQUIRED
            or self.field_name is not None
            or self.observed_evidence_id is not None
        ):
            raise ValueError("CSRF metadata must be absent when no token is required")
        if self.required and self.source is CsrfTokenSource.NOT_REQUIRED:
            raise ValueError("CSRF-protected action requires an observed token source")
        if self.required and self.observed_evidence_id is None:
            raise ValueError("CSRF-protected action requires observed evidence lineage")
        return self


SAFE_PROBES_BY_CONTEXT: dict[ClientSideContext, str] = {
    ClientSideContext.HTML_TEXT: "marker-html-text-v1",
    ClientSideContext.HTML_ATTRIBUTE: "marker-html-attribute-v1",
    ClientSideContext.URL_ATTRIBUTE: "marker-url-attribute-v1",
    ClientSideContext.DOM_SINK: "marker-dom-sink-v1",
}
BASELINE_CONTROL_PROBE = "baseline-no-marker-v1"


class ClientVerificationProposal(DomainModel):
    """A plan only. It contains no payload, cookie, CSRF token, or browser command."""

    web_resource_id: Identifier
    evidence_ids: list[Identifier] = Field(min_length=1, max_length=20)
    navigation_path: str = Field(min_length=1, max_length=2048)
    input_name: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_.-]+$")
    context: ClientSideContext
    target_environment: BrowserTargetEnvironment
    csrf: CsrfHandling
    candidate_probe_id: str = Field(min_length=1, max_length=100)
    control_probe_id: str = BASELINE_CONTROL_PROBE
    requires_operator_approval: bool = True
    isolated_browser_context: bool = True
    same_origin_only: bool = True
    external_network_egress: bool = False

    @model_validator(mode="after")
    def validate_navigation(self) -> "ClientVerificationProposal":
        parsed = urlsplit(self.navigation_path)
        if (
            not self.navigation_path.startswith("/")
            or self.navigation_path.startswith("//")
            or parsed.scheme
            or parsed.netloc
            or parsed.fragment
        ):
            raise ValueError("navigation path must be relative to the resolved WebResource origin")
        return self


class ClientVerificationValidation(DomainModel):
    valid: bool
    errors: tuple[str, ...] = ()


class ClientVerificationRunStatus(StrEnum):
    CREATED = "CREATED"
    WAITING_FOR_APPROVAL = "WAITING_FOR_APPROVAL"
    AUTHORIZED = "AUTHORIZED"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    REJECTED = "REJECTED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ClientVerificationObservation(DomainModel):
    """Report-safe facts captured from one isolated browser context.

    This deliberately contains no DOM, URL query, console text, cookies, or
    storage values.  Those can be target-controlled or secret-bearing.
    """

    reflected: bool = False
    executed: bool = False
    canary_observed: bool = False
    context: ClientSideContext = ClientSideContext.UNKNOWN
    final_url_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    dom_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    console_signal_count: int = Field(default=0, ge=0, le=1000)
    runtime_error_count: int = Field(default=0, ge=0, le=1000)
    policy_blocked: bool = False
    source_ref: str | None = Field(default=None, max_length=200)
    sink_ref: str | None = Field(default=None, max_length=200)


class ClientVerificationRun(EntityModel):
    """Persistent, secret-free browser verification lifecycle record."""

    research_session_id: Identifier
    research_action_id: Identifier
    action_approval_id: Identifier
    web_resource_id: Identifier
    hypothesis_id: Identifier
    proposal: ClientVerificationProposal
    status: ClientVerificationRunStatus = ClientVerificationRunStatus.CREATED
    candidate_dom_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    control_dom_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    candidate_observation: ClientVerificationObservation | None = None
    control_observation: ClientVerificationObservation | None = None
    external_requests_blocked: int = Field(default=0, ge=0)
    error_code: str | None = Field(default=None, max_length=100)
    created_at: datetime = Field(default_factory=utc_now)
    started_at: datetime | None = None
    finished_at: datetime | None = None


class ClientVerificationValidator:
    """Fail-closed validator used before any future browser executor is invoked."""

    def validate(
        self,
        proposal: ClientVerificationProposal,
        *,
        available_evidence_ids: frozenset[Identifier],
        persisted_operator_approval: bool,
    ) -> ClientVerificationValidation:
        errors: list[str] = []
        if proposal.context is ClientSideContext.UNKNOWN:
            errors.append("CONTEXT_NOT_DETERMINED")
        expected_probe = SAFE_PROBES_BY_CONTEXT.get(proposal.context)
        if expected_probe is None or proposal.candidate_probe_id != expected_probe:
            errors.append("PROBE_NOT_ALLOWED_FOR_CONTEXT")
        if proposal.control_probe_id != BASELINE_CONTROL_PROBE:
            errors.append("CONTROL_PROBE_NOT_ALLOWED")
        if proposal.target_environment not in {
            BrowserTargetEnvironment.ISOLATED_LAB,
            BrowserTargetEnvironment.STAGING,
        }:
            errors.append("TARGET_ENVIRONMENT_NOT_ALLOWED")
        if not proposal.requires_operator_approval or not persisted_operator_approval:
            errors.append("OPERATOR_APPROVAL_REQUIRED")
        if not proposal.isolated_browser_context:
            errors.append("ISOLATED_BROWSER_REQUIRED")
        if not proposal.same_origin_only or proposal.external_network_egress:
            errors.append("EXTERNAL_EGRESS_NOT_ALLOWED")
        if not set(proposal.evidence_ids).issubset(available_evidence_ids):
            errors.append("EVIDENCE_NOT_GROUNDED")
        if proposal.csrf.required and proposal.csrf.observed_evidence_id not in available_evidence_ids:
            errors.append("CSRF_EVIDENCE_NOT_GROUNDED")
        return ClientVerificationValidation(valid=not errors, errors=tuple(errors))
