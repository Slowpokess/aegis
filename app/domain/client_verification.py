"""Typed, non-executable proposals for controlled client-side verification."""

from enum import StrEnum

from pydantic import Field, model_validator

from app.domain.common import DomainModel, Identifier


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
    context: ClientSideContext
    target_environment: BrowserTargetEnvironment
    csrf: CsrfHandling
    candidate_probe_id: str = Field(min_length=1, max_length=100)
    control_probe_id: str = BASELINE_CONTROL_PROBE
    requires_operator_approval: bool = True
    isolated_browser_context: bool = True
    same_origin_only: bool = True
    external_network_egress: bool = False


class ClientVerificationValidation(DomainModel):
    valid: bool
    errors: tuple[str, ...] = ()


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
