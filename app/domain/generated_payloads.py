"""Closed-registry proof metadata; generation has no execution authority."""
from datetime import datetime
from enum import StrEnum

from pydantic import Field, model_validator

from app.domain.client_verification import ClientSideContext, ClientVerificationRun
from app.domain.common import EntityModel, Identifier, utc_now
from app.domain.recommendations import RecommendationVerdict, SafetyClass, VerificationRecommendation, VulnerabilityClass


class GeneratedPayload(EntityModel):
    verification_run_id: Identifier
    research_session_id: Identifier
    finding_id: Identifier | None = None
    vulnerability_class: VulnerabilityClass
    injection_context: ClientSideContext
    source_ref: str | None = Field(default=None, max_length=200)
    sink_ref: str | None = Field(default=None, max_length=200)
    template_id: str = Field(min_length=1, max_length=100)
    purpose: str = "confirm_execution"
    target_parameter: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_.-]+$")
    expected_candidate_signal: str = Field(min_length=1, max_length=500)
    expected_control_signal: str = Field(min_length=1, max_length=500)
    safety_class: SafetyClass = SafetyClass.INERT_CANARY
    requires_approval: bool = True
    template_version: str = "sealed-canary-v1"
    created_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def sealed_only(self) -> "GeneratedPayload":
        allowed = {"marker-html-text-v1", "marker-html-attribute-v1", "marker-url-attribute-v1", "marker-dom-sink-v1"}
        if self.template_id not in allowed or not self.requires_approval:
            raise ValueError("generated payload must be a sealed approved inert canary")
        if self.injection_context is ClientSideContext.UNKNOWN:
            raise ValueError("generated payload requires an evidenced injection context")
        return self


class PayloadGenerationEngine:
    """Returns metadata for an inert template only after deterministic confirmation."""
    def generate(self, run: ClientVerificationRun, recommendation: VerificationRecommendation) -> GeneratedPayload | None:
        candidate = run.candidate_observation
        if (recommendation.verdict is not RecommendationVerdict.CONFIRMED
                or recommendation.vulnerability_class is not VulnerabilityClass.XSS
                or candidate is None or not candidate.executed
                or candidate.context is ClientSideContext.UNKNOWN):
            return None
        template = {
            ClientSideContext.HTML_TEXT: "marker-html-text-v1",
            ClientSideContext.HTML_ATTRIBUTE: "marker-html-attribute-v1",
            ClientSideContext.URL_ATTRIBUTE: "marker-url-attribute-v1",
            ClientSideContext.DOM_SINK: "marker-dom-sink-v1",
        }.get(candidate.context)
        if template is None:
            return None
        return GeneratedPayload(verification_run_id=run.id, research_session_id=run.research_session_id,
            vulnerability_class=VulnerabilityClass.XSS, injection_context=candidate.context,
            source_ref=candidate.source_ref, sink_ref=candidate.sink_ref, template_id=template,
            target_parameter=run.proposal.input_name,
            expected_candidate_signal="The inert AEGIS DOM canary is observed.",
            expected_control_signal="The inert AEGIS DOM canary is not observed.",
            provenance=run.provenance)
