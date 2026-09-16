"""Evidence-bound, non-executable client verification recommendations."""

from enum import StrEnum
from datetime import datetime

from pydantic import Field, model_validator

from app.domain.client_verification import ClientSideContext, ClientVerificationRun
from app.domain.common import DomainModel, EntityModel, Identifier, utc_now


RECOMMENDATION_ENGINE_VERSION = "verification-recommendation-rules-v1"


class RecommendationVerdict(StrEnum):
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    PARTIALLY_CONFIRMED = "PARTIALLY_CONFIRMED"
    NEEDS_ADDITIONAL_VERIFICATION = "NEEDS_ADDITIONAL_VERIFICATION"


class RecommendedAction(StrEnum):
    NO_ACTION = "NO_ACTION"
    CLOSE_AS_REJECTED = "CLOSE_AS_REJECTED"
    COLLECT_MORE_EVIDENCE = "COLLECT_MORE_EVIDENCE"
    RUN_ADDITIONAL_VERIFICATION = "RUN_ADDITIONAL_VERIFICATION"
    CREATE_FINDING = "CREATE_FINDING"
    UPDATE_FINDING = "UPDATE_FINDING"
    REMEDIATE = "REMEDIATE"
    MANUAL_REVIEW = "MANUAL_REVIEW"


class VulnerabilityClass(StrEnum):
    XSS = "XSS"
    CSRF = "CSRF"
    OPEN_REDIRECT = "OPEN_REDIRECT"
    UNSAFE_CLIENT_NAVIGATION = "UNSAFE_CLIENT_NAVIGATION"
    CORS = "CORS"
    AUTHORIZATION_SESSION = "AUTHORIZATION_SESSION"
    CLIENT_SIDE_INJECTION = "CLIENT_SIDE_INJECTION"
    INSECURE_DOM_SINK = "INSECURE_DOM_SINK"
    BROWSER_POLICY = "BROWSER_POLICY"
    UNKNOWN = "UNKNOWN"


class SafetyClass(StrEnum):
    INERT_CANARY = "INERT_CANARY"


class SuggestedProbe(DomainModel):
    purpose: str = Field(min_length=1, max_length=80)
    target_parameter: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_.-]+$")
    context: ClientSideContext
    payload_template: str = Field(min_length=1, max_length=200)
    expected_candidate_signal: str = Field(min_length=1, max_length=500)
    expected_control_signal: str = Field(min_length=1, max_length=500)
    safety_class: SafetyClass = SafetyClass.INERT_CANARY
    requires_approval: bool = True

    @model_validator(mode="after")
    def only_sealed_inert_templates(self) -> "SuggestedProbe":
        allowed = {
            "marker-html-text-v1", "marker-html-attribute-v1",
            "marker-url-attribute-v1", "marker-dom-sink-v1",
        }
        if self.payload_template not in allowed:
            raise ValueError("suggested probes must use a sealed inert-canary template")
        if not self.requires_approval:
            raise ValueError("active suggested probes always require approval")
        return self


class VerificationRecommendation(EntityModel):
    run_id: Identifier
    research_session_id: Identifier
    finding_id: Identifier | None = None
    proposal_id: Identifier | None = None
    verdict: RecommendationVerdict
    vulnerability_class: VulnerabilityClass = VulnerabilityClass.UNKNOWN
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str = Field(min_length=1, max_length=4000)
    evidence_refs: tuple[Identifier, ...] = Field(min_length=1, max_length=50)
    recommended_action: RecommendedAction
    recommended_verification: str | None = Field(default=None, max_length=2000)
    suggested_probe: SuggestedProbe | None = None
    remediation: tuple[str, ...] = Field(default_factory=tuple, max_length=10)
    requires_approval: bool = False
    created_at: datetime = Field(default_factory=utc_now)
    engine_version: str = RECOMMENDATION_ENGINE_VERSION

    @model_validator(mode="after")
    def recommendation_is_non_executable(self) -> "VerificationRecommendation":
        active = self.recommended_action is RecommendedAction.RUN_ADDITIONAL_VERIFICATION
        if active != (self.suggested_probe is not None):
            raise ValueError("additional verification requires exactly one structured probe")
        if active and not self.requires_approval:
            raise ValueError("additional verification requires approval")
        if not active and self.requires_approval:
            raise ValueError("only active verification recommendations require approval")
        return self


class VerificationRecommendationEngine:
    """Deterministic rules. No LLM or ungrounded payload generation occurs here."""

    def generate(self, run: ClientVerificationRun) -> VerificationRecommendation:
        refs = tuple(run.proposal.evidence_ids)
        candidate, control = run.candidate_observation, run.control_observation
        base = dict(run_id=run.id, research_session_id=run.research_session_id,
                    evidence_refs=refs, provenance=run.provenance)
        if not refs or candidate is None or control is None:
            return VerificationRecommendation(**base, verdict=RecommendationVerdict.NEEDS_ADDITIONAL_VERIFICATION,
                confidence=0.0, vulnerability_class=VulnerabilityClass.UNKNOWN,
                reasoning="Candidate/control observations or evidence lineage are incomplete; no context or exploitability can be inferred.",
                recommended_action=RecommendedAction.COLLECT_MORE_EVIDENCE,
                recommended_verification="Collect a complete isolated candidate/control observation pair.")
        if candidate.executed and not control.executed:
            context = candidate.context
            known_context = context is not ClientSideContext.UNKNOWN
            remediation = self._remediation(context) if known_context else ()
            return VerificationRecommendation(**base, verdict=RecommendationVerdict.CONFIRMED,
                vulnerability_class=VulnerabilityClass.XSS if known_context else VulnerabilityClass.CLIENT_SIDE_INJECTION,
                confidence=0.95, reasoning="Candidate produced an execution signal while the control did not; a differential execution exists in the persisted evidence lineage.",
                recommended_action=RecommendedAction.CREATE_FINDING,
                recommended_verification=None, remediation=remediation)
        if candidate.reflected and not candidate.executed and not control.reflected:
            context = candidate.context
            if context is ClientSideContext.UNKNOWN:
                return VerificationRecommendation(**base, verdict=RecommendationVerdict.NEEDS_ADDITIONAL_VERIFICATION,
                    vulnerability_class=VulnerabilityClass.UNKNOWN, confidence=0.4,
                    reasoning="Candidate reflection is observed but execution and injection context are not evidenced.",
                    recommended_action=RecommendedAction.COLLECT_MORE_EVIDENCE,
                    recommended_verification="Determine the reflected context before proposing a controlled probe.")
            probe = SuggestedProbe(purpose="confirm_execution", target_parameter=run.proposal.input_name,
                context=context, payload_template=_template(context),
                expected_candidate_signal="The inert AEGIS DOM canary is observed.",
                expected_control_signal="The inert AEGIS DOM canary is not observed.")
            return VerificationRecommendation(**base, verdict=RecommendationVerdict.PARTIALLY_CONFIRMED,
                vulnerability_class=VulnerabilityClass.XSS, confidence=0.6,
                reasoning=f"Candidate reflection is observed in {context.value}; JavaScript execution is not observed and XSS is not confirmed.",
                recommended_action=RecommendedAction.RUN_ADDITIONAL_VERIFICATION,
                recommended_verification="Test the evidenced context with a sealed inert DOM canary.", suggested_probe=probe,
                requires_approval=True)
        if self._same(candidate, control):
            return VerificationRecommendation(**base, verdict=RecommendationVerdict.REJECTED,
                vulnerability_class=VulnerabilityClass.UNKNOWN, confidence=0.85,
                reasoning="Candidate and control have identical persisted observations; differential verification failed.",
                recommended_action=RecommendedAction.CLOSE_AS_REJECTED)
        return VerificationRecommendation(**base, verdict=RecommendationVerdict.INCONCLUSIVE,
            vulnerability_class=VulnerabilityClass.UNKNOWN, confidence=0.25,
            reasoning="The evidence does not establish a candidate/control execution differential or a safe context-specific next probe.",
            recommended_action=RecommendedAction.MANUAL_REVIEW)

    @staticmethod
    def _same(candidate: object, control: object) -> bool:
        return candidate == control

    @staticmethod
    def _remediation(context: ClientSideContext) -> tuple[str, ...]:
        if context is ClientSideContext.HTML_ATTRIBUTE:
            return ("Apply context-aware attribute output encoding.", "Avoid constructing attributes from untrusted input.", "Deploy a restrictive Content Security Policy as defense in depth.")
        if context is ClientSideContext.DOM_SINK:
            return ("Avoid dangerous DOM sinks for untrusted input.", "Use safe DOM APIs and context-aware sanitization.")
        return ("Apply context-aware output encoding.", "Deploy a restrictive Content Security Policy as defense in depth.")


def _template(context: ClientSideContext) -> str:
    return {
        ClientSideContext.HTML_TEXT: "marker-html-text-v1",
        ClientSideContext.HTML_ATTRIBUTE: "marker-html-attribute-v1",
        ClientSideContext.URL_ATTRIBUTE: "marker-url-attribute-v1",
        ClientSideContext.DOM_SINK: "marker-dom-sink-v1",
    }[context]
