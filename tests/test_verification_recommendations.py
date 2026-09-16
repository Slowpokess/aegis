from uuid import uuid4

from app.domain.client_verification import (
    BrowserTargetEnvironment, ClientSideContext, ClientVerificationObservation,
    ClientVerificationProposal, ClientVerificationRun, ClientVerificationRunStatus,
    CsrfHandling, CsrfTokenSource,
)
from app.domain.common import Provenance
from app.domain.recommendations import (
    RecommendedAction, RecommendationVerdict, VerificationRecommendationEngine,
)
from app.domain.generated_payloads import PayloadGenerationEngine


def _run(candidate: ClientVerificationObservation | None, control: ClientVerificationObservation | None) -> ClientVerificationRun:
    evidence = uuid4()
    proposal = ClientVerificationProposal(web_resource_id=uuid4(), evidence_ids=[evidence], navigation_path="/x",
        input_name="comment", context=ClientSideContext.HTML_ATTRIBUTE,
        target_environment=BrowserTargetEnvironment.ISOLATED_LAB,
        csrf=CsrfHandling(required=False, source=CsrfTokenSource.NOT_REQUIRED),
        candidate_probe_id="marker-html-attribute-v1")
    return ClientVerificationRun(research_session_id=uuid4(), research_action_id=uuid4(), action_approval_id=uuid4(),
        web_resource_id=proposal.web_resource_id, hypothesis_id=uuid4(), proposal=proposal,
        status=ClientVerificationRunStatus.COMPLETED, candidate_observation=candidate,
        control_observation=control, provenance=Provenance(source_type="test", source_reference="run"))


def test_execution_differential_is_confirmed_without_new_probe() -> None:
    value = VerificationRecommendationEngine().generate(_run(
        ClientVerificationObservation(executed=True, canary_observed=True, context=ClientSideContext.HTML_ATTRIBUTE),
        ClientVerificationObservation(context=ClientSideContext.HTML_ATTRIBUTE)))
    assert value.verdict is RecommendationVerdict.CONFIRMED
    assert value.recommended_action is RecommendedAction.CREATE_FINDING
    assert value.suggested_probe is None


def test_reflection_without_execution_needs_approved_inert_probe() -> None:
    value = VerificationRecommendationEngine().generate(_run(
        ClientVerificationObservation(reflected=True, context=ClientSideContext.HTML_ATTRIBUTE),
        ClientVerificationObservation(context=ClientSideContext.HTML_ATTRIBUTE)))
    assert value.verdict is RecommendationVerdict.PARTIALLY_CONFIRMED
    assert value.recommended_action is RecommendedAction.RUN_ADDITIONAL_VERIFICATION
    assert value.suggested_probe and value.suggested_probe.payload_template == "marker-html-attribute-v1"
    assert value.requires_approval


def test_equal_candidate_control_is_rejected_not_payload_fuzzing() -> None:
    observed = ClientVerificationObservation(reflected=True, context=ClientSideContext.HTML_TEXT)
    value = VerificationRecommendationEngine().generate(_run(observed, observed))
    assert value.verdict is RecommendationVerdict.REJECTED
    assert value.suggested_probe is None


def test_missing_observations_cannot_fabricate_context_or_probe() -> None:
    value = VerificationRecommendationEngine().generate(_run(None, None))
    assert value.verdict is RecommendationVerdict.NEEDS_ADDITIONAL_VERIFICATION
    assert value.suggested_probe is None


def test_payload_generation_is_closed_registry_and_requires_confirmation() -> None:
    run = _run(ClientVerificationObservation(executed=True, context=ClientSideContext.HTML_ATTRIBUTE),
               ClientVerificationObservation(context=ClientSideContext.HTML_ATTRIBUTE))
    recommendation = VerificationRecommendationEngine().generate(run)
    payload = PayloadGenerationEngine().generate(run, recommendation)
    assert payload is not None
    assert payload.template_id == "marker-html-attribute-v1"
    assert payload.requires_approval
    assert PayloadGenerationEngine().generate(_run(None, None),
        VerificationRecommendationEngine().generate(_run(None, None))) is None
