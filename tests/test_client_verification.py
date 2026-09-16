from uuid import uuid4

import pytest

from app.domain.client_verification import (
    BASELINE_CONTROL_PROBE,
    BrowserTargetEnvironment,
    ClientSideContext,
    ClientVerificationProposal,
    ClientVerificationValidator,
    CsrfHandling,
    CsrfTokenSource,
)


def _proposal(**updates: object) -> ClientVerificationProposal:
    evidence_id = uuid4()
    values = {
        "web_resource_id": uuid4(),
        "evidence_ids": [evidence_id],
        "context": ClientSideContext.HTML_TEXT,
        "target_environment": BrowserTargetEnvironment.ISOLATED_LAB,
        "csrf": CsrfHandling(required=False, source=CsrfTokenSource.NOT_REQUIRED),
        "candidate_probe_id": "marker-html-text-v1",
        "control_probe_id": BASELINE_CONTROL_PROBE,
    }
    values.update(updates)
    return ClientVerificationProposal(**values)


def test_safe_browser_plan_is_grounded_and_requires_persisted_approval() -> None:
    proposal = _proposal()
    result = ClientVerificationValidator().validate(
        proposal,
        available_evidence_ids=frozenset(proposal.evidence_ids),
        persisted_operator_approval=True,
    )
    assert result.valid


def test_csrf_is_metadata_only_and_requires_observed_lineage() -> None:
    evidence_id = uuid4()
    with pytest.raises(ValueError, match="observed evidence lineage"):
        CsrfHandling(required=True, source=CsrfTokenSource.OBSERVED_FORM_FIELD)

    proposal = _proposal(
        csrf=CsrfHandling(
            required=True,
            source=CsrfTokenSource.OBSERVED_FORM_FIELD,
            field_name="csrf_token",
            observed_evidence_id=evidence_id,
        )
    )
    result = ClientVerificationValidator().validate(
        proposal,
        available_evidence_ids=frozenset(proposal.evidence_ids),
        persisted_operator_approval=True,
    )
    assert not result.valid
    assert "CSRF_EVIDENCE_NOT_GROUNDED" in result.errors


def test_validator_rejects_freeform_probe_unknown_context_and_egress() -> None:
    proposal = _proposal(
        context=ClientSideContext.UNKNOWN,
        candidate_probe_id="model-provided-value",
        external_network_egress=True,
    )
    result = ClientVerificationValidator().validate(
        proposal,
        available_evidence_ids=frozenset(proposal.evidence_ids),
        persisted_operator_approval=False,
    )
    assert not result.valid
    assert {
        "CONTEXT_NOT_DETERMINED",
        "PROBE_NOT_ALLOWED_FOR_CONTEXT",
        "EXTERNAL_EGRESS_NOT_ALLOWED",
        "OPERATOR_APPROVAL_REQUIRED",
    } <= set(result.errors)
