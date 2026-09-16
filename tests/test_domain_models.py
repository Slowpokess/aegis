from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.domain.common import Provenance
from app.domain.findings import Finding, VerificationStatus
from app.domain.hypotheses import Hypothesis, HypothesisStatus
from app.domain.observations import Observation, ObservationSource


def test_observation_keeps_provenance_and_classification_separate() -> None:
    observation = Observation(
        asset_id=uuid4(),
        source=ObservationSource.HTTP,
        raw_data={"status_code": 200},
        normalized_data={"status": 200},
        provenance=Provenance(source_type="http", source_reference="GET /health"),
        trust="UNTRUSTED",
    )

    assert observation.provenance.classification.value == "OBSERVED"
    assert observation.trust.value == "UNTRUSTED"
    assert observation.raw_data != observation.normalized_data


def test_supported_hypothesis_requires_evidence() -> None:
    with pytest.raises(ValidationError, match="require evidence_ids"):
        Hypothesis(
            provenance=Provenance(
                source_type="reasoning",
                source_reference="test",
                classification="INFERRED",
            ),
            title="Authorization differs",
            description="A response appears identity-dependent.",
            observation_ids=[uuid4()],
            confidence=0.8,
            status=HypothesisStatus.SUPPORTED,
        )


def test_supported_finding_requires_control() -> None:
    with pytest.raises(ValidationError, match="require control evidence"):
        Finding(
            provenance=Provenance(
                source_type="verifier",
                source_reference="test",
                classification="INFERRED",
            ),
            hypothesis_id=uuid4(),
            claim="Object access is not scoped to the owner.",
            evidence_ids=[uuid4()],
            reproduction=["Repeat the policy-approved request."],
            impact="Another laboratory user's object is observable.",
            confidence=0.9,
            verification_status=VerificationStatus.SUPPORTED,
        )
