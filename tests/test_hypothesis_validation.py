from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.domain.common import Provenance
from app.domain.evidence import Evidence, HTTPRequestRecord, HTTPResponseRecord
from app.domain.observations import Observation, ObservationSource
from app.reasoning.schemas import HypothesisBatch, HypothesisCandidate
from app.reasoning.validation import HypothesisRejectionCode, HypothesisValidator


def linked_pair(session_id=None, path="/api/orders/101") -> tuple[Observation, Evidence]:
    session_id = session_id or uuid4()
    evidence = Evidence(
        research_session_id=session_id,
        request_id=f"REQ-{uuid4()}",
        request=HTTPRequestRecord(method="GET", url=f"http://127.0.0.1:8001{path}"),
        response=HTTPResponseRecord(status_code=200, body="{}", elapsed_ms=1),
        integrity_hash="a" * 64,
        provenance=Provenance(source_type="http", source_reference=path),
    )
    observation = Observation(
        asset_id=uuid4(),
        research_session_id=session_id,
        request_id=evidence.request_id,
        evidence_id=evidence.id,
        source=ObservationSource.HTTP,
        raw_data={},
        provenance=Provenance(source_type="http", source_reference=str(evidence.id)),
    )
    return observation, evidence


def candidate(observation: Observation, evidence: Evidence, **updates) -> HypothesisCandidate:
    values = {
        "title": "Possible order authorization behavior",
        "description": "Observed behavior at /api/orders/101 may depend on object ownership.",
        "observation_ids": [observation.id],
        "evidence_ids": [evidence.id],
        "assumptions": ["The object identity is stable."],
        "missing_information": [
            {
                "description": "Need an owner baseline comparison.",
                "related_observation_ids": [observation.id],
            }
        ],
        "confidence": 0.6,
    }
    values.update(updates)
    return HypothesisCandidate.model_validate(values)


def validate(session_id, candidates, observations, evidence, max_hypotheses=5):
    return HypothesisValidator().validate(
        batch=HypothesisBatch(hypotheses=candidates),
        research_session_id=session_id,
        observations=observations,
        evidence=evidence,
        existing_hypotheses=[],
        max_hypotheses=max_hypotheses,
    )


def test_valid_candidate_is_accepted() -> None:
    observation, evidence = linked_pair()
    result = validate(
        observation.research_session_id,
        [candidate(observation, evidence)],
        [observation],
        [evidence],
    )
    assert len(result.accepted) == 1
    assert result.rejected == []


def test_nonexistent_observation_overrides_false_confidence() -> None:
    observation, evidence = linked_pair()
    proposed = candidate(observation, evidence).model_copy(
        update={"observation_ids": [uuid4()], "confidence": 0.99}
    )
    result = validate(
        observation.research_session_id, [proposed], [observation], [evidence]
    )
    assert result.rejected[0].code is HypothesisRejectionCode.INVALID_OBSERVATION_REFERENCE


def test_existing_observation_with_wrong_evidence_is_rejected() -> None:
    first_observation, first_evidence = linked_pair()
    _, second_evidence = linked_pair(first_observation.research_session_id, "/api/profile")
    proposed = candidate(first_observation, first_evidence).model_copy(
        update={"evidence_ids": [second_evidence.id]}
    )
    result = validate(
        first_observation.research_session_id,
        [proposed],
        [first_observation],
        [first_evidence, second_evidence],
    )
    assert result.rejected[0].code is HypothesisRejectionCode.OBSERVATION_EVIDENCE_MISMATCH


def test_cross_session_reference_is_rejected() -> None:
    primary_observation, primary_evidence = linked_pair()
    other_observation, other_evidence = linked_pair()
    result = validate(
        primary_observation.research_session_id,
        [candidate(other_observation, other_evidence)],
        [primary_observation, other_observation],
        [primary_evidence, other_evidence],
    )
    assert result.rejected[0].code is HypothesisRejectionCode.CROSS_SESSION_REFERENCE


def test_confidence_above_one_is_schema_rejected() -> None:
    observation, evidence = linked_pair()
    with pytest.raises(ValidationError):
        candidate(observation, evidence, confidence=1.01)


def test_hypothesis_limit_and_duplicates_are_deterministic() -> None:
    observation, evidence = linked_pair()
    first = candidate(observation, evidence)
    duplicate = candidate(observation, evidence, title=" POSSIBLE order authorization behavior ")
    extra = candidate(observation, evidence, title="Second distinct hypothesis")
    result = validate(
        observation.research_session_id,
        [first, duplicate, extra],
        [observation],
        [evidence],
        max_hypotheses=1,
    )
    assert len(result.accepted) == 1
    assert [item.code for item in result.rejected] == [
        HypothesisRejectionCode.DUPLICATE_HYPOTHESIS,
        HypothesisRejectionCode.MAX_HYPOTHESES_EXCEEDED,
    ]


def test_hallucinated_endpoint_is_rejected() -> None:
    observation, evidence = linked_pair()
    proposed = candidate(
        observation,
        evidence,
        description="The observed /api/secret-debug endpoint may expose data.",
    )
    result = validate(
        observation.research_session_id, [proposed], [observation], [evidence]
    )
    assert result.rejected[0].code is HypothesisRejectionCode.UNSUPPORTED_CONTEXT_REFERENCE
