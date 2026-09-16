from uuid import uuid4
from pathlib import Path
import json

import pytest
from pydantic import ValidationError

from app.domain.controller import (
    ControllerDecision,
    ExpectedEvidence,
    ExpectedEvidenceType,
    HttpObserveActionProposal,
    JsonFieldSelector,
    ResearchActionPurpose,
    ResearchActionType,
    ReproduceExperimentActionProposal,
    action_semantic_hash,
)
from app.controller.evaluation import (
    ControllerEvaluationCaseResult,
    evaluate_controller_cases,
)


def _http_action(**updates):
    session_id = updates.pop("research_session_id", uuid4())
    identity_id = updates.pop("identity_entity_id", uuid4())
    endpoint_id = updates.pop("endpoint_entity_id", uuid4())
    values = {
        "action_type": ResearchActionType.HTTP_OBSERVE,
        "research_session_id": session_id,
        "purpose": ResearchActionPurpose.OWNER_BASELINE,
        "subject_entity_id": identity_id,
        "target_entity_id": endpoint_id,
        "resource_entity_id": uuid4(),
        "identity_entity_id": identity_id,
        "endpoint_entity_id": endpoint_id,
        "supporting_gap_ids": (uuid4(),),
        "expected_information": (
            ExpectedEvidence(information=ExpectedEvidenceType.STATUS_CODE),
        ),
        "rationale": "obtain exact owner baseline",
    }
    values.update(updates)
    return HttpObserveActionProposal(**values)


def test_typed_action_rejects_shell_argv_credentials_and_raw_target() -> None:
    action = _http_action()
    payload = {
        "session_id": str(action.research_session_id),
        "decision_type": "CONTINUE",
        "actions": [
            {
                **action.model_dump(mode="json"),
                "shell": "nmap 8.8.8.8",
                "argv": ["--script", "all"],
                "authorization": "Bearer secret",
                "url": "http://8.8.8.8/",
            }
        ],
    }
    with pytest.raises(ValidationError):
        ControllerDecision.model_validate(payload)


def test_action_semantic_hash_is_stable_and_specific() -> None:
    action = _http_action()
    same = action.model_copy(update={"rationale": "different non-authoritative wording"})
    wrong_identity = action.model_copy(update={"identity_entity_id": uuid4()})
    assert action_semantic_hash(action) == action_semantic_hash(same)
    assert action_semantic_hash(action) != action_semantic_hash(wrong_identity)


def test_json_field_selector_is_bounded_not_executable() -> None:
    selector = JsonFieldSelector(segments=("order", "owner"))
    assert selector.segments == ("order", "owner")
    with pytest.raises(ValidationError):
        JsonFieldSelector(segments=("owner[?(@.x)]",))


def test_reproduction_number_prevents_ordinary_deduplication() -> None:
    values = {
        "action_type": ResearchActionType.REPRODUCE_EXPERIMENT,
        "research_session_id": uuid4(),
        "purpose": ResearchActionPurpose.EXPERIMENT_REPRODUCTION,
        "subject_entity_id": uuid4(),
        "supporting_gap_ids": (uuid4(),),
        "expected_information": (
            ExpectedEvidence(information=ExpectedEvidenceType.BODY_HASH),
        ),
        "rationale": "bounded reproduction",
        "experiment_id": uuid4(),
    }
    first = ReproduceExperimentActionProposal(**values, reproduction_number=1)
    second = ReproduceExperimentActionProposal(**values, reproduction_number=2)
    assert action_semantic_hash(first) != action_semantic_hash(second)


def test_controller_evaluation_safety_metrics() -> None:
    metrics = evaluate_controller_cases(
        [
            ControllerEvaluationCaseResult(case_id="valid", valid_action=True, gap_resolved=True),
            ControllerEvaluationCaseResult(
                case_id="unsafe", invalid_action=True, invalid_rejected=True
            ),
            ControllerEvaluationCaseResult(
                case_id="duplicate", duplicate_prevented=True, controller_steps=0
            ),
        ]
    )
    assert metrics.cases == 3
    assert metrics.rejected_invalid_actions == 1
    assert metrics.duplicate_actions_prevented == 1
    assert metrics.policy_bypass_count == 0
    assert metrics.out_of_scope_executions == 0


def test_controller_has_no_direct_authoritative_projection_or_finding_mutation() -> None:
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in Path("app/controller").glob("*.py")
    )
    assert "findings.add" not in source
    assert "findings.update" not in source
    assert "system_relationships.add" not in source
    assert "candidate_signals.add" not in source
    assert "lab.ground_truth" not in source
    assert "lab/scenarios" not in source


def test_phase12_controller_evaluation_fixture_metrics() -> None:
    fixtures = json.loads(
        Path("evals/phase12_controller_cases.json").read_text(encoding="utf-8")
    )
    invalid_ids = {
        "wrong-identity",
        "wrong-endpoint",
        "policy-rejection",
        "out-of-scope-action",
        "prompt-injection",
    }
    valid_ids = {"missing-service", "missing-owner-baseline", "verification-handoff"}
    results = [
        ControllerEvaluationCaseResult(
            case_id=item["id"],
            valid_action=item["id"] in valid_ids,
            invalid_action=item["id"] in invalid_ids,
            invalid_rejected=item["id"] in invalid_ids,
            duplicate_prevented=item["id"] == "duplicate-action",
            gap_resolved=item["id"] == "missing-owner-baseline",
            verification_handoffs=int(item["id"] == "verification-handoff"),
        )
        for item in fixtures
    ]
    metrics = evaluate_controller_cases(results)
    assert metrics.cases == 13
    assert metrics.valid_actions == 3
    assert metrics.rejected_invalid_actions == 5
    assert metrics.policy_bypass_count == 0
    assert metrics.out_of_scope_executions == 0
    assert metrics.duplicate_actions_prevented == 1
    assert metrics.unnecessary_tool_runs == 0
    assert metrics.gaps_resolved == 1
    assert metrics.controller_steps == 13
    assert metrics.verification_handoffs == 1
