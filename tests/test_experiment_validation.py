from app.domain.experiments import HTTPExperimentAction, RiskLevel
from app.domain.verification import (
    ComparisonOperator,
    ComparisonSpec,
    ComparisonType,
    VerificationSpec,
)
from app.reasoning.experiment_schemas import ExperimentProposal
from app.reasoning.experiment_validation import ExperimentValidator


def proposal(**candidate_changes: object) -> ExperimentProposal:
    candidate = {
        "method": "GET",
        "path": "/api/orders/101",
        "identity": "bob",
        **candidate_changes,
    }
    return ExperimentProposal(
        description="Compare access using two logical identities",
        changed_variable="identity",
        constants=["method", "path"],
        preconditions=["identities are configured"],
        candidate=HTTPExperimentAction(**candidate),
        control=HTTPExperimentAction(
            method="GET", path="/api/orders/101", identity="alice"
        ),
        expected_if_true="candidate and control expose the same object",
        expected_if_false="candidate is denied",
        risk=RiskLevel.LOW,
    )


def test_valid_candidate_control_and_deterministic_rejections() -> None:
    validator = ExperimentValidator()
    paths = frozenset({"/api/orders/101"})
    assert validator.validate(proposal(), allowed_paths=paths).valid

    cases = [
        (proposal(path="/api/debug/root"), "PATH_NOT_GROUNDED"),
        (proposal(path="https://outside.invalid/root"), "INVALID_PATH"),
        (proposal(identity="root"), "IDENTITY_NOT_ALLOWED"),
        (proposal(method="POST"), "METHOD_NOT_ALLOWED"),
        (proposal(headers={"Authorization": "Bearer attacker"}), "HEADER_NOT_ALLOWED"),
        (proposal(headers={"Host": "outside.invalid"}), "HEADER_NOT_ALLOWED"),
    ]
    for item, code in cases:
        result = validator.validate(item, allowed_paths=paths)
        assert not result.valid
        assert code in {error["code"] for error in result.errors}


def test_high_risk_and_identical_control_are_rejected() -> None:
    item = proposal()
    item = item.model_copy(update={"risk": RiskLevel.HIGH, "control": item.candidate})
    result = ExperimentValidator().validate(
        ExperimentProposal.model_validate(item), allowed_paths=frozenset({"/api/orders/101"})
    )
    assert {error["code"] for error in result.errors} == {
        "RISK_NOT_ALLOWED",
        "CONTROL_NOT_FALSIFYING",
    }


def test_status_code_alone_cannot_be_declared_observable_impact() -> None:
    item = proposal().model_copy(
        update={
            "verification_spec": VerificationSpec(
                rule_id="status-only",
                rule_version="v1",
                comparisons=[
                    ComparisonSpec(
                        type=ComparisonType.STATUS_CODE,
                        operator=ComparisonOperator.EQUAL,
                        impact=True,
                    )
                ],
            )
        }
    )
    result = ExperimentValidator().validate(
        item, allowed_paths=frozenset({"/api/orders/101"})
    )
    assert "STATUS_NOT_OBSERVABLE_IMPACT" in {
        error["code"] for error in result.errors
    }
