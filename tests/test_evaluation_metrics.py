from app.domain.common import Provenance
from app.domain.evaluation import (
    EvaluationClassification,
    PipelineMetrics,
    ScenarioEvaluation,
    ScenarioRun,
    ScenarioRunStatus,
    FailureStage,
)
from app.domain.verification import VerificationVerdict
from evals.evaluator import classify
from evals.evaluator import evaluate_scenario
from evals.metrics import aggregate_metrics


def evaluation(classification: EvaluationClassification, vulnerability: bool | None):
    return ScenarioEvaluation(
        benchmark_run_id="00000000-0000-0000-0000-000000000001",
        scenario_run_id="00000000-0000-0000-0000-000000000002",
        scenario_id="LAB-001",
        research_session_id="00000000-0000-0000-0000-000000000003",
        expected_vulnerability=vulnerability,
        expected_verdict=(
            VerificationVerdict.SUPPORTED
            if vulnerability is True
            else VerificationVerdict.REJECTED
            if vulnerability is False
            else VerificationVerdict.INCONCLUSIVE
        ),
        expected_class="test",
        selected_actual_verdict=VerificationVerdict.REJECTED,
        classification=classification,
        metrics=PipelineMetrics(
            observations=2,
            evidence_records=2,
            hypotheses_generated=1,
            hypotheses_accepted=1,
            experiments_generated=1,
            experiments_validated=1,
            policy_approvals=2,
            experiment_executions=1,
            verification_runs=1,
            http_requests=4,
            llm_runs=2,
            llm_input_tokens=None,
            llm_output_tokens=None,
            llm_total_tokens=None,
            runtime_ms=10,
        ),
        duration_ms=10,
        provenance=Provenance(source_type="test", source_reference="metrics"),
    )


def test_classification_matrix_and_inconclusive_semantics() -> None:
    assert classify(True, VerificationVerdict.SUPPORTED) is EvaluationClassification.TP
    assert classify(True, VerificationVerdict.REJECTED) is EvaluationClassification.FN
    assert classify(False, VerificationVerdict.REJECTED) is EvaluationClassification.TN
    assert classify(False, VerificationVerdict.SUPPORTED) is EvaluationClassification.FP
    assert (
        classify(None, VerificationVerdict.INCONCLUSIVE)
        is EvaluationClassification.CORRECT_INCONCLUSIVE
    )
    assert (
        classify(True, VerificationVerdict.INCONCLUSIVE)
        is EvaluationClassification.UNEXPECTED_INCONCLUSIVE
    )
    assert (
        classify(False, VerificationVerdict.INCONCLUSIVE)
        is EvaluationClassification.UNEXPECTED_INCONCLUSIVE
    )
    assert classify(True, None) is EvaluationClassification.FN
    assert classify(False, None) is EvaluationClassification.TN
    assert (
        classify(True, VerificationVerdict.REJECTED, completed=False)
        is EvaluationClassification.NOT_SCORED
    )


def test_standard_metrics_without_intermediate_rounding() -> None:
    items = (
        [evaluation(EvaluationClassification.TP, True) for _ in range(8)]
        + [evaluation(EvaluationClassification.FP, False) for _ in range(2)]
        + [evaluation(EvaluationClassification.FN, True) for _ in range(4)]
    )
    metrics = aggregate_metrics(items, benchmark_runtime_ms=123)
    assert metrics.precision == 0.8
    assert metrics.recall == 8 / 12
    assert metrics.f1 == 2 * 0.8 * (8 / 12) / (0.8 + (8 / 12))
    assert metrics.f1 == 0.7272727272727272
    assert metrics.http_requests == 56
    assert metrics.llm_total_tokens is None


def test_undefined_metrics_are_null_with_reasons() -> None:
    metrics = aggregate_metrics(
        [evaluation(EvaluationClassification.TN, False)], benchmark_runtime_ms=1
    )
    assert metrics.precision is None
    assert metrics.recall is None
    assert metrics.f1 is None
    assert metrics.undefined_reasons == {
        "precision": "undefined_no_positive_predictions",
        "recall": "undefined_no_expected_positive_binary_results",
        "f1": "undefined_precision_or_recall",
    }


def test_inconclusive_and_failure_denominators_remain_visible() -> None:
    metrics = aggregate_metrics(
        [
            evaluation(EvaluationClassification.CORRECT_INCONCLUSIVE, None),
            evaluation(EvaluationClassification.UNEXPECTED_INCONCLUSIVE, True),
            evaluation(EvaluationClassification.NOT_SCORED, True),
        ],
        benchmark_runtime_ms=5,
    )
    assert metrics.correct_inconclusive == 1
    assert metrics.unexpected_inconclusive == 1
    assert metrics.inconclusive_count == 2
    assert metrics.completed == 2
    assert metrics.failed == 1
    assert metrics.inconclusive_rate == 1.0
    assert metrics.correct_inconclusive_rate == 1.0


def test_provider_and_pipeline_failures_are_not_security_predictions() -> None:
    from lab.ground_truth import load_ground_truth

    truth = next(item for item in load_ground_truth() if item.id == "LAB-002")
    for status, stage in (
        (ScenarioRunStatus.FAILED_PROVIDER, FailureStage.PROVIDER),
        (ScenarioRunStatus.FAILED_PIPELINE, FailureStage.EXECUTION),
    ):
        run = ScenarioRun(
            benchmark_run_id="00000000-0000-0000-0000-000000000001",
            scenario_id="LAB-002",
            research_session_id="00000000-0000-0000-0000-000000000003",
            status=status,
            failure_stage=stage,
            provenance=Provenance(source_type="test", source_reference="failure"),
        )
        result = evaluate_scenario(
            truth=truth,
            scenario_run=run,
            actual_verdict=None,
            hypothesis_ids=[],
            experiment_ids=[],
            verification_ids=[],
            finding_ids=[],
            metrics=PipelineMetrics(),
            duration_ms=1,
        )
        assert result.classification is EvaluationClassification.NOT_SCORED
        assert result.failure_stage is stage
