from app.domain.common import FactClassification, Provenance
from app.domain.evaluation import (
    EvaluationClassification,
    PipelineMetrics,
    ScenarioEvaluation,
    ScenarioRun,
    ScenarioRunStatus,
)
from app.domain.verification import VerificationVerdict
from lab.ground_truth import GroundTruthScenario


def classify(
    vulnerability: bool | None,
    actual: VerificationVerdict | None,
    *,
    completed: bool = True,
) -> EvaluationClassification:
    if not completed:
        return EvaluationClassification.NOT_SCORED
    if vulnerability is None:
        return (
            EvaluationClassification.CORRECT_INCONCLUSIVE
            if actual is VerificationVerdict.INCONCLUSIVE
            else EvaluationClassification.NOT_SCORED
        )
    if actual is VerificationVerdict.INCONCLUSIVE:
        return EvaluationClassification.UNEXPECTED_INCONCLUSIVE
    predicted_positive = actual is VerificationVerdict.SUPPORTED
    if actual is None:
        predicted_positive = False
    if vulnerability and predicted_positive:
        return EvaluationClassification.TP
    if vulnerability:
        return EvaluationClassification.FN
    if predicted_positive:
        return EvaluationClassification.FP
    return EvaluationClassification.TN


def evaluate_scenario(
    *,
    truth: GroundTruthScenario,
    scenario_run: ScenarioRun,
    actual_verdict: VerificationVerdict | None,
    hypothesis_ids: list,
    experiment_ids: list,
    verification_ids: list,
    finding_ids: list,
    metrics: PipelineMetrics,
    duration_ms: int,
) -> ScenarioEvaluation:
    completed = scenario_run.status is ScenarioRunStatus.COMPLETED
    classification = classify(truth.vulnerability, actual_verdict, completed=completed)
    return ScenarioEvaluation(
        benchmark_run_id=scenario_run.benchmark_run_id,
        scenario_run_id=scenario_run.id,
        scenario_id=scenario_run.scenario_id,
        research_session_id=scenario_run.research_session_id,
        expected_vulnerability=truth.vulnerability,
        expected_verdict=VerificationVerdict(truth.expected_verdict.value),
        expected_class=truth.vulnerability_class,
        actual_hypothesis_ids=hypothesis_ids,
        actual_experiment_ids=experiment_ids,
        actual_verification_ids=verification_ids,
        actual_finding_ids=finding_ids,
        selected_actual_verdict=actual_verdict,
        classification=classification,
        failure_stage=scenario_run.failure_stage,
        matched_finding_id=finding_ids[0] if len(finding_ids) == 1 else None,
        metrics=metrics,
        duration_ms=duration_ms,
        provenance=Provenance(
            source_type="evaluation",
            source_reference=scenario_run.scenario_id,
            collector="aegis-evaluator",
            classification=FactClassification.OBSERVED,
        ),
    )
