from app.domain.evaluation import (
    BenchmarkMetrics,
    EvaluationClassification,
    ScenarioEvaluation,
)


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _sum_nullable(values: list[int | None]) -> int | None:
    if not values or any(item is None for item in values):
        return None
    return sum(item for item in values if item is not None)


def aggregate_metrics(
    evaluations: list[ScenarioEvaluation], *, benchmark_runtime_ms: int
) -> BenchmarkMetrics:
    counts = {classification: 0 for classification in EvaluationClassification}
    for item in evaluations:
        counts[item.classification] += 1
    tp = counts[EvaluationClassification.TP]
    fp = counts[EvaluationClassification.FP]
    tn = counts[EvaluationClassification.TN]
    fn = counts[EvaluationClassification.FN]
    correct = counts[EvaluationClassification.CORRECT_INCONCLUSIVE]
    unexpected = counts[EvaluationClassification.UNEXPECTED_INCONCLUSIVE]
    failed = counts[EvaluationClassification.NOT_SCORED]
    completed = len(evaluations) - failed
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = None
    if precision is not None and recall is not None and precision + recall:
        f1 = 2 * precision * recall / (precision + recall)
    undefined: dict[str, str] = {}
    if precision is None:
        undefined["precision"] = "undefined_no_positive_predictions"
    if recall is None:
        undefined["recall"] = "undefined_no_expected_positive_binary_results"
    if f1 is None:
        undefined["f1"] = "undefined_precision_or_recall"
    pipeline = [item.metrics for item in evaluations]
    integer_fields = (
        "observations",
        "evidence_records",
        "hypotheses_generated",
        "hypotheses_accepted",
        "hypotheses_rejected",
        "experiments_generated",
        "experiments_validated",
        "experiments_rejected",
        "policy_approvals",
        "policy_rejections",
        "experiment_executions",
        "verification_runs",
        "findings",
        "http_requests",
        "llm_runs",
    )
    totals = {field: sum(getattr(item, field) for item in pipeline) for field in integer_fields}
    input_tokens = _sum_nullable([item.llm_input_tokens for item in pipeline])
    output_tokens = _sum_nullable([item.llm_output_tokens for item in pipeline])
    total_tokens = _sum_nullable([item.llm_total_tokens for item in pipeline])
    llm_latency = _sum_nullable([item.llm_latency_ms for item in pipeline])
    binary_total = tp + fp + tn + fn
    ambiguous_total = sum(item.expected_vulnerability is None for item in evaluations)
    inconclusive = correct + unexpected
    return BenchmarkMetrics(
        **totals,
        llm_input_tokens=input_tokens,
        llm_output_tokens=output_tokens,
        llm_total_tokens=total_tokens,
        llm_latency_ms=llm_latency,
        runtime_ms=benchmark_runtime_ms,
        scenario_count=len(evaluations),
        completed=completed,
        failed=failed,
        tp=tp,
        fp=fp,
        tn=tn,
        fn=fn,
        correct_inconclusive=correct,
        unexpected_inconclusive=unexpected,
        inconclusive_count=inconclusive,
        precision=precision,
        recall=recall,
        f1=f1,
        accuracy=_ratio(tp + tn, binary_total),
        false_positive_rate=_ratio(fp, fp + tn),
        false_negative_rate=_ratio(fn, fn + tp),
        inconclusive_rate=_ratio(inconclusive, completed),
        correct_inconclusive_rate=_ratio(correct, ambiguous_total),
        requests_per_finding=_ratio(totals["http_requests"], totals["findings"]),
        requests_per_tp=_ratio(totals["http_requests"], tp),
        tokens_per_hypothesis=(
            _ratio(total_tokens, totals["hypotheses_generated"])
            if total_tokens is not None
            else None
        ),
        tokens_per_finding=(
            _ratio(total_tokens, totals["findings"])
            if total_tokens is not None
            else None
        ),
        undefined_reasons=undefined,
    )
