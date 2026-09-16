from app.domain.common import Provenance, utc_now
from app.domain.evaluation import (
    BenchmarkMetrics,
    BenchmarkMode,
    BenchmarkRun,
    BenchmarkStatus,
)
from evals.reporting import compare_runs


def benchmark(*, precision: float, requests: int, runtime: int) -> BenchmarkRun:
    metrics = BenchmarkMetrics(
        scenario_count=1,
        completed=1,
        tp=1,
        precision=precision,
        recall=1.0,
        f1=2 * precision / (precision + 1),
        accuracy=1.0,
        http_requests=requests,
        runtime_ms=runtime,
    )
    return BenchmarkRun(
        name="comparison",
        mode=BenchmarkMode.DETERMINISTIC,
        status=BenchmarkStatus.COMPLETED,
        finished_at=utc_now(),
        provider="fake",
        model="fixture",
        hypothesis_prompt_version="hypothesis-v1",
        experiment_prompt_version="experiment-v2",
        verifier_version="verification-v1",
        scenario_count=1,
        configuration_snapshot={},
        configuration_sha256="a" * 64,
        ground_truth_sha256="b" * 64,
        harness_version="harness-v1",
        harness_sha256="c" * 64,
        metrics=metrics,
        provenance=Provenance(source_type="test", source_reference="reporting"),
    )


def test_benchmark_comparison_uses_explicit_b_minus_a_direction() -> None:
    result = compare_runs(
        benchmark(precision=0.5, requests=10, runtime=100),
        benchmark(precision=0.75, requests=8, runtime=150),
    )
    assert result["direction"] == "B - A"
    assert result["metrics"]["precision"]["delta_b_minus_a"] == 0.25
    assert result["metrics"]["http_requests"]["delta_b_minus_a"] == -2
    assert result["metrics"]["runtime_ms"]["delta_b_minus_a"] == 50
