import json
from pathlib import Path
from uuid import UUID

from app.domain.evaluation import BenchmarkRun
from app.storage.database import Database
from app.storage.repositories import RepositorySet


def benchmark_document(database: Database, run_id: UUID) -> dict[str, object]:
    with database.session_factory() as session:
        repositories = RepositorySet(session)
        run = repositories.benchmark_runs.get(run_id)
        if run is None:
            raise ValueError("benchmark run does not exist")
        scenarios = repositories.scenario_evaluations.list_by_benchmark(run_id)
    return {
        "benchmark": run.model_dump(mode="json"),
        "scenarios": [item.model_dump(mode="json") for item in scenarios],
    }


def export_json(database: Database, run_id: UUID, root: Path) -> Path:
    document = benchmark_document(database, run_id)
    output = root / str(run_id)
    output.mkdir(parents=True, exist_ok=True)
    (output / "summary.json").write_text(
        json.dumps(document["benchmark"], indent=2, sort_keys=True), encoding="utf-8"
    )
    (output / "scenarios.json").write_text(
        json.dumps(document["scenarios"], indent=2, sort_keys=True), encoding="utf-8"
    )
    benchmark = document["benchmark"]
    (output / "config.json").write_text(
        json.dumps(benchmark["configuration_snapshot"], indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return output


def compare_runs(run_a: BenchmarkRun, run_b: BenchmarkRun) -> dict[str, object]:
    if run_a.metrics is None or run_b.metrics is None:
        raise ValueError("both benchmark runs require persisted metrics")
    fields = (
        "precision",
        "recall",
        "f1",
        "fp",
        "fn",
        "inconclusive_count",
        "http_requests",
        "llm_total_tokens",
        "runtime_ms",
    )
    comparison = {}
    for field in fields:
        a = getattr(run_a.metrics, field)
        b = getattr(run_b.metrics, field)
        comparison[field] = {
            "a": a,
            "b": b,
            "delta_b_minus_a": b - a if a is not None and b is not None else None,
        }
    return {
        "run_a": str(run_a.id),
        "run_b": str(run_b.id),
        "direction": "B - A",
        "metrics": comparison,
    }
