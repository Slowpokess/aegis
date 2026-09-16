import json
from pathlib import Path

import pytest

from typer.testing import CliRunner

from app.config import Settings, get_settings
from app.domain.evaluation import (
    BenchmarkMode,
    BenchmarkStatus,
    EvaluationClassification,
)
from app.storage.database import Database
from app.storage.repositories import RepositorySet
from evals.entrypoint import cli
from evals.reporting import export_json
from evals.runner import BenchmarkRunner, current_git_commit


@pytest.mark.asyncio
async def test_all_scenarios_pipeline_benchmark_persists_metrics_and_exports(
    database: Database, live_lab: int, tmp_path: Path, monkeypatch
) -> None:
    settings = Settings(
        database_url=str(database.engine.url),
        eval_target_port=live_lab,
        executor_path=Path("native/rust/target/debug/aegis-executor"),
        policy_path=Path("native/rust/target/debug/aegis-policy"),
        eval_report_directory=tmp_path / "reports",
    )
    run = await BenchmarkRunner(database, settings).run(
        mode=BenchmarkMode.DETERMINISTIC,
        name="all-scenarios-test",
    )
    assert run.status is BenchmarkStatus.COMPLETED
    assert run.scenario_count == 8
    assert run.ground_truth_sha256 is not None
    assert run.git_commit == current_git_commit()
    assert run.metrics is not None
    assert (run.metrics.tp, run.metrics.fp, run.metrics.tn, run.metrics.fn) == (2, 0, 5, 0)
    assert run.metrics.correct_inconclusive == 1
    assert run.metrics.unexpected_inconclusive == 0
    assert run.metrics.precision == run.metrics.recall == run.metrics.f1 == 1.0
    assert run.metrics.observations == run.metrics.evidence_records == 29
    assert run.metrics.http_requests == 29
    assert run.metrics.hypotheses_generated == run.metrics.hypotheses_accepted == 8
    assert run.metrics.hypotheses_rejected == 0
    assert run.metrics.experiments_generated == run.metrics.experiments_validated == 8
    assert run.metrics.policy_approvals == 14
    assert run.metrics.policy_rejections == 0
    assert run.metrics.experiment_executions == run.metrics.verification_runs == 8
    assert run.metrics.findings == 2
    assert run.metrics.llm_runs == 16
    assert run.metrics.llm_total_tokens is None

    with database.session_factory() as session:
        repositories = RepositorySet(session)
        scenarios = repositories.scenario_evaluations.list_by_benchmark(run.id)
        assert repositories.benchmark_runs.get(run.id) == run
        assert len(repositories.scenario_runs.list_by_benchmark(run.id)) == 8
    classes = {item.scenario_id: item.classification for item in scenarios}
    assert classes == {
        "LAB-001": EvaluationClassification.TN,
        "LAB-002": EvaluationClassification.TP,
        "LAB-003": EvaluationClassification.TN,
        "LAB-004": EvaluationClassification.TP,
        "LAB-005": EvaluationClassification.TN,
        "LAB-006": EvaluationClassification.CORRECT_INCONCLUSIVE,
        "LAB-007": EvaluationClassification.TN,
        "LAB-008": EvaluationClassification.TN,
    }
    output = export_json(database, run.id, tmp_path / "export")
    assert {item.name for item in output.iterdir()} == {
        "summary.json",
        "scenarios.json",
        "config.json",
    }
    exported = "\n".join(item.read_text() for item in output.iterdir())
    assert "Authorization" not in exported
    assert "alice-token" not in exported

    monkeypatch.setenv("AEGIS_DATABASE_URL", str(database.engine.url))
    monkeypatch.setenv("AEGIS_EVAL_REPORT_DIRECTORY", str(tmp_path / "cli-export"))
    get_settings.cache_clear()
    listed = CliRunner().invoke(cli, ["eval", "list"])
    assert listed.exit_code == 0, listed.output
    assert json.loads(listed.output)[0]["run_id"] == str(run.id)
    shown = CliRunner().invoke(cli, ["eval", "show", str(run.id)])
    assert shown.exit_code == 0, shown.output
    assert len(json.loads(shown.output)["scenarios"]) == 8
    detail = CliRunner().invoke(cli, ["eval", "scenario", str(run.id), "LAB-002"])
    assert detail.exit_code == 0, detail.output
    assert json.loads(detail.output)["classification"] == "TP"
    exported_cli = CliRunner().invoke(cli, ["eval", "export", str(run.id)])
    assert exported_cli.exit_code == 0, exported_cli.output
    assert Path(exported_cli.output.strip()).is_dir()
    compared = CliRunner().invoke(
        cli, ["eval", "compare", str(run.id), str(run.id)]
    )
    assert compared.exit_code == 0, compared.output
    assert json.loads(compared.output)["metrics"]["f1"]["delta_b_minus_a"] == 0
    get_settings.cache_clear()
