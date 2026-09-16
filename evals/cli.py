import asyncio
import json
from pathlib import Path
from typing import Annotated
from uuid import UUID

import typer

from app.config import get_settings
from app.domain.evaluation import BenchmarkMode
from app.storage.database import Database
from app.storage.repositories import RepositorySet
from evals.reporting import benchmark_document, compare_runs, export_json
from evals.runner import BenchmarkRunner

eval_cli = typer.Typer(help="Run and inspect isolated ground-truth benchmarks.")


@eval_cli.command("run")
def eval_run(
    mode: Annotated[str, typer.Option(help="deterministic or live")] = "deterministic",
    scenario: Annotated[str | None, typer.Option(help="One LAB-NNN scenario.")] = None,
    all_scenarios: Annotated[bool, typer.Option("--all", help="Run all harness scenarios.")] = False,
    name: Annotated[str, typer.Option(help="Benchmark run name.")] = "phase6-benchmark",
) -> None:
    """Run a persisted benchmark against the controlled laboratory."""
    normalized = mode.strip().lower()
    if normalized not in {"deterministic", "live"}:
        raise typer.BadParameter("mode must be deterministic or live")
    if bool(scenario) == all_scenarios:
        raise typer.BadParameter("select exactly one of --scenario or --all")
    benchmark_mode = (
        BenchmarkMode.DETERMINISTIC if normalized == "deterministic" else BenchmarkMode.LIVE_LLM
    )
    settings = get_settings()
    if benchmark_mode is BenchmarkMode.LIVE_LLM:
        if settings.llm_provider == "anthropic" and settings.anthropic_api_key is None:
            typer.echo(
                json.dumps(
                    {
                        "executed": False,
                        "reason": "Anthropic authentication unavailable",
                    },
                    sort_keys=True,
                )
            )
            raise typer.Exit(code=2)
        raise typer.BadParameter("LIVE_LLM model benchmark harness is not configured")
    database = Database(settings.database_url)
    database.create_schema()
    try:
        run = asyncio.run(
            BenchmarkRunner(database, settings).run(
                mode=benchmark_mode,
                scenario_ids=[scenario] if scenario else None,
                name=name,
            )
        )
        typer.echo(json.dumps(run.model_dump(mode="json"), sort_keys=True))
    finally:
        database.dispose()


@eval_cli.command("list")
def eval_list() -> None:
    """List persisted benchmark summaries."""
    database = Database(get_settings().database_url)
    try:
        with database.session_factory() as session:
            runs = RepositorySet(session).benchmark_runs.list()
        rows = [
            {
                "run_id": str(item.id),
                "mode": item.mode.value,
                "provider": item.provider,
                "model": item.model,
                "scenarios": item.scenario_count,
                "precision": item.metrics.precision if item.metrics else None,
                "recall": item.metrics.recall if item.metrics else None,
                "f1": item.metrics.f1 if item.metrics else None,
                "status": item.status.value,
                "created": item.started_at.isoformat(),
            }
            for item in runs
        ]
        typer.echo(json.dumps(rows, sort_keys=True))
    finally:
        database.dispose()


@eval_cli.command("show")
def eval_show(run_id: UUID) -> None:
    """Show configuration, metrics, and all scenario evaluations."""
    database = Database(get_settings().database_url)
    try:
        typer.echo(json.dumps(benchmark_document(database, run_id), sort_keys=True))
    finally:
        database.dispose()


@eval_cli.command("scenario")
def eval_scenario(run_id: UUID, scenario_id: str) -> None:
    """Show one scenario's expected/actual lineage and metrics."""
    database = Database(get_settings().database_url)
    try:
        with database.session_factory() as session:
            item = RepositorySet(session).scenario_evaluations.get_by_benchmark_scenario(
                run_id, scenario_id
            )
        if item is None:
            raise typer.BadParameter("scenario evaluation does not exist")
        typer.echo(json.dumps(item.model_dump(mode="json"), sort_keys=True))
    finally:
        database.dispose()


@eval_cli.command("compare")
def eval_compare(run_a: UUID, run_b: UUID) -> None:
    """Compare persisted metrics using the explicit B-minus-A direction."""
    database = Database(get_settings().database_url)
    try:
        with database.session_factory() as session:
            repositories = RepositorySet(session)
            a = repositories.benchmark_runs.get(run_a)
            b = repositories.benchmark_runs.get(run_b)
        if a is None or b is None:
            raise typer.BadParameter("benchmark run does not exist")
        typer.echo(json.dumps(compare_runs(a, b), sort_keys=True))
    finally:
        database.dispose()


@eval_cli.command("export")
def eval_export(
    run_id: UUID,
    format_name: Annotated[str, typer.Option("--format")] = "json",
    output: Annotated[Path | None, typer.Option(help="Report root directory.")] = None,
) -> None:
    """Export sanitized JSON summary, scenario, and configuration artifacts."""
    if format_name.lower() != "json":
        raise typer.BadParameter("Phase 6 supports only JSON export")
    settings = get_settings()
    database = Database(settings.database_url)
    try:
        directory = export_json(database, run_id, output or settings.eval_report_directory)
        typer.echo(str(directory))
    finally:
        database.dispose()
