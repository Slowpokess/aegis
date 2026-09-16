import asyncio
import json
from pathlib import Path
from typing import Annotated
from uuid import UUID

import typer

from app.collectors.pipeline import ObservationPipeline
from app.config import get_settings
from app.discovery.engine import DiscoveryEngine
from app.discovery.registry import ToolRegistry
from app.domain.discovery import DiscoveryProfile
from app.execution.rust_executor import RustExecutorClient
from app.storage.database import Database
from app.storage.repositories import RepositorySet

tools_cli = typer.Typer(help="Inspect the authoritative controlled-tool registry.")
discover_cli = typer.Typer(help="Plan and explicitly run bounded discovery.")
tool_runs_cli = typer.Typer(help="Inspect persisted controlled tool runs.")
artifacts_cli = typer.Typer(help="Inspect immutable tool artifacts.")


def _registry() -> ToolRegistry:
    settings = get_settings()
    return ToolRegistry(enabled={"nmap": settings.nmap_enabled})


def _database() -> Database:
    database = Database(get_settings().database_url)
    database.create_schema()
    return database


def _engine(database: Database) -> DiscoveryEngine:
    settings = get_settings()
    pipeline = ObservationPipeline(
        database,
        RustExecutorClient(
            settings.executor_path,
            process_grace_seconds=settings.executor_process_grace_seconds,
        ),
    )
    return DiscoveryEngine(
        database,
        _registry(),
        pipeline,
        artifact_max_bytes=settings.tool_artifact_max_bytes,
        max_concurrency=settings.tool_max_concurrency,
        max_runs_per_plan=settings.tool_max_runs_per_plan,
    )


@tools_cli.command("list")
def tools_list() -> None:
    typer.echo(
        json.dumps(
            [descriptor.model_dump(mode="json") for descriptor in _registry().list()],
            sort_keys=True,
        )
    )


@tools_cli.command("show")
def tools_show(tool_id: str) -> None:
    try:
        descriptor = _registry().require(tool_id)
    except ValueError as error:
        raise typer.BadParameter(str(error)) from error
    typer.echo(descriptor.model_dump_json())


@tools_cli.command("doctor")
def tools_doctor() -> None:
    typer.echo(
        json.dumps(
            {
                descriptor.id: {
                    "available": descriptor.available,
                    "enabled": descriptor.enabled,
                    "version": descriptor.version,
                    "executable_path": descriptor.executable_path,
                }
                for descriptor in _registry().list()
            },
            sort_keys=True,
        )
    )


@discover_cli.command("plan")
def discover_plan(
    session_id: Annotated[UUID, typer.Option("--session")],
    profile: Annotated[DiscoveryProfile, typer.Option(case_sensitive=False)] = (
        DiscoveryProfile.STANDARD
    ),
) -> None:
    database = _database()
    try:
        plan = _engine(database).create_plan(session_id, profile)
        typer.echo(plan.model_dump_json())
    finally:
        database.dispose()


@discover_cli.command("run")
def discover_run(plan_id: UUID) -> None:
    database = _database()
    try:
        engine = _engine(database)
        plan = asyncio.run(engine.run(plan_id))
        with database.session_factory() as session:
            runs = RepositorySet(session).tool_runs.list_by_plan(plan.id)
        typer.echo(
            json.dumps(
                {
                    "plan_id": str(plan.id),
                    "status": plan.status.value,
                    "tool_runs": [run.model_dump(mode="json") for run in runs],
                },
                sort_keys=True,
            )
        )
    finally:
        database.dispose()


@discover_cli.command("export")
def discover_export(
    plan_id: UUID,
    export_format: Annotated[str, typer.Option("--format")] = "json",
    output: Annotated[Path | None, typer.Option("--output")] = None,
) -> None:
    if export_format.lower() != "json":
        raise typer.BadParameter("Phase 9 supports only JSON discovery export")
    database = _database()
    try:
        encoded = json.dumps(_engine(database).export(plan_id), indent=2, sort_keys=True)
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(encoded + "\n", encoding="utf-8")
            typer.echo(str(output))
        else:
            typer.echo(encoded)
    finally:
        database.dispose()


@tool_runs_cli.command("list")
def tool_runs_list(
    session_id: Annotated[UUID, typer.Option("--session")],
) -> None:
    database = _database()
    try:
        with database.session_factory() as session:
            runs = RepositorySet(session).tool_runs.list_by_session(session_id)
        typer.echo(json.dumps([run.model_dump(mode="json") for run in runs], sort_keys=True))
    finally:
        database.dispose()


@tool_runs_cli.command("show")
def tool_runs_show(tool_run_id: UUID) -> None:
    database = _database()
    try:
        with database.session_factory() as session:
            repositories = RepositorySet(session)
            run = repositories.tool_runs.get(tool_run_id)
            artifacts = repositories.tool_artifacts.list_by_run(tool_run_id)
        if run is None:
            raise typer.BadParameter("tool run does not exist")
        typer.echo(
            json.dumps(
                {
                    "run": run.model_dump(mode="json"),
                    "artifacts": [
                        item.model_dump(mode="json", exclude={"content_base64"})
                        for item in artifacts
                    ],
                },
                sort_keys=True,
            )
        )
    finally:
        database.dispose()


@artifacts_cli.command("show")
def artifacts_show(
    artifact_id: UUID,
    raw: Annotated[bool, typer.Option("--raw")] = False,
) -> None:
    database = _database()
    try:
        with database.session_factory() as session:
            artifact = RepositorySet(session).tool_artifacts.get(artifact_id)
        if artifact is None:
            raise typer.BadParameter("tool artifact does not exist")
        if raw:
            if not artifact.content_type.startswith(("text/", "application/json", "application/xml")):
                raise typer.BadParameter("binary artifacts cannot be printed to the terminal")
            typer.echo(artifact.content_bytes().decode(errors="replace"))
        else:
            typer.echo(
                json.dumps(
                    artifact.model_dump(mode="json", exclude={"content_base64"}),
                    sort_keys=True,
                )
            )
    finally:
        database.dispose()
