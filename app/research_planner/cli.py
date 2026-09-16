import asyncio
import json
from pathlib import Path
from typing import Annotated
from uuid import UUID

import typer

from app.config import get_settings
from app.discovery.cli import _database, _engine
from app.domain.research_planner import PlannerDecision
from app.llm.providers.fake import FakeLLMProvider
from app.research_planner.engine import ResearchEngine
from app.storage.repositories import RepositorySet


def _research_engine(decision_file: Path | None = None) -> tuple[object, ResearchEngine]:
    database = _database()
    provider = None
    if decision_file:
        decision = PlannerDecision.model_validate_json(decision_file.read_text())
        provider = FakeLLMProvider([decision], model="fake-research-planner-v1")
    return database, ResearchEngine(
        database, get_settings(), _engine(database), provider=provider
    )


def register_research_planner_commands(research_cli: typer.Typer) -> None:
    @research_cli.command("plan")
    def research_plan(
        session_id: Annotated[UUID, typer.Option("--session")],
        decision_file: Annotated[Path | None, typer.Option("--decision-file")] = None,
    ) -> None:
        """Persist proposal/resolution/policy preview without executing tools."""
        database, engine = _research_engine(decision_file)
        try:
            step = asyncio.run(engine.step(session_id, execute=False))
            with database.session_factory() as session:
                intents = RepositorySet(session).research_intents.list_by_step(step.id)
            typer.echo(
                json.dumps(
                    {
                        "research_step": step.model_dump(mode="json"),
                        "intents": [item.model_dump(mode="json") for item in intents],
                        "tool_processes_invoked": 0,
                    },
                    sort_keys=True,
                )
            )
        finally:
            database.dispose()

    @research_cli.command("step")
    def research_step(
        session_id: Annotated[UUID, typer.Option("--session")],
        decision_file: Annotated[Path | None, typer.Option("--decision-file")] = None,
    ) -> None:
        database, engine = _research_engine(decision_file)
        try:
            typer.echo(asyncio.run(engine.step(session_id)).model_dump_json())
        finally:
            database.dispose()

    @research_cli.command("run")
    def research_run(session_id: Annotated[UUID, typer.Option("--session")]) -> None:
        database, engine = _research_engine()
        try:
            typer.echo(asyncio.run(engine.run(session_id)).model_dump_json())
        finally:
            database.dispose()

    @research_cli.command("resume")
    def research_resume(session_id: Annotated[UUID, typer.Option("--session")]) -> None:
        research_run(session_id)

    @research_cli.command("steps")
    def research_steps(session_id: Annotated[UUID, typer.Option("--session")]) -> None:
        database = _database()
        try:
            with database.session_factory() as session:
                values = RepositorySet(session).research_steps.list_by_session(session_id)
            typer.echo(json.dumps([item.model_dump(mode="json") for item in values], sort_keys=True))
        finally:
            database.dispose()

    @research_cli.command("step-show")
    def research_step_show(step_id: UUID) -> None:
        database = _database()
        try:
            with database.session_factory() as session:
                repositories = RepositorySet(session)
                step = repositories.research_steps.get(step_id)
                intents = repositories.research_intents.list_by_step(step_id)
            if step is None:
                raise typer.BadParameter("research step does not exist")
            typer.echo(
                json.dumps(
                    {
                        "step": step.model_dump(mode="json"),
                        "intents": [item.model_dump(mode="json") for item in intents],
                    },
                    sort_keys=True,
                )
            )
        finally:
            database.dispose()

    @research_cli.command("intents")
    def research_intents(
        session_id: Annotated[UUID, typer.Option("--session")],
    ) -> None:
        database = _database()
        try:
            with database.session_factory() as session:
                values = RepositorySet(session).research_intents.list_by_session(session_id)
            typer.echo(json.dumps([item.model_dump(mode="json") for item in values], sort_keys=True))
        finally:
            database.dispose()

    @research_cli.command("export")
    def research_export(
        session_id: Annotated[UUID, typer.Option("--session")],
        output_format: Annotated[str, typer.Option("--format")] = "json",
    ) -> None:
        if output_format != "json":
            raise typer.BadParameter("only json is supported")
        database = _database()
        try:
            with database.session_factory() as session:
                repositories = RepositorySet(session)
                steps = repositories.research_steps.list_by_session(session_id)
                intents = repositories.research_intents.list_by_session(session_id)
                plan_ids = {item.discovery_plan_id for item in intents if item.discovery_plan_id}
                plans = [repositories.discovery_plans.get(item) for item in sorted(plan_ids)]
                runs = repositories.tool_runs.list_by_session(session_id)
                artifacts = [
                    artifact
                    for run in runs
                    for artifact in repositories.tool_artifacts.list_by_run(run.id)
                ]
                observations = repositories.observations.list_by_session(session_id)
            typer.echo(
                json.dumps(
                    {
                        "session_id": str(session_id),
                        "steps": [item.model_dump(mode="json") for item in steps],
                        "intents": [item.model_dump(mode="json") for item in intents],
                        "discovery_plans": [
                            item.model_dump(mode="json") for item in plans if item
                        ],
                        "tool_runs": [item.model_dump(mode="json") for item in runs],
                        "artifacts": [
                            {
                                "id": str(item.id),
                                "tool_run_id": str(item.tool_run_id),
                                "sha256": item.sha256,
                                "size_bytes": item.size_bytes,
                                "parser_version": item.parser_version,
                            }
                            for item in artifacts
                        ],
                        "observation_ids": [str(item.id) for item in observations],
                    },
                    sort_keys=True,
                )
            )
        finally:
            database.dispose()
