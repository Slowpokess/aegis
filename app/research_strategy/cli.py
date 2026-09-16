import json
from typing import Annotated
from uuid import UUID

import typer

from app.config import get_settings
from app.discovery.cli import _database, _engine
from app.research_planner.resolver import ToolResolver
from app.research_strategy.knowledge import KnowledgeService
from app.research_strategy.strategy import ResearchStrategyEngine
from app.storage.repositories import RepositorySet

knowledge_cli = typer.Typer(help="Inspect deterministic session knowledge state.")
gaps_cli = typer.Typer(help="Inspect persistent evidence gaps.")
strategy_cli = typer.Typer(help="Plan evidence-gap-driven research without executing tools.")


def _strategy_engine(database):
    settings = get_settings()
    discovery = _engine(database)
    return ResearchStrategyEngine(
        database,
        ToolResolver(discovery.registry, discovery.policy),
        minimum_verification_runs=settings.min_verification_runs,
        max_selected_intents=settings.strategy_max_selected_intents,
    )


@knowledge_cli.command("show")
def knowledge_show(
    session_id: Annotated[UUID, typer.Option("--session")],
) -> None:
    database = _database()
    try:
        state, snapshot, gaps = KnowledgeService(
            database,
            minimum_verification_runs=get_settings().min_verification_runs,
        ).build(session_id)
        typer.echo(
            json.dumps(
                {
                    "snapshot": snapshot.model_dump(mode="json"),
                    "counts": {
                        "KNOWN": snapshot.known_count,
                        "ASSUMED": snapshot.assumed_count,
                        "UNKNOWN": snapshot.unknown_count,
                        "CONFLICTING": snapshot.conflicting_count,
                        "UNTESTED": snapshot.untested_count,
                        "INCONCLUSIVE": snapshot.inconclusive_count,
                    },
                    "open_gaps": sum(
                        item.status.value in {"OPEN", "PARTIALLY_RESOLVED"}
                        for item in gaps
                    ),
                    "facts": [item.model_dump(mode="json") for item in state.facts],
                },
                sort_keys=True,
            )
        )
    finally:
        database.dispose()


@gaps_cli.command("list")
def gaps_list(
    session_id: Annotated[UUID, typer.Option("--session")],
) -> None:
    database = _database()
    try:
        KnowledgeService(
            database,
            minimum_verification_runs=get_settings().min_verification_runs,
        ).build(session_id)
        with database.session_factory() as session:
            gaps = RepositorySet(session).evidence_gaps.list_by_session(session_id)
        typer.echo(json.dumps([item.model_dump(mode="json") for item in gaps], sort_keys=True))
    finally:
        database.dispose()


@gaps_cli.command("show")
def gaps_show(gap_id: UUID) -> None:
    database = _database()
    try:
        with database.session_factory() as session:
            gap = RepositorySet(session).evidence_gaps.get(gap_id)
        if gap is None:
            raise typer.BadParameter("evidence gap does not exist")
        typer.echo(gap.model_dump_json())
    finally:
        database.dispose()


@strategy_cli.command("plan")
def strategy_plan(
    session_id: Annotated[UUID, typer.Option("--session")],
) -> None:
    """Persist and display strategy proposals; never invoke a target tool."""
    database = _database()
    try:
        run, decision = _strategy_engine(database).plan(session_id)
        with database.session_factory() as session:
            repositories = RepositorySet(session)
            gaps = repositories.evidence_gaps.list_by_session(session_id)
            questions = repositories.research_questions.list_by_session(session_id)
        typer.echo(
            json.dumps(
                {
                    "strategy_run": run.model_dump(mode="json"),
                    "planner_decision": decision.model_dump(mode="json"),
                    "gaps": [item.model_dump(mode="json") for item in gaps],
                    "questions": [item.model_dump(mode="json") for item in questions],
                    "tool_processes_invoked": 0,
                },
                sort_keys=True,
            )
        )
    finally:
        database.dispose()


@strategy_cli.command("export")
def strategy_export(
    session_id: Annotated[UUID, typer.Option("--session")],
    output_format: Annotated[str, typer.Option("--format")] = "json",
) -> None:
    if output_format.lower() != "json":
        raise typer.BadParameter("only json is supported")
    database = _database()
    try:
        with database.session_factory() as session:
            repositories = RepositorySet(session)
            snapshots = repositories.knowledge_snapshots.list_by_session(session_id)
            gaps = repositories.evidence_gaps.list_by_session(session_id)
            questions = repositories.research_questions.list_by_session(session_id)
            runs = repositories.strategy_runs.list_by_session(session_id)
        typer.echo(
            json.dumps(
                {
                    "session_id": str(session_id),
                    "knowledge_snapshots": [
                        item.model_dump(mode="json") for item in snapshots
                    ],
                    "evidence_gaps": [item.model_dump(mode="json") for item in gaps],
                    "research_questions": [
                        item.model_dump(mode="json") for item in questions
                    ],
                    "strategy_runs": [item.model_dump(mode="json") for item in runs],
                },
                sort_keys=True,
            )
        )
    finally:
        database.dispose()
