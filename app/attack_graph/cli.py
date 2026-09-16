import json
from pathlib import Path
from typing import Annotated
from uuid import UUID

import typer

from app.attack_graph.builder import AttackGraphBuilder
from app.attack_graph.errors import AttackGraphError
from app.attack_graph.queries import GraphQueryService
from app.config import get_settings
from app.domain.attack_graph import CandidateSignalType
from app.storage.database import Database

graph_cli = typer.Typer(help="Build and query evidence-backed attack graph projections.")


def _database() -> Database:
    settings = get_settings()
    database = Database(settings.database_url)
    database.create_schema()
    return database


def _query(database: Database) -> GraphQueryService:
    settings = get_settings()
    return GraphQueryService(
        database,
        max_depth=settings.graph_max_depth,
        max_paths=settings.graph_max_paths,
        max_nodes=settings.graph_max_nodes,
    )


@graph_cli.command("build")
def graph_build(
    session_id: Annotated[UUID, typer.Option("--session", help="Research session UUID.")],
) -> None:
    """Build and persist a deterministic graph snapshot; no target access occurs."""
    settings = get_settings()
    database = _database()
    try:
        graph, snapshot, signals = AttackGraphBuilder(
            database, max_nodes=settings.graph_max_nodes
        ).build(session_id)
        typer.echo(
            json.dumps(
                {
                    "graph_id": str(snapshot.id),
                    "system_model_hash": graph.system_model_hash,
                    "graph_hash": graph.graph_hash,
                    "nodes": len(graph.nodes),
                    "edges": len(graph.edges),
                    "traversable_edges": snapshot.traversable_edge_count,
                    "blocking_edges": snapshot.blocking_edge_count,
                    "candidate_signals": len(signals),
                    "truncated": graph.truncated,
                },
                sort_keys=True,
            )
        )
    except AttackGraphError as error:
        raise typer.BadParameter(f"{error.code.value}: {error}") from error
    finally:
        database.dispose()


@graph_cli.command("show")
def graph_show(graph_id: UUID) -> None:
    """Show graph snapshot metadata and current candidate-signal count."""
    database = _database()
    try:
        query = _query(database)
        graph = query.load(graph_id)
        snapshot = query.snapshot(graph_id)
        typer.echo(
            json.dumps(
                {
                    **snapshot.model_dump(mode="json"),
                    "candidate_signals": len(query.candidate_signals(graph_id)),
                    "nodes": len(graph.nodes),
                    "edges": len(graph.edges),
                },
                sort_keys=True,
            )
        )
    except AttackGraphError as error:
        raise typer.BadParameter(f"{error.code.value}: {error}") from error
    finally:
        database.dispose()


@graph_cli.command("path")
def graph_path(
    graph_id: Annotated[UUID, typer.Option("--graph")],
    source: Annotated[str, typer.Option("--from")],
    target: Annotated[str, typer.Option("--to")],
) -> None:
    """Return deterministic shortest-hop traversable path, if one exists."""
    database = _database()
    try:
        result = _query(database).shortest_path(graph_id, source, target)
        typer.echo(json.dumps(result.model_dump(mode="json") if result else None, sort_keys=True))
    except AttackGraphError as error:
        raise typer.BadParameter(f"{error.code.value}: {error}") from error
    finally:
        database.dispose()


@graph_cli.command("reachable")
def graph_reachable(
    graph_id: Annotated[UUID, typer.Option("--graph")],
    source: Annotated[str, typer.Option("--from")],
) -> None:
    """List nodes reachable over observed traversable edges."""
    database = _database()
    try:
        typer.echo(json.dumps(_query(database).reachable_from(graph_id, source)))
    except AttackGraphError as error:
        raise typer.BadParameter(f"{error.code.value}: {error}") from error
    finally:
        database.dispose()


def _signals(graph_id: UUID, signal_type: CandidateSignalType) -> None:
    database = _database()
    try:
        values = _query(database).candidate_signals(graph_id, signal_type.value)
        typer.echo(json.dumps([item.model_dump(mode="json") for item in values], sort_keys=True))
    except AttackGraphError as error:
        raise typer.BadParameter(f"{error.code.value}: {error}") from error
    finally:
        database.dispose()


@graph_cli.command("cross-identity")
def graph_cross_identity(
    graph_id: Annotated[UUID, typer.Option("--graph")],
) -> None:
    """List cross-identity resource-access candidate signals, never findings."""
    _signals(graph_id, CandidateSignalType.CROSS_IDENTITY_RESOURCE_ACCESS)


@graph_cli.command("role-diff")
def graph_role_difference(
    graph_id: Annotated[UUID, typer.Option("--graph")],
) -> None:
    """List observed access differences between identities with different roles."""
    _signals(graph_id, CandidateSignalType.ROLE_ACCESS_DIFFERENCE)


@graph_cli.command("export")
def graph_export(
    graph_id: UUID,
    output: Annotated[Path | None, typer.Option("--output")] = None,
    export_format: Annotated[str, typer.Option("--format")] = "json",
) -> None:
    """Export the graph as credential-free JSON."""
    if export_format.lower() != "json":
        raise typer.BadParameter("Phase 8 supports only JSON graph export")
    database = _database()
    try:
        encoded = json.dumps(_query(database).export(graph_id), indent=2, sort_keys=True)
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(encoded + "\n", encoding="utf-8")
            typer.echo(str(output))
        else:
            typer.echo(encoded)
    except AttackGraphError as error:
        raise typer.BadParameter(f"{error.code.value}: {error}") from error
    finally:
        database.dispose()
