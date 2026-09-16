import json
from pathlib import Path
from typing import Annotated
from uuid import UUID

import typer

from app.config import get_settings
from app.domain.system_model import RelationshipType
from app.storage.database import Database
from app.storage.repositories import RepositorySet
from app.system_model.builder import SystemModelBuilder
from app.system_model.queries import SystemModelQueryService

model_cli = typer.Typer(help="Build and inspect the evidence-backed system model.")


def _database() -> Database:
    database = Database(get_settings().database_url)
    database.create_schema()
    return database


@model_cli.command("build")
def build_model(
    session_id: Annotated[UUID, typer.Option("--session", help="Research session UUID.")],
) -> None:
    """Incrementally process observations not already projected."""
    database = _database()
    try:
        build = SystemModelBuilder(database).build(session_id)
        typer.echo(json.dumps(build.model_dump(mode="json"), sort_keys=True))
    finally:
        database.dispose()


@model_cli.command("rebuild")
def rebuild_model(
    session_id: Annotated[UUID, typer.Option("--session", help="Research session UUID.")],
) -> None:
    """Delete only the projection and replay immutable observations."""
    database = _database()
    try:
        build = SystemModelBuilder(database).build(session_id, rebuild=True)
        typer.echo(json.dumps(build.model_dump(mode="json"), sort_keys=True))
    finally:
        database.dispose()


@model_cli.command("show")
def show_model(
    session_id: Annotated[UUID, typer.Option("--session", help="Research session UUID.")],
) -> None:
    database = _database()
    try:
        typer.echo(
            json.dumps(SystemModelQueryService(database).summary(session_id), sort_keys=True)
        )
    finally:
        database.dispose()


def _list_collection(session_id: UUID, repository_name: str) -> None:
    database = _database()
    try:
        with database.session_factory() as session:
            repository = getattr(RepositorySet(session), repository_name)
            items = repository.list_by_session(session_id)
        typer.echo(
            json.dumps([item.model_dump(mode="json") for item in items], sort_keys=True)
        )
    finally:
        database.dispose()


@model_cli.command("assets")
def list_assets(
    session_id: Annotated[UUID, typer.Option("--session")],
) -> None:
    _list_collection(session_id, "system_assets")


@model_cli.command("endpoints")
def list_endpoints(
    session_id: Annotated[UUID, typer.Option("--session")],
) -> None:
    _list_collection(session_id, "system_endpoints")


@model_cli.command("identities")
def list_identities(
    session_id: Annotated[UUID, typer.Option("--session")],
) -> None:
    _list_collection(session_id, "system_identities")


@model_cli.command("relationships")
def list_relationships(
    session_id: Annotated[UUID, typer.Option("--session")],
    relationship_type: Annotated[
        RelationshipType | None, typer.Option("--type", case_sensitive=False)
    ] = None,
    source: Annotated[str | None, typer.Option("--source")] = None,
) -> None:
    database = _database()
    try:
        with database.session_factory() as session:
            repositories = RepositorySet(session)
            identities = {
                item.canonical_identifier: item.id
                for item in repositories.system_identities.list_by_session(session_id)
            }
            source_id = identities.get(
                source if source and source.startswith("identity:") else f"identity:{source}"
            ) if source else None
            items = repositories.system_relationships.list_filtered(
                session_id,
                relationship_type=relationship_type.value if relationship_type else None,
                source_entity_id=source_id,
            )
        typer.echo(
            json.dumps([item.model_dump(mode="json") for item in items], sort_keys=True)
        )
    finally:
        database.dispose()


@model_cli.command("export")
def export_command(
    session_id: Annotated[UUID, typer.Option("--session")],
    output_format: Annotated[str, typer.Option("--format")] = "json",
    output: Annotated[Path | None, typer.Option("--output")] = None,
) -> None:
    if output_format.lower() != "json":
        raise typer.BadParameter("Phase 7 supports only JSON export")
    database = _database()
    try:
        document = SystemModelQueryService(database).export(session_id)
        encoded = json.dumps(document, indent=2, sort_keys=True) + "\n"
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(encoded, encoding="utf-8")
            typer.echo(str(output))
        else:
            typer.echo(encoded, nl=False)
    finally:
        database.dispose()
