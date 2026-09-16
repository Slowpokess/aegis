import json
import asyncio
from pathlib import Path
from typing import Annotated
from uuid import UUID

import typer

from app.config import get_settings
from app.active_web.service import ActiveWebAssessmentService
from app.controller.factory import build_controller
from app.domain.active_web import ActiveWebProfile
from app.discovery.registry import ToolRegistry
from app.storage.database import Database
from app.storage.repositories import RepositorySet
from app.system_model.builder import SystemModelBuilder
from app.web_surface.builder import WebSurfaceBuilder
from app.web_surface.queries import WebSurfaceQueryService
from app.web_surface.service import WebImportFailure, WebImportService

web_cli = typer.Typer(help="Import, build, and inspect the persistent Web Surface.")


def _database() -> Database:
    database = Database(get_settings().database_url)
    database.create_schema()
    return database


def _registry() -> ToolRegistry:
    settings = get_settings()
    return ToolRegistry(
        enabled={
            "nmap": settings.nmap_enabled,
            "ffuf": settings.ffuf_enabled,
            "nuclei": settings.nuclei_enabled,
        }
    )


def _read_bounded(path: Path, maximum: int) -> bytes:
    try:
        if path.stat().st_size > maximum:
            raise typer.BadParameter("input file exceeds configured size limit")
        return path.read_bytes()
    except OSError as error:
        raise typer.BadParameter("input file cannot be read") from error


@web_cli.command("import-burp")
def import_burp(
    session_id: Annotated[UUID, typer.Option("--session")],
    file: Annotated[Path, typer.Option("--file")],
    template_file: Annotated[Path | None, typer.Option("--template-file")] = None,
) -> None:
    """Persist an offline Burp XML export and optional passive template JSONL."""
    settings = get_settings()
    raw = _read_bounded(file, settings.web_import_max_bytes)
    template = (
        _read_bounded(template_file, settings.web_import_max_bytes) if template_file else None
    )
    database = _database()
    try:
        result = WebImportService(database, settings).import_burp(
            session_id, raw, template_results=template
        )
    except WebImportFailure as error:
        typer.echo(
            json.dumps(
                {"status": "FAILED", "artifact_id": str(error.artifact_id), "error": str(error)},
                sort_keys=True,
            )
        )
        raise typer.Exit(code=2) from error
    finally:
        database.dispose()
    typer.echo(json.dumps(result.model_dump(mode="json"), sort_keys=True))


@web_cli.command("build")
def build(session_id: Annotated[UUID, typer.Option("--session")]) -> None:
    database = _database()
    try:
        SystemModelBuilder(database).build(session_id)
        snapshot = WebSurfaceBuilder(database).build(session_id)
    finally:
        database.dispose()
    typer.echo(json.dumps(snapshot.model_dump(mode="json"), sort_keys=True))


@web_cli.command("import-template")
def import_template(
    session_id: Annotated[UUID, typer.Option("--session")],
    file: Annotated[Path, typer.Option("--file")],
) -> None:
    """Persist passive template-assessment JSONL; no Nuclei process is run."""
    settings = get_settings()
    raw = _read_bounded(file, settings.web_import_max_bytes)
    database = _database()
    try:
        result = WebImportService(database, settings).import_template_assessment(session_id, raw)
    except WebImportFailure as error:
        typer.echo(
            json.dumps(
                {"status": "FAILED", "artifact_id": str(error.artifact_id), "error": str(error)},
                sort_keys=True,
            )
        )
        raise typer.Exit(code=2) from error
    finally:
        database.dispose()
    typer.echo(json.dumps(result.model_dump(mode="json"), sort_keys=True))


@web_cli.command("rebuild")
def rebuild(session_id: Annotated[UUID, typer.Option("--session")]) -> None:
    database = _database()
    try:
        snapshot = WebSurfaceBuilder(database).build(session_id, rebuild=True)
    finally:
        database.dispose()
    typer.echo(json.dumps(snapshot.model_dump(mode="json"), sort_keys=True))


@web_cli.command("show")
def show(session_id: Annotated[UUID, typer.Option("--session")]) -> None:
    database = _database()
    try:
        value = WebSurfaceQueryService(database).summary(session_id)
    finally:
        database.dispose()
    typer.echo(json.dumps(value, sort_keys=True))


@web_cli.command("resources")
def resources(session_id: Annotated[UUID, typer.Option("--session")]) -> None:
    database = _database()
    try:
        value = WebSurfaceQueryService(database).resources(session_id)
    finally:
        database.dispose()
    typer.echo(json.dumps(value, sort_keys=True))


@web_cli.command("resource-show")
def resource_show(resource_id: UUID) -> None:
    database = _database()
    try:
        value = WebSurfaceQueryService(database).resource(resource_id)
    finally:
        database.dispose()
    typer.echo(json.dumps(value, sort_keys=True))


@web_cli.command("parameters")
def parameters(session_id: Annotated[UUID, typer.Option("--session")]) -> None:
    database = _database()
    try:
        value = WebSurfaceQueryService(database).parameters(session_id)
    finally:
        database.dispose()
    typer.echo(json.dumps(value, sort_keys=True))


@web_cli.command("templates")
def templates(session_id: Annotated[UUID, typer.Option("--session")]) -> None:
    database = _database()
    try:
        value = WebSurfaceQueryService(database).templates(session_id)
    finally:
        database.dispose()
    typer.echo(json.dumps(value, sort_keys=True))


@web_cli.command("discover")
def discover(
    session_id: Annotated[UUID, typer.Option("--session")],
    resource_id: Annotated[UUID, typer.Option("--resource")],
    profile: Annotated[ActiveWebProfile, typer.Option()] = ActiveWebProfile.WEB_CONTENT_SMALL,
    preview: Annotated[bool, typer.Option("--preview")] = False,
) -> None:
    """Preview or run bounded ffuf discovery for one persisted WebResource."""
    settings = get_settings()
    database = _database()
    service = ActiveWebAssessmentService(database, settings, _registry())
    try:
        value = (
            service.preview_discovery(session_id, resource_id, profile)
            if preview
            else asyncio.run(
                build_controller(database, settings, registry=_registry())
                .request_web_discovery(session_id, resource_id, profile.value)
            ).actions[0]
        )
    finally:
        database.dispose()
    typer.echo(json.dumps(value.model_dump(mode="json"), sort_keys=True))


@web_cli.command("assess")
def assess(
    session_id: Annotated[UUID, typer.Option("--session")],
    resource_ids: Annotated[list[UUID] | None, typer.Option("--resource")] = None,
    profile: Annotated[ActiveWebProfile, typer.Option()] = ActiveWebProfile.SAFE_TEMPLATES,
    preview: Annotated[bool, typer.Option("--preview")] = False,
) -> None:
    """Preview or run bounded Nuclei assessment over scoped WebResources."""
    settings = get_settings()
    database = _database()
    service = ActiveWebAssessmentService(database, settings, _registry())
    selected = tuple(resource_ids or ()) or None
    try:
        value = (
            service.preview_assessment(session_id, selected, profile)
            if preview
            else asyncio.run(
                build_controller(database, settings, registry=_registry())
                .request_web_assessment(
                    session_id,
                    selected
                    or tuple(
                        item["id"]
                        for item in WebSurfaceQueryService(database).resources(session_id)
                    ),
                    profile.value,
                )
            ).actions[0]
        )
    finally:
        database.dispose()
    typer.echo(json.dumps(value.model_dump(mode="json"), sort_keys=True))


@web_cli.command("tool-runs")
def active_tool_runs(session_id: Annotated[UUID, typer.Option("--session")]) -> None:
    database = _database()
    try:
        with database.session_factory() as session:
            values = RepositorySet(session).tool_runs.list_by_session(session_id)
    finally:
        database.dispose()
    typer.echo(
        json.dumps(
            [
                item.model_dump(mode="json")
                for item in values
                if item.tool_id in {"ffuf", "nuclei"}
            ],
            sort_keys=True,
        )
    )
