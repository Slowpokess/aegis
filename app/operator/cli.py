import json
from pathlib import Path
from typing import Annotated
from uuid import UUID

import typer

from app.config import get_settings
from app.domain.operator import (
    ApprovalMode,
    ResearchBudgetTemplate,
    ResearchPolicyProfile,
)
from app.domain.research import TargetScope
from app.operator.policy import policy_settings
from app.operator.reporting import ReportService
from app.operator.service import ProjectService, operator_provenance
from app.storage.database import Database
from app.storage.repositories import RepositorySet

projects_cli = typer.Typer(help="Manage operator-level research projects.")
policies_cli = typer.Typer(help="Inspect built-in research policy profiles.")
report_cli = typer.Typer(help="Generate evidence-backed reports.")


def _database() -> Database:
    database = Database(get_settings().database_url)
    database.create_schema()
    return database


@projects_cli.command("create")
def create_project(
    name: Annotated[str, typer.Option("--name")],
    description: Annotated[str | None, typer.Option("--description")] = None,
    policy: Annotated[
        ResearchPolicyProfile, typer.Option("--policy")
    ] = ResearchPolicyProfile.CONSERVATIVE,
) -> None:
    database = _database()
    try:
        project = ProjectService(database, get_settings()).create(
            name, description=description, profile=policy
        )
        typer.echo(str(project.id))
    finally:
        database.dispose()


@projects_cli.command("list")
def list_projects() -> None:
    database = _database()
    try:
        with database.session_factory() as session:
            values = RepositorySet(session).research_projects.list()
        typer.echo(json.dumps([item.model_dump(mode="json") for item in values], sort_keys=True))
    finally:
        database.dispose()


@projects_cli.command("show")
def show_project(project_id: UUID) -> None:
    database = _database()
    try:
        with database.session_factory() as session:
            value = RepositorySet(session).research_projects.get(project_id)
        if value is None:
            raise typer.BadParameter("project does not exist")
        typer.echo(json.dumps(value.model_dump(mode="json"), sort_keys=True))
    finally:
        database.dispose()


@projects_cli.command("configure")
def configure_project(
    project_id: UUID,
    host: Annotated[str, typer.Option("--host")],
    port: Annotated[int, typer.Option("--port")],
    scheme: Annotated[str, typer.Option("--scheme")] = "http",
    identities: Annotated[str, typer.Option("--identities")] = "anonymous,alice,bob,admin",
    policy: Annotated[
        ResearchPolicyProfile, typer.Option("--policy")
    ] = ResearchPolicyProfile.CONSERVATIVE,
    approval: Annotated[ApprovalMode, typer.Option("--approval-mode")] = ApprovalMode.AUTO,
    max_steps: Annotated[int | None, typer.Option("--max-steps")] = None,
    max_actions: Annotated[int | None, typer.Option("--max-actions")] = None,
    max_tool_runs: Annotated[int | None, typer.Option("--max-tool-runs")] = None,
    max_requests: Annotated[int | None, typer.Option("--max-requests")] = None,
    max_duration_seconds: Annotated[float | None, typer.Option("--max-duration-seconds")] = None,
    max_llm_calls: Annotated[int | None, typer.Option("--max-llm-calls")] = None,
) -> None:
    database = _database()
    settings = get_settings()
    try:
        scope = TargetScope(
            hosts=(host,),
            ports=(port,),
            schemes=(scheme,),
            provenance=operator_provenance(f"project-scope:{project_id}"),
        )
        budget = ResearchBudgetTemplate(
            max_steps=max_steps or settings.controller_max_steps,
            max_actions=max_actions or settings.controller_max_actions,
            max_tool_runs=(
                settings.controller_max_tool_runs if max_tool_runs is None else max_tool_runs
            ),
            max_requests=(
                settings.controller_max_requests if max_requests is None else max_requests
            ),
            max_duration_seconds=(
                settings.controller_max_duration_seconds
                if max_duration_seconds is None
                else max_duration_seconds
            ),
            max_llm_calls=(
                settings.controller_max_llm_calls if max_llm_calls is None else max_llm_calls
            ),
            allowed_capabilities=settings.controller_allowed_capabilities,
        )
        value = ProjectService(database, settings).configure(
            project_id,
            scope=scope,
            identity_names=tuple(item.strip() for item in identities.split(",") if item.strip()),
            profile=policy,
            approval_mode=approval,
            budget=budget,
        )
        typer.echo(json.dumps(value.model_dump(mode="json"), sort_keys=True))
    finally:
        database.dispose()


@projects_cli.command("policy-set")
def policy_set(project_id: UUID, policy: ResearchPolicyProfile) -> None:
    database = _database()
    settings = get_settings()
    try:
        with database.session_factory() as session:
            project = RepositorySet(session).research_projects.get(project_id)
        if project is None or project.scope is None:
            raise typer.BadParameter("configured project does not exist")
        value = ProjectService(database, settings).configure(
            project_id,
            scope=project.scope,
            identity_names=project.identity_names,
            profile=policy,
            approval_mode=project.approval_mode,
            budget=project.budget,
        )
        typer.echo(json.dumps(value.model_dump(mode="json"), sort_keys=True))
    finally:
        database.dispose()


@projects_cli.command("start")
def start_project(project_id: UUID) -> None:
    database = _database()
    try:
        research = ProjectService(database, get_settings()).start(project_id)
        typer.echo(str(research.id))
    finally:
        database.dispose()


@policies_cli.command("list")
def list_policies() -> None:
    typer.echo(json.dumps([item.value for item in ResearchPolicyProfile]))


@policies_cli.command("show")
def show_policy(name: ResearchPolicyProfile) -> None:
    typer.echo(
        json.dumps(
            {
                "version": "research-policy-v1",
                "profile": name.value,
                "settings": policy_settings(name).model_dump(mode="json"),
            },
            sort_keys=True,
        )
    )


@report_cli.command("generate")
def generate_report(session_id: Annotated[UUID, typer.Option("--session")]) -> None:
    database = _database()
    try:
        metadata, manifest = ReportService(database, get_settings()).generate(session_id)
        typer.echo(
            json.dumps(
                {"report": metadata.model_dump(mode="json"), "manifest_hash": manifest.sha256},
                sort_keys=True,
            )
        )
    finally:
        database.dispose()


@report_cli.command("show")
def show_report(session_id: Annotated[UUID, typer.Option("--session")]) -> None:
    database = _database()
    try:
        with database.session_factory() as session:
            values = RepositorySet(session).report_metadata.list_by_session(session_id)
        typer.echo(
            json.dumps(values[-1].model_dump(mode="json") if values else None, sort_keys=True)
        )
    finally:
        database.dispose()


@report_cli.command("export")
def export_report(
    session_id: Annotated[UUID, typer.Option("--session")],
    export_format: Annotated[str, typer.Option("--format")] = "json",
) -> None:
    if export_format not in {"json", "html"}:
        raise typer.BadParameter("report format must be json or html")
    database = _database()
    try:
        metadata, _ = ReportService(database, get_settings()).generate(session_id)
        name = "summary.json" if export_format == "json" else "technical-report.html"
        typer.echo(str(Path(metadata.path) / name))
    finally:
        database.dispose()
