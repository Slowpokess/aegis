import asyncio
import json
from pathlib import Path
from typing import Annotated
from uuid import UUID

import typer

from app.config import get_settings
from app.controller.factory import build_controller
from app.domain.controller import ControllerDecision
from app.domain.operator import ControllerMode
from app.llm.factory import create_llm_provider
from app.llm.providers.fake import FakeLLMProvider
from app.storage.database import Database
from app.storage.repositories import RepositorySet

controller_cli = typer.Typer(help="Run bounded typed closed-loop research.")


def _database() -> Database:
    database = Database(get_settings().database_url)
    database.create_schema()
    return database


def _controller(database: Database, fake_decision: Path | None = None):
    settings = get_settings()
    provider = None
    if fake_decision is not None:
        try:
            decision = ControllerDecision.model_validate_json(fake_decision.read_text())
        except (OSError, ValueError) as error:
            raise typer.BadParameter(
                "fake decision is not valid ControllerDecision JSON"
            ) from error
        provider = FakeLLMProvider([decision], model="fake-controller-v1")
    elif settings.llm_provider != "fake":
        provider = create_llm_provider(settings)
    return build_controller(database, settings, provider=provider)


def _step_payload(result: object) -> dict[str, object]:
    step = result.step  # type: ignore[attr-defined]
    actions = result.actions  # type: ignore[attr-defined]
    results = result.results  # type: ignore[attr-defined]
    return {
        "step": step.model_dump(mode="json"),
        "decision": result.decision.model_dump(mode="json"),  # type: ignore[attr-defined]
        "actions": [
            {
                "id": str(item.id),
                "type": item.action_type.value,
                "purpose": item.purpose.value,
                "status": item.status.value,
                "semantic_hash": item.semantic_hash,
                "validation": item.validation_reason,
                "capability": item.contract.capability.value
                if item.contract and item.contract.capability
                else None,
                "tool": "http" if item.action_type.value == "HTTP_OBSERVE" else None,
                "profile": "entity_observe" if item.action_type.value == "HTTP_OBSERVE" else None,
                "policy": (
                    item.contract.policy_decision.reason_code
                    if item.contract and item.contract.policy_decision
                    else "PREVIEW_ONLY"
                    if item.status.value == "VALIDATED"
                    else None
                ),
                "tool_run_ids": [str(value) for value in item.tool_run_ids],
                "evidence_ids": [str(value) for value in item.evidence_ids],
                "observation_ids": [str(value) for value in item.observation_ids],
            }
            for item in actions
        ],
        "results": [item.model_dump(mode="json") for item in results],
        "target_operations": sum(len(item.tool_run_ids) for item in results),
    }


@controller_cli.command("plan")
def controller_plan(
    session_id: Annotated[UUID, typer.Option("--session")],
    fake_decision: Annotated[Path | None, typer.Option("--fake-decision")] = None,
) -> None:
    """Create and validate one decision without target execution."""
    database = _database()
    try:
        result = asyncio.run(_controller(database, fake_decision).plan(session_id))
        typer.echo(json.dumps(_step_payload(result), sort_keys=True))
    finally:
        database.dispose()


@controller_cli.command("step")
def controller_step(
    session_id: Annotated[UUID, typer.Option("--session")],
    fake_decision: Annotated[Path | None, typer.Option("--fake-decision")] = None,
) -> None:
    """Execute at most one bounded controller decision."""
    database = _database()
    try:
        result = asyncio.run(_controller(database, fake_decision).step(session_id))
        typer.echo(json.dumps(_step_payload(result), sort_keys=True))
    finally:
        database.dispose()


@controller_cli.command("run")
def controller_run(session_id: Annotated[UUID, typer.Option("--session")]) -> None:
    """Run until a deterministic stop condition or persisted budget boundary."""
    database = _database()
    try:
        result = asyncio.run(_controller(database).run(session_id))
        typer.echo(
            json.dumps(
                {
                    "session_id": str(result.session_id),
                    "steps": [_step_payload(item) for item in result.steps],
                    "stop_reason": result.stop_reason,
                },
                sort_keys=True,
            )
        )
    finally:
        database.dispose()


@controller_cli.command("pause")
def controller_pause(session_id: Annotated[UUID, typer.Option("--session")]) -> None:
    database = _database()
    try:
        budget = _controller(database).pause(session_id)
        typer.echo(json.dumps(budget.model_dump(mode="json"), sort_keys=True))
    finally:
        database.dispose()


@controller_cli.command("resume")
def controller_resume(session_id: Annotated[UUID, typer.Option("--session")]) -> None:
    database = _database()
    try:
        result = asyncio.run(_controller(database).resume(session_id))
        typer.echo(
            json.dumps(
                {
                    "session_id": str(result.session_id),
                    "steps": [_step_payload(item) for item in result.steps],
                    "stop_reason": result.stop_reason,
                },
                sort_keys=True,
            )
        )
    finally:
        database.dispose()


@controller_cli.command("status")
def controller_status(session_id: Annotated[UUID, typer.Option("--session")]) -> None:
    database = _database()
    try:
        controller = _controller(database)
        budget = controller.ensure_budget(session_id)
        with database.session_factory() as session:
            repositories = RepositorySet(session)
            steps = repositories.controller_steps.list_by_session(session_id)
            actions = repositories.research_actions.list_by_session(session_id)
            gaps = repositories.evidence_gaps.list_by_session(session_id)
            findings = repositories.findings.list_by_session(session_id)
            research = repositories.research_sessions.get(session_id)
            project = (
                repositories.research_projects.get(research.project_id)
                if research and research.project_id
                else None
            )
            policy = (
                repositories.research_policies.get(project.research_policy_id) if project else None
            )
            approvals = repositories.action_approvals.list_by_session(session_id)
        typer.echo(
            json.dumps(
                {
                    "session_id": str(session_id),
                    "experimental_mode": controller.settings.controller_experimental_mode
                    or bool(project and project.controller_mode is ControllerMode.EXPERIMENTAL),
                    "project_id": str(project.id) if project else None,
                    "research_policy": policy.profile.value if policy else None,
                    "approval_mode": project.approval_mode.value if project else "AUTO",
                    "pending_approvals": sum(item.status.value == "PENDING" for item in approvals),
                    "controller_status": budget.controller_status.value,
                    "current_step": len(steps),
                    "budget": budget.model_dump(mode="json"),
                    "open_gaps": sum(
                        item.status.value in {"OPEN", "PARTIALLY_RESOLVED"} for item in gaps
                    ),
                    "resolved_gaps": sum(item.status.value == "RESOLVED" for item in gaps),
                    "findings": len(findings),
                    "last_action": actions[-1].model_dump(mode="json") if actions else None,
                    "last_policy_rejection": next(
                        (
                            item.failure_reason or item.validation_reason
                            for item in reversed(actions)
                            if item.status.value == "REJECTED"
                        ),
                        None,
                    ),
                    "stop_reason": budget.stop_reason,
                },
                sort_keys=True,
            )
        )
    finally:
        database.dispose()


@controller_cli.command("steps")
def controller_steps(session_id: Annotated[UUID, typer.Option("--session")]) -> None:
    database = _database()
    try:
        with database.session_factory() as session:
            values = RepositorySet(session).controller_steps.list_by_session(session_id)
        typer.echo(json.dumps([item.model_dump(mode="json") for item in values], sort_keys=True))
    finally:
        database.dispose()


@controller_cli.command("actions")
def controller_actions(session_id: Annotated[UUID, typer.Option("--session")]) -> None:
    database = _database()
    try:
        with database.session_factory() as session:
            values = RepositorySet(session).research_actions.list_by_session(session_id)
        typer.echo(json.dumps([item.model_dump(mode="json") for item in values], sort_keys=True))
    finally:
        database.dispose()


@controller_cli.command("approvals")
def controller_approvals(
    session_id: Annotated[UUID, typer.Option("--session")],
) -> None:
    database = _database()
    try:
        with database.session_factory() as session:
            values = RepositorySet(session).action_approvals.list_by_session(session_id)
        typer.echo(json.dumps([item.model_dump(mode="json") for item in values], sort_keys=True))
    finally:
        database.dispose()


@controller_cli.command("approve")
def controller_approve(
    action_id: UUID,
    reason: Annotated[str | None, typer.Option("--reason")] = None,
) -> None:
    database = _database()
    try:
        value = asyncio.run(_controller(database).approve_action(action_id, reason=reason))
        typer.echo(json.dumps(value.model_dump(mode="json"), sort_keys=True))
    finally:
        database.dispose()


@controller_cli.command("reject")
def controller_reject(
    action_id: UUID,
    reason: Annotated[str | None, typer.Option("--reason")] = None,
) -> None:
    database = _database()
    try:
        value = _controller(database).reject_action(action_id, reason=reason)
        typer.echo(json.dumps(value.model_dump(mode="json"), sort_keys=True))
    finally:
        database.dispose()


@controller_cli.command("export")
def controller_export(
    session_id: Annotated[UUID, typer.Option("--session")],
    export_format: Annotated[str, typer.Option("--format")] = "json",
) -> None:
    """Export audit lineage as JSON IDs/metadata only; never raw credentials or reasoning."""
    if export_format.lower() != "json":
        raise typer.BadParameter("Phase 12 supports only JSON controller export")
    database = _database()
    try:
        controller = _controller(database)
        budget = controller.ensure_budget(session_id)
        with database.session_factory() as session:
            repositories = RepositorySet(session)
            research = repositories.research_sessions.get(session_id)
            steps = repositories.controller_steps.list_by_session(session_id)
            actions = repositories.research_actions.list_by_session(session_id)
            results = [
                result
                for action in actions
                if (result := repositories.research_action_results.get_by_action(action.id))
            ]
            gaps = repositories.evidence_gaps.list_by_session(session_id)
            findings = repositories.findings.list_by_session(session_id)
            project = (
                repositories.research_projects.get(research.project_id)
                if research and research.project_id
                else None
            )
            policy = (
                repositories.research_policies.get(project.research_policy_id) if project else None
            )
            approvals = repositories.action_approvals.list_by_session(session_id)
        if research is None:
            raise typer.BadParameter("research session does not exist")
        payload = {
            "experimental_mode": controller.settings.controller_experimental_mode
            or bool(project and project.controller_mode is ControllerMode.EXPERIMENTAL),
            "project_id": str(project.id) if project else None,
            "research_policy": policy.profile.value if policy else None,
            "approval_mode": project.approval_mode.value if project else "AUTO",
            "approvals": [item.model_dump(mode="json") for item in approvals],
            "session": {
                "id": str(research.id),
                "scope": research.scope.model_dump(mode="json"),
            },
            "budget": budget.model_dump(mode="json"),
            "steps": [item.model_dump(mode="json") for item in steps],
            "actions": [item.model_dump(mode="json") for item in actions],
            "results": [item.model_dump(mode="json") for item in results],
            "gap_transitions": [
                {"id": str(item.id), "type": item.gap_type.value, "status": item.status.value}
                for item in gaps
            ],
            "findings": [str(item.id) for item in findings],
            "reasoning_content_persisted": False,
        }
        encoded = json.dumps(payload, sort_keys=True)
        if any(secret in encoded.lower() for secret in ("authorization", "cookie", "bearer ")):
            raise RuntimeError("controller export credential scan failed")
        typer.echo(encoded)
    finally:
        database.dispose()
