from pathlib import Path
from typing import Annotated
from uuid import UUID
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from app.config import Settings
from app.active_web.service import ActiveWebAssessmentService
from app.domain.active_web import ActiveWebProfile
from app import __version__
from app.attack_graph.queries import GraphQueryService
from app.controller.factory import build_controller
from app.discovery.registry import ToolRegistry
from app.domain.controller import ResearchAction, ResearchActionStatus, ResearchActionType
from app.domain.recommendations import VerificationRecommendationEngine
from app.domain.recommendations import RecommendedAction
from app.domain.generated_payloads import PayloadGenerationEngine
from app.domain.operator import ActionApproval
from app.domain.common import utc_now
from app.domain.operator import (
    ApprovalMode,
    ResearchEventType,
    ResearchBudgetTemplate,
    ResearchPolicyProfile,
)
from app.domain.research import TargetScope
from app.operator.service import ProjectService, ResearchEventService, operator_provenance
from app.operator.reporting import ReportService
from app.storage.repositories import RepositorySet
from app.system_model.serialization import export_model
from app.system_model.builder import SystemModelBuilder
from app.web_surface.builder import WebSurfaceBuilder
from app.web_surface.queries import WebSurfaceQueryService
from app.web_surface.service import WebImportFailure, WebImportService

router = APIRouter()


class StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProjectCreateRequest(StrictRequest):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    policy: ResearchPolicyProfile = ResearchPolicyProfile.CONSERVATIVE


class ProjectConfigureRequest(StrictRequest):
    hosts: tuple[str, ...] = Field(min_length=1)
    ports: tuple[int, ...] = Field(min_length=1)
    schemes: tuple[str, ...] = Field(min_length=1)
    identities: tuple[str, ...] = ()
    policy: ResearchPolicyProfile = ResearchPolicyProfile.CONSERVATIVE
    approval_mode: ApprovalMode = ApprovalMode.AUTO
    budget: ResearchBudgetTemplate = Field(default_factory=ResearchBudgetTemplate)


class ApprovalRequest(StrictRequest):
    reason: str | None = Field(default=None, max_length=1000)


class BlockActionRequest(StrictRequest):
    action_type: ResearchActionType
    blocked: bool = True


class WebDiscoverRequest(StrictRequest):
    resource_id: UUID
    profile: ActiveWebProfile = ActiveWebProfile.WEB_CONTENT_SMALL
    execute: bool = True


class WebAssessRequest(StrictRequest):
    resource_ids: tuple[UUID, ...] = ()
    profile: ActiveWebProfile = ActiveWebProfile.SAFE_TEMPLATES
    execute: bool = True


def _services(request: Request) -> tuple[ProjectService, Settings]:
    settings: Settings = request.app.state.settings
    return ProjectService(request.app.state.database, settings), settings


def _not_found(error: ValueError) -> HTTPException:
    return HTTPException(status_code=404, detail=str(error))


def _registry(request: Request) -> ToolRegistry:
    return request.app.state.tool_registry


def _active_action_payload(
    request: Request,
    action: ResearchAction,
    repositories: RepositorySet | None = None,
) -> dict[str, object]:
    def build(values: RepositorySet) -> dict[str, object]:
        approval = values.action_approvals.get_by_action(action.id)
        runs = [values.tool_runs.get(run_id) for run_id in action.tool_run_ids]
        run = next((item for item in runs if item is not None), None)
        return {
            "action_id": str(action.id),
            "action_type": action.action_type.value,
            "status": action.status.value,
            "approval_id": str(approval.id) if approval else None,
            "approval_status": approval.status.value if approval else None,
            "tool_run_id": str(run.id) if run else None,
            "tool_run_ids": [str(item) for item in action.tool_run_ids],
            "tool_id": run.tool_id if run else (
                "ffuf"
                if action.action_type is ResearchActionType.DISCOVER_WEB_CONTENT
                else "nuclei"
            ),
            "profile": getattr(action.proposal, "profile", None),
            "tool_version": run.tool_version if run else None,
            "parser_version": run.parser_version if run else None,
            "error_code": run.error_code.value if run and run.error_code else None,
            "failure_reason": action.failure_reason,
            "observation_ids": [str(item) for item in action.observation_ids],
            "created_at": action.created_at.isoformat(),
            "finished_at": action.finished_at.isoformat() if action.finished_at else None,
        }

    if repositories is not None:
        return build(repositories)
    with request.app.state.database.session_factory() as session:
        return build(RepositorySet(session))


async def _bounded_upload(request: Request, maximum: int) -> bytes:
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > maximum:
                raise HTTPException(status_code=413, detail="web import exceeds file-size limit")
        except ValueError as error:
            raise HTTPException(status_code=400, detail="invalid Content-Length") from error
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > maximum:
            raise HTTPException(status_code=413, detail="web import exceeds file-size limit")
        chunks.append(chunk)
    return b"".join(chunks)


def _integration_payload(integration: object) -> dict[str, object]:
    descriptor = integration.descriptor
    return {
        **descriptor.model_dump(mode="json"),
        "tool_id": descriptor.id,
        "display_name": descriptor.name,
        "profiles": [
            {
                "id": profile.profile_id,
                "display_name": profile.display_name,
                "description": profile.description,
                "capability": profile.capability.value,
                "risk": profile.risk_class.value,
            }
            for profile in integration.profiles
        ],
        "ui": {
            "summary": integration.ui.summary,
            "documentation_url": integration.ui.documentation_url,
        },
    }


@router.get("/tools", tags=["tools"])
async def tools(request: Request) -> list[dict[str, object]]:
    return [_integration_payload(item) for item in _registry(request).integrations()]


@router.get("/tools/{tool_id}", tags=["tools"])
async def tool(tool_id: str, request: Request) -> dict[str, object]:
    integration = _registry(request).integration(tool_id)
    if integration is None:
        raise HTTPException(status_code=404, detail="tool integration does not exist")
    return _integration_payload(integration)


@router.get("/runtime", tags=["system"])
async def runtime(request: Request) -> dict[str, object]:
    _, settings = _services(request)
    return {
        "version": __version__,
        "bind_default": "127.0.0.1",
        "operator_api_version": "operator-api-v1",
        "tool_integration_version": "tool-integration-v1",
        "web_surface_version": "web-surface-v1",
        "web_import_max_bytes": settings.web_import_max_bytes,
        "llm": {
            "provider": settings.llm_provider,
            "model": settings.llm_model,
            "status": "configured"
            if settings.llm_provider == "fake" or settings.nvidia_api_key is not None
            else "unavailable",
        },
    }


@router.get("/projects", tags=["operator"])
async def projects(request: Request) -> list[dict[str, object]]:
    with request.app.state.database.session_factory() as session:
        values = RepositorySet(session).research_projects.list()
    return [item.model_dump(mode="json") for item in values]


@router.post("/projects", tags=["operator"], status_code=201)
async def create_project(payload: ProjectCreateRequest, request: Request) -> dict[str, object]:
    service, _ = _services(request)
    project = service.create(
        payload.name,
        description=payload.description,
        profile=payload.policy,
        created_by={"type": "local_api_operator"},
    )
    return project.model_dump(mode="json")


@router.get("/projects/{project_id}", tags=["operator"])
async def project(project_id: UUID, request: Request) -> dict[str, object]:
    with request.app.state.database.session_factory() as session:
        value = RepositorySet(session).research_projects.get(project_id)
    if value is None:
        raise HTTPException(status_code=404, detail="project does not exist")
    return value.model_dump(mode="json")


@router.put("/projects/{project_id}", tags=["operator"])
async def configure_project(
    project_id: UUID, payload: ProjectConfigureRequest, request: Request
) -> dict[str, object]:
    service, _ = _services(request)
    try:
        value = service.configure(
            project_id,
            scope=TargetScope(
                hosts=payload.hosts,
                ports=payload.ports,
                schemes=payload.schemes,
                provenance=operator_provenance(f"project-scope:{project_id}"),
            ),
            identity_names=payload.identities,
            profile=payload.policy,
            approval_mode=payload.approval_mode,
            budget=payload.budget,
        )
    except ValueError as error:
        raise _not_found(error) from error
    return value.model_dump(mode="json")


@router.post("/projects/{project_id}/start", tags=["operator"], status_code=201)
async def start_project(project_id: UUID, request: Request) -> dict[str, object]:
    service, _ = _services(request)
    try:
        value = service.start(project_id)
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    return value.model_dump(mode="json")


@router.post("/projects/{project_id}/cancel", tags=["operator"])
async def cancel_project(project_id: UUID, request: Request) -> dict[str, object]:
    service, _ = _services(request)
    try:
        value = service.cancel(project_id)
    except ValueError as error:
        raise _not_found(error) from error
    return value.model_dump(mode="json")


@router.post("/projects/{project_id}/block-action-type", tags=["operator"])
async def block_action_type(
    project_id: UUID, payload: BlockActionRequest, request: Request
) -> dict[str, object]:
    with request.app.state.database.session_factory.begin() as session:
        repositories = RepositorySet(session)
        project = repositories.research_projects.get(project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="project does not exist")
        blocked = set(project.blocked_action_types)
        if payload.blocked:
            blocked.add(payload.action_type)
        else:
            blocked.discard(payload.action_type)
        updated = project.model_copy(
            update={"blocked_action_types": tuple(sorted(blocked, key=lambda x: x.value))}
        )
        repositories.research_projects.update(updated)
    return updated.model_dump(mode="json")


@router.get("/projects/{project_id}/sessions", tags=["operator"])
async def project_sessions(project_id: UUID, request: Request) -> list[dict[str, object]]:
    with request.app.state.database.session_factory() as session:
        values = RepositorySet(session).research_sessions.list_by_project(project_id)
    return [item.model_dump(mode="json") for item in values]


@router.get("/sessions/{session_id}/status", tags=["operator"])
async def session_status(session_id: UUID, request: Request) -> dict[str, object]:
    service, _ = _services(request)
    try:
        return service.overview(session_id).model_dump(mode="json")
    except ValueError as error:
        raise _not_found(error) from error


@router.get("/sessions/{session_id}/events", tags=["operator"])
async def session_events(
    session_id: UUID,
    request: Request,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
    event_type: ResearchEventType | None = None,
) -> list[dict[str, object]]:
    ResearchEventService(request.app.state.database).sync_session(session_id)
    with request.app.state.database.session_factory() as session:
        values = RepositorySet(session).research_events.list_by_session(
            session_id,
            offset=offset,
            limit=limit,
            event_type=event_type.value if event_type else None,
        )
    return [item.model_dump(mode="json") for item in values]


@router.get("/sessions/{session_id}/actions", tags=["operator"])
async def session_actions(
    session_id: UUID,
    request: Request,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
    status: ResearchActionStatus | None = None,
) -> list[dict[str, object]]:
    with request.app.state.database.session_factory() as session:
        values = RepositorySet(session).research_actions.list_by_session(session_id)
    if status:
        values = [item for item in values if item.status is status]
    return [item.model_dump(mode="json") for item in values[offset : offset + limit]]


@router.get("/sessions/{session_id}/findings", tags=["operator"])
async def session_findings(session_id: UUID, request: Request) -> list[dict[str, object]]:
    with request.app.state.database.session_factory() as session:
        values = RepositorySet(session).findings.list_by_session(session_id)
    return [item.model_dump(mode="json") for item in values]


@router.get("/client-verifications/{run_id}/recommendation", tags=["client-verification"])
async def client_verification_recommendation(run_id: UUID, request: Request) -> dict[str, object]:
    """Return a persisted deterministic recommendation; this route never executes a probe."""
    with request.app.state.database.session_factory.begin() as session:
        repositories = RepositorySet(session)
        run = repositories.client_verification_runs.get(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="client verification run does not exist")
        value = repositories.verification_recommendations.get_by_run(run_id)
        if value is None:
            value = VerificationRecommendationEngine().generate(run)
            try:
                repositories.verification_recommendations.add(value)
            except ValueError as error:
                raise HTTPException(status_code=409, detail=str(error)) from error
        generated = repositories.generated_payloads.get_by_run(run_id)
        if generated is None:
            generated = PayloadGenerationEngine().generate(run, value)
            if generated is not None:
                repositories.generated_payloads.add(generated)
    payload = value.model_dump(mode="json")
    payload["generated_payload"] = generated.model_dump(mode="json") if generated else None
    return payload


@router.get("/sessions/{session_id}/recommendations", tags=["client-verification"])
async def session_recommendations(
    session_id: UUID, request: Request,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
) -> list[dict[str, object]]:
    with request.app.state.database.session_factory() as session:
        values = RepositorySet(session).verification_recommendations.list_by_session(
            session_id, offset=offset, limit=limit)
    return [item.model_dump(mode="json") for item in values]


@router.post("/recommendations/{recommendation_id}/request-action", tags=["client-verification"], status_code=201)
async def request_recommendation_action(recommendation_id: UUID, request: Request) -> dict[str, object]:
    """Accept a recommendation by creating a *pending* action only.

    No executor is imported or called here. Approval re-runs the regular action
    validation path (scope, policy, repetition and budget checks) before any
    future browser integration may run.
    """
    with request.app.state.database.session_factory.begin() as session:
        repositories = RepositorySet(session)
        recommendation = repositories.verification_recommendations.get(recommendation_id)
        if recommendation is None:
            raise HTTPException(status_code=404, detail="verification recommendation does not exist")
        if (recommendation.recommended_action is not RecommendedAction.RUN_ADDITIONAL_VERIFICATION
                or recommendation.suggested_probe is None or not recommendation.requires_approval):
            raise HTTPException(status_code=409, detail="recommendation does not authorize a verification action")
        run = repositories.client_verification_runs.get(recommendation.run_id)
        original = repositories.research_actions.get(run.research_action_id) if run else None
        research = repositories.research_sessions.get(recommendation.research_session_id)
        project = repositories.research_projects.get(research.project_id) if research and research.project_id else None
        if original is None or project is None:
            raise HTTPException(status_code=409, detail="recommendation action lineage is incomplete")
        # Preserve the sealed original action proposal; the recommendation never
        # supplies a browser command or free-form payload.
        proposal = original.proposal.model_copy(update={
            "rationale": f"Approved recommendation {recommendation.id}: {recommendation.reasoning[:600]}",
            "repeat_reason": "REPRODUCTION",
        })
        action = original.model_copy(update={
            "id": uuid4(), "proposal": proposal, "semantic_hash": original.semantic_hash,
            "status": ResearchActionStatus.WAITING_FOR_APPROVAL, "operator_initiated": True,
            "validation_reason": "RECOMMENDATION_PENDING_FRESH_VALIDATION",
            "failure_reason": None, "created_at": utc_now(), "finished_at": None,
            "tool_run_ids": (), "evidence_ids": (), "observation_ids": (), "verification_result_ids": (),
        })
        repositories.research_actions.add(action)
        approval = ActionApproval(project_id=project.id, research_session_id=action.research_session_id,
            action_id=action.id, policy_preview_allowed=True,
            policy_preview_reason="Recommendation acceptance requires fresh approval and validation.",
            provenance=operator_provenance(f"recommendation-action:{recommendation.id}:{action.id}"))
        repositories.action_approvals.add(approval)
    return {"action": action.model_dump(mode="json"), "approval": approval.model_dump(mode="json")}


@router.get("/sessions/{session_id}/gaps", tags=["operator"])
async def session_gaps(session_id: UUID, request: Request) -> list[dict[str, object]]:
    with request.app.state.database.session_factory() as session:
        values = RepositorySet(session).evidence_gaps.list_by_session(session_id)
    return [item.model_dump(mode="json") for item in values]


@router.get("/sessions/{session_id}/assets", tags=["operator"])
async def session_assets(session_id: UUID, request: Request) -> list[dict[str, object]]:
    with request.app.state.database.session_factory() as session:
        values = RepositorySet(session).system_assets.list_by_session(session_id)
    return [item.model_dump(mode="json") for item in values]


@router.get("/sessions/{session_id}/graph-summary", tags=["operator"])
async def graph_summary(session_id: UUID, request: Request) -> dict[str, object]:
    with request.app.state.database.session_factory() as session:
        values = RepositorySet(session).attack_graph_snapshots.list_by_session(session_id)
    return values[-1].model_dump(mode="json") if values else {"status": "UNKNOWN"}


@router.get("/sessions/{session_id}/graph", tags=["operator"])
async def graph(session_id: UUID, request: Request) -> dict[str, object]:
    with request.app.state.database.session_factory() as session:
        values = RepositorySet(session).attack_graph_snapshots.list_by_session(session_id)
    if not values:
        return {"nodes": [], "edges": [], "candidate_signals": [], "status": "UNKNOWN"}
    current = next(
        (item for item in reversed(values) if item.status.value == "CURRENT"), values[-1]
    )
    try:
        return GraphQueryService(request.app.state.database).export(current.id)
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error


@router.get("/sessions/{session_id}/model", tags=["operator"])
async def model(session_id: UUID, request: Request) -> dict[str, object]:
    with request.app.state.database.session_factory() as session:
        return export_model(RepositorySet(session), session_id)


@router.post("/sessions/{session_id}/web/import-burp", tags=["web"], status_code=201)
async def import_burp(session_id: UUID, request: Request) -> dict[str, object]:
    _, settings = _services(request)
    raw = await _bounded_upload(request, settings.web_import_max_bytes)
    try:
        result = WebImportService(request.app.state.database, settings).import_burp(session_id, raw)
    except WebImportFailure as error:
        raise HTTPException(
            status_code=422,
            detail={"message": str(error), "artifact_id": str(error.artifact_id)},
        ) from error
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    return result.model_dump(mode="json")


@router.post("/sessions/{session_id}/web/build", tags=["web"])
async def build_web_surface(session_id: UUID, request: Request) -> dict[str, object]:
    try:
        SystemModelBuilder(request.app.state.database).build(session_id)
        snapshot = WebSurfaceBuilder(request.app.state.database).build(session_id)
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    return snapshot.model_dump(mode="json")


@router.post("/sessions/{session_id}/web/import-template", tags=["web"], status_code=201)
async def import_template_assessment(session_id: UUID, request: Request) -> dict[str, object]:
    _, settings = _services(request)
    raw = await _bounded_upload(request, settings.web_import_max_bytes)
    try:
        result = WebImportService(request.app.state.database, settings).import_template_assessment(
            session_id, raw
        )
    except WebImportFailure as error:
        raise HTTPException(
            status_code=422,
            detail={"message": str(error), "artifact_id": str(error.artifact_id)},
        ) from error
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    return result.model_dump(mode="json")


@router.get("/sessions/{session_id}/web-surface", tags=["web"])
async def web_surface(session_id: UUID, request: Request) -> dict[str, object]:
    try:
        return WebSurfaceQueryService(request.app.state.database).summary(session_id)
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error


@router.get("/sessions/{session_id}/web-resources", tags=["web"])
async def web_resources(session_id: UUID, request: Request) -> list[dict[str, object]]:
    return WebSurfaceQueryService(request.app.state.database).resources(session_id)


@router.get("/web-resources/{resource_id}", tags=["web"])
async def web_resource(resource_id: UUID, request: Request) -> dict[str, object]:
    try:
        return WebSurfaceQueryService(request.app.state.database).resource(resource_id)
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error


@router.get("/sessions/{session_id}/web-parameters", tags=["web"])
async def web_parameters(session_id: UUID, request: Request) -> list[dict[str, object]]:
    return WebSurfaceQueryService(request.app.state.database).parameters(session_id)


@router.get("/sessions/{session_id}/http-request-templates", tags=["web"])
async def http_request_templates(session_id: UUID, request: Request) -> list[dict[str, object]]:
    return WebSurfaceQueryService(request.app.state.database).templates(session_id)


@router.get("/sessions/{session_id}/web-template-candidates", tags=["web"])
async def web_template_candidates(session_id: UUID, request: Request) -> list[dict[str, object]]:
    return WebSurfaceQueryService(request.app.state.database).candidates(session_id)


@router.post("/sessions/{session_id}/web/discover", tags=["web"])
async def discover_web(
    session_id: UUID, payload: WebDiscoverRequest, request: Request
) -> dict[str, object]:
    service = ActiveWebAssessmentService(
        request.app.state.database, request.app.state.settings, _registry(request)
    )
    try:
        if not payload.execute:
            value = service.preview_discovery(session_id, payload.resource_id, payload.profile)
            return value.model_dump(mode="json")
        else:
            result = await build_controller(
                request.app.state.database,
                request.app.state.settings,
                registry=_registry(request),
            ).request_web_discovery(
                session_id, payload.resource_id, payload.profile.value
            )
    except ValueError as error:
        status = 409 if str(error) == "OPERATOR_APPROVAL_REQUIRED" else 422
        raise HTTPException(status_code=status, detail=str(error)) from error
    return _active_action_payload(request, result.actions[0])


@router.post("/sessions/{session_id}/web/assess", tags=["web"])
async def assess_web(
    session_id: UUID, payload: WebAssessRequest, request: Request
) -> dict[str, object]:
    service = ActiveWebAssessmentService(
        request.app.state.database, request.app.state.settings, _registry(request)
    )
    resource_ids = payload.resource_ids or None
    try:
        if not payload.execute:
            value = service.preview_assessment(session_id, resource_ids, payload.profile)
            return value.model_dump(mode="json")
        else:
            if resource_ids is None:
                with request.app.state.database.session_factory() as session:
                    resource_ids = tuple(
                        item.id
                        for item in RepositorySet(session).web_resources.list_by_session(
                            session_id
                        )
                    )
            result = await build_controller(
                request.app.state.database,
                request.app.state.settings,
                registry=_registry(request),
            ).request_web_assessment(
                session_id, resource_ids, payload.profile.value
            )
    except ValueError as error:
        status = 409 if str(error) == "OPERATOR_APPROVAL_REQUIRED" else 422
        raise HTTPException(status_code=status, detail=str(error)) from error
    return _active_action_payload(request, result.actions[0])


@router.get("/sessions/{session_id}/web/assessment-runs", tags=["web"])
async def web_assessment_runs(session_id: UUID, request: Request) -> list[dict[str, object]]:
    with request.app.state.database.session_factory() as session:
        repositories = RepositorySet(session)
        actions = [
            item
            for item in repositories.research_actions.list_by_session(session_id)
            if item.action_type
            in {
                ResearchActionType.DISCOVER_WEB_CONTENT,
                ResearchActionType.ASSESS_WEB_TEMPLATES,
            }
        ]
        return [_active_action_payload(request, action, repositories) for action in actions]


@router.get("/web/assessment-runs/{tool_run_id}", tags=["web"])
async def web_assessment_run(tool_run_id: UUID, request: Request) -> dict[str, object]:
    return await tool_run(tool_run_id, request)


@router.get("/sessions/{session_id}/tool-runs", tags=["tools"])
async def tool_runs(
    session_id: UUID,
    request: Request,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
) -> list[dict[str, object]]:
    with request.app.state.database.session_factory() as session:
        values = RepositorySet(session).tool_runs.list_by_session(session_id)
    return [item.model_dump(mode="json") for item in values[offset : offset + limit]]


@router.get("/tool-runs/{tool_run_id}", tags=["tools"])
async def tool_run(tool_run_id: UUID, request: Request) -> dict[str, object]:
    with request.app.state.database.session_factory() as session:
        r = RepositorySet(session)
        value = r.tool_runs.get(tool_run_id)
        artifacts = r.tool_artifacts.list_by_run(tool_run_id) if value else []
    if value is None:
        raise HTTPException(status_code=404, detail="tool run does not exist")
    payload = value.model_dump(mode="json")
    payload["artifacts"] = [
        {
            "id": str(item.id),
            "artifact_type": item.artifact_type.value,
            "content_type": item.content_type,
            "size_bytes": item.size_bytes,
            "sha256": item.sha256,
            "parser_status": item.parser_status.value,
            "parser_version": item.parser_version,
        }
        for item in artifacts
    ]
    return payload


@router.post("/sessions/{session_id}/controller/plan", tags=["operator"])
async def controller_plan(session_id: UUID, request: Request) -> dict[str, object]:
    _, settings = _services(request)
    result = await build_controller(request.app.state.database, settings).plan(session_id)
    return {
        "step": result.step.model_dump(mode="json"),
        "decision": result.decision.model_dump(mode="json"),
        "actions": [item.model_dump(mode="json") for item in result.actions],
        "results": [item.model_dump(mode="json") for item in result.results],
    }


@router.post("/sessions/{session_id}/controller/step", tags=["operator"])
async def controller_step(session_id: UUID, request: Request) -> dict[str, object]:
    _, settings = _services(request)
    result = await build_controller(request.app.state.database, settings).step(session_id)
    return {
        "step": result.step.model_dump(mode="json"),
        "decision": result.decision.model_dump(mode="json"),
        "actions": [item.model_dump(mode="json") for item in result.actions],
        "results": [item.model_dump(mode="json") for item in result.results],
    }


@router.post("/sessions/{session_id}/controller/run", tags=["operator"])
async def controller_run(session_id: UUID, request: Request) -> dict[str, object]:
    _, settings = _services(request)
    result = await build_controller(request.app.state.database, settings).run(session_id)
    return {"session_id": str(result.session_id), "stop_reason": result.stop_reason}


@router.get("/sessions/{session_id}/reports", tags=["reports"])
async def reports(session_id: UUID, request: Request) -> list[dict[str, object]]:
    with request.app.state.database.session_factory() as session:
        values = RepositorySet(session).report_metadata.list_by_session(session_id)
    return [item.model_dump(mode="json") for item in values]


@router.post("/sessions/{session_id}/reports", tags=["reports"], status_code=201)
async def generate_report(session_id: UUID, request: Request) -> dict[str, object]:
    _, settings = _services(request)
    try:
        metadata, manifest = ReportService(request.app.state.database, settings).generate(
            session_id
        )
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    return {
        "report": metadata.model_dump(mode="json"),
        "manifest": manifest.model_dump(mode="json"),
        "verified": ReportService.verify_manifest(Path(metadata.path)),
    }


@router.post("/sessions/{session_id}/pause", tags=["operator"])
async def pause_controller(session_id: UUID, request: Request) -> dict[str, object]:
    _, settings = _services(request)
    return (
        build_controller(request.app.state.database, settings)
        .pause(session_id)
        .model_dump(mode="json")
    )


@router.post("/sessions/{session_id}/resume", tags=["operator"])
async def resume_controller(session_id: UUID, request: Request) -> dict[str, object]:
    _, settings = _services(request)
    result = await build_controller(request.app.state.database, settings).resume(session_id)
    return {"session_id": str(result.session_id), "stop_reason": result.stop_reason}


@router.post("/sessions/{session_id}/stop", tags=["operator"])
async def stop_controller(session_id: UUID, request: Request) -> dict[str, object]:
    _, settings = _services(request)
    return (
        build_controller(request.app.state.database, settings)
        .stop(session_id)
        .model_dump(mode="json")
    )


@router.post("/actions/{action_id}/approve", tags=["operator"])
async def approve_action(
    action_id: UUID, payload: ApprovalRequest, request: Request
) -> dict[str, object]:
    _, settings = _services(request)
    try:
        action = await build_controller(
            request.app.state.database, settings, registry=_registry(request)
        ).approve_action(action_id, reason=payload.reason)
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    return action.model_dump(mode="json")


@router.post("/actions/{action_id}/reject", tags=["operator"])
async def reject_action(
    action_id: UUID, payload: ApprovalRequest, request: Request
) -> dict[str, object]:
    _, settings = _services(request)
    try:
        action = build_controller(request.app.state.database, settings).reject_action(
            action_id, reason=payload.reason
        )
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    return action.model_dump(mode="json")


@router.get("/sessions/{session_id}/approvals", tags=["operator"])
async def approvals(session_id: UUID, request: Request) -> list[dict[str, object]]:
    with request.app.state.database.session_factory() as session:
        values = RepositorySet(session).action_approvals.list_by_session(session_id)
    return [item.model_dump(mode="json") for item in values]
