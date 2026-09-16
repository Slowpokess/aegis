import inspect as python_inspect
import json
from pathlib import Path
import asyncio

import httpx
import pytest

import app.active_web.adapters as active_adapters
from app.active_web.adapters import ActiveProcessResult, FfufAdapter, NucleiAdapter
from app.active_web.parsers import FfufParser, NucleiParser
from app.active_web.service import ActiveWebAssessmentService
from app.config import Settings
from app.controller.factory import build_controller
from app.discovery.errors import ToolExecutionError
from app.discovery.registry import ToolRegistry
from app.domain.active_web import ActiveWebProfile
from app.domain.controller import ResearchActionStatus
from app.domain.discovery import ToolErrorCode, ToolRunStatus
from app.domain.operator import ApprovalMode, ApprovalStatus, ResearchBudgetTemplate
from app.domain.operator import ResearchPolicyProfile
from app.domain.research import TargetScope
from app.main import create_app
from app.operator.service import ProjectService, operator_provenance
from app.storage.repositories import RepositorySet
from app.web_surface.service import WebImportService


FFUF_OUTPUT = json.dumps(
    {
        "results": [
            {
                "url": "http://127.0.0.1:8001/admin",
                "status": 200,
                "length": 12,
                "words": 2,
                "lines": 1,
            },
            {
                "url": "http://127.0.0.1:8001/new-active-resource",
                "status": 200,
                "length": 5,
            },
            {"url": "https://external.invalid/escape", "status": 200},
        ]
    }
).encode()

NUCLEI_OUTPUT = (
    json.dumps(
        {
            "template-id": "aegis-safe-lab-candidate",
            "info": {
                "name": "<script>alert(1)</script>",
                "severity": "info",
            },
            "matcher-name": "status",
            "matched-at": "http://127.0.0.1:8001/admin",
            "type": "http",
            "timestamp": "2026-08-27T00:00:00Z",
        }
    )
    + "\n"
).encode()


def _registry(*, enabled: bool = True, available: bool = True) -> ToolRegistry:
    def resolve(name: str) -> str | None:
        if not available or name not in {"nmap", "ffuf", "nuclei"}:
            return None
        return f"/fixed/{name}"

    return ToolRegistry(
        binary_resolver=resolve,
        version_inspector=lambda _: "7.95",
        ffuf_version_inspector=lambda _: "2.1.0",
        nuclei_version_inspector=lambda _: "3.3.0",
        enabled={"ffuf": enabled, "nuclei": enabled},
    )


def _session(
    database,
    settings: Settings,
    *,
    approval: ApprovalMode = ApprovalMode.AUTO,
    max_requests: int = 100,
):
    projects = ProjectService(database, settings)
    project = projects.create("phase15-3-rc", profile=ResearchPolicyProfile.CONSERVATIVE)
    project = projects.configure(
        project.id,
        scope=TargetScope(
            hosts=("127.0.0.1",),
            ports=(8001,),
            schemes=("http",),
            provenance=operator_provenance("phase15-3-rc-scope"),
        ),
        identity_names=("anonymous",),
        profile=ResearchPolicyProfile.CONSERVATIVE,
        approval_mode=approval,
        budget=ResearchBudgetTemplate(
            max_steps=10,
            max_actions=10,
            max_tool_runs=10,
            max_requests=max_requests,
            max_duration_seconds=600,
            max_llm_calls=0,
        ),
    )
    research = projects.start(project.id)
    WebImportService(database, settings).import_burp(
        research.id, Path("tests/fixtures/web/phase15-burp.xml").read_bytes()
    )
    with database.session_factory() as session:
        resources = RepositorySet(session).web_resources.list_by_session(research.id)
    admin = next(item for item in resources if item.path == "/admin")
    return research, admin


async def _ffuf_success(self, *, target, profile):
    return ActiveProcessResult(
        stdout=FFUF_OUTPUT,
        stderr="",
        argv=self.argv(target=target, profile=profile),
        exit_code=0,
    )


async def _nuclei_success(self, *, targets, profile):
    return ActiveProcessResult(
        stdout=NUCLEI_OUTPUT,
        stderr="",
        argv=(self.descriptor.executable_path or "", "-jsonl"),
        exit_code=0,
    )


def test_active_integrations_profiles_argv_parsers_and_shell_boundary(database, tmp_path) -> None:
    registry = _registry()
    assert {"ffuf", "nuclei"} <= {item.descriptor.id for item in registry.integrations()}
    settings = Settings(environment="test")
    research, resource = _session(database, settings)
    service = ActiveWebAssessmentService(database, settings, registry)
    preview = service.preview_discovery(
        research.id, resource.id, ActiveWebProfile.WEB_CONTENT_SMALL
    )
    profile = service._ffuf_profile(ActiveWebProfile.WEB_CONTENT_SMALL)
    argv = FfufAdapter(registry.require("ffuf"), output_max_bytes=1024).argv(
        target=preview.target + "--config=/tmp/evil", profile=profile
    )
    assert argv[0] == "/fixed/ffuf"
    assert argv[argv.index("-u") + 1].endswith("FUZZ--config=/tmp/evil")
    assert "--config=/tmp/evil" not in argv
    adapter_source = python_inspect.getsource(active_adapters)
    assert "create_subprocess_exec" in adapter_source
    assert "shell=True" not in adapter_source
    nuclei_profile = service._nuclei_profile(ActiveWebProfile.SAFE_TEMPLATES)
    nuclei_argv = NucleiAdapter(
        registry.require("nuclei"), output_max_bytes=1024
    ).argv(targets_file=tmp_path / "targets.txt", profile=nuclei_profile)
    assert nuclei_argv[0] == "/fixed/nuclei"
    assert "-disable-update-check" in nuclei_argv
    assert nuclei_argv[nuclei_argv.index("-templates") + 1] == str(
        settings.nuclei_safe_template.resolve()
    )

    records = FfufParser(max_bytes=10_000, max_results=10).parse(
        FFUF_OUTPUT, research.scope
    )
    assert len(records) == 2
    assert all("external.invalid" not in item.url for item in records)
    with pytest.raises(ValueError, match="valid JSON"):
        FfufParser(max_bytes=100, max_results=10).parse(b"not-json", research.scope)
    assert len(NucleiParser(max_bytes=10_000, max_results=10).parse(NUCLEI_OUTPUT, research.scope)) == 1

    outside = tmp_path / "unapproved.txt"
    outside.write_text("admin\n", encoding="utf-8")
    unsafe_settings = Settings(environment="test", ffuf_small_wordlist=outside)
    with pytest.raises(ValueError, match="approved configured inventory"):
        ActiveWebAssessmentService(database, unsafe_settings, registry).preview_discovery(
            research.id, resource.id
        )
    unsafe_nuclei = Settings(environment="test", nuclei_safe_template=outside)
    with pytest.raises(ValueError, match="approved configured inventory"):
        ActiveWebAssessmentService(database, unsafe_nuclei, registry).preview_assessment(
            research.id, (resource.id,)
        )


@pytest.mark.asyncio
async def test_active_external_execution_uses_controlled_home_without_secret_inheritance(monkeypatch) -> None:
    captured = {}

    def _stream(value: bytes) -> asyncio.StreamReader:
        stream = asyncio.StreamReader()
        stream.feed_data(value)
        stream.feed_eof()
        return stream

    class _Process:
        def __init__(self) -> None:
            self.stdout = _stream(b"{}")
            self.stderr = _stream(b"")
            self.returncode = 0

        async def wait(self) -> int:
            return 0

        def kill(self) -> None:
            self.returncode = -9

    async def fake_exec(*args, **kwargs):
        captured["argv"] = args
        captured["env"] = kwargs["env"]
        return _Process()

    monkeypatch.setattr(active_adapters.asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setenv("NVIDIA_API_KEY", "SHOULD_NOT_LEAK")
    result = await active_adapters._execute(
        ("/usr/local/bin/ffuf", "-V"),
        timeout_seconds=1,
        output_max_bytes=32,
    )
    assert result.exit_code == 0
    env = captured["env"]
    assert env["HOME"].endswith("/aegis-active-tools/ffuf/home")
    assert Path(env["HOME"], "Library", "Application Support", "ffuf", "scraper").is_dir()
    assert env["XDG_CONFIG_HOME"].endswith("/aegis-active-tools/ffuf/xdg_config")
    assert "NVIDIA_API_KEY" not in env


@pytest.mark.asyncio
async def test_active_service_persists_ffuf_nuclei_lineage_without_findings(
    database, monkeypatch
) -> None:
    settings = Settings(environment="test")
    research, resource = _session(database, settings)
    registry = _registry()
    monkeypatch.setattr(FfufAdapter, "execute", _ffuf_success)
    monkeypatch.setattr(NucleiAdapter, "execute", _nuclei_success)
    controller = build_controller(database, settings, registry=registry)

    with database.session_factory() as session:
        repositories = RepositorySet(session)
        before_resources = len(repositories.web_resources.list_by_session(research.id))
        before_findings = len(repositories.findings.list_by_session(research.id))
    ffuf = await controller.request_web_discovery(
        research.id, resource.id, ActiveWebProfile.WEB_CONTENT_SMALL.value
    )
    assert ffuf.actions[0].status is ResearchActionStatus.SATISFIED
    nuclei = await controller.request_web_assessment(
        research.id, (resource.id,), ActiveWebProfile.SAFE_TEMPLATES.value
    )
    assert nuclei.actions[0].status is ResearchActionStatus.SATISFIED

    with database.session_factory() as session:
        repositories = RepositorySet(session)
        runs = [
            item
            for item in repositories.tool_runs.list_by_session(research.id)
            if item.tool_id in {"ffuf", "nuclei"}
        ]
        artifacts = repositories.tool_artifacts.list_by_session(research.id)
        observations = repositories.observations.list_by_session(research.id)
        resources = repositories.web_resources.list_by_session(research.id)
        candidates = repositories.web_template_candidates.list_by_session(research.id)
        provenance = repositories.web_candidate_provenance.list_by_session(research.id)
        findings = repositories.findings.list_by_session(research.id)
    assert {item.tool_id for item in runs} == {"ffuf", "nuclei"}
    assert all(item.status is ToolRunStatus.COMPLETED for item in runs)
    assert any(item.tool_id == "ffuf" for item in artifacts)
    assert any(item.provenance.source_type == "ffuf" for item in observations)
    assert len(resources) == before_resources + 1
    assert len(candidates) == 1 and candidates[0].finding_created is False
    assert len(provenance) == 1 and provenance[0].source == "NUCLEI_ASSESSMENT"
    assert len(findings) == before_findings


@pytest.mark.asyncio
async def test_persisted_approval_is_authoritative_and_policy_is_rechecked(
    database, monkeypatch
) -> None:
    settings = Settings(environment="test")
    research, resource = _session(
        database, settings, approval=ApprovalMode.APPROVE_EVERY_ACTION
    )
    registry = _registry()
    invoked = 0

    async def counted(self, *, target, profile):
        nonlocal invoked
        invoked += 1
        return await _ffuf_success(self, target=target, profile=profile)

    monkeypatch.setattr(FfufAdapter, "execute", counted)
    controller = build_controller(database, settings, registry=registry)
    pending = await controller.request_web_discovery(
        research.id, resource.id, ActiveWebProfile.WEB_CONTENT_SMALL.value
    )
    action = pending.actions[0]
    assert action.status is ResearchActionStatus.WAITING_FOR_APPROVAL
    with database.session_factory() as session:
        repositories = RepositorySet(session)
        approval = repositories.action_approvals.get_by_action(action.id)
        assert approval is not None and approval.status is ApprovalStatus.PENDING
        assert repositories.tool_runs.list_by_session(research.id)[-1].tool_id == "burp_import"
    assert invoked == 0

    rejected = controller.reject_action(action.id, reason="RC rejection proof")
    assert rejected.status is ResearchActionStatus.REJECTED
    assert invoked == 0

    second = await controller.request_web_discovery(
        research.id, resource.id, ActiveWebProfile.WEB_CONTENT_SMALL.value
    )
    descriptor = registry.require("ffuf")
    registry._tools["ffuf"] = descriptor.model_copy(update={"enabled": False})
    blocked = await controller.approve_action(second.actions[0].id)
    assert blocked.status is ResearchActionStatus.FAILED
    assert invoked == 0
    with database.session_factory() as session:
        runs = [
            item
            for item in RepositorySet(session).tool_runs.list_by_session(research.id)
            if item.tool_id == "ffuf"
        ]
    assert len(runs) == 1 and runs[0].status is ToolRunStatus.POLICY_REJECTED


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error_code", "message"),
    [
        (ToolErrorCode.PROCESS_TIMEOUT, "timeout"),
        (ToolErrorCode.OUTPUT_TOO_LARGE, "output exceeded limit"),
    ],
)
async def test_active_failures_are_typed_and_fabricate_no_observations(
    database, monkeypatch, error_code, message
) -> None:
    settings = Settings(environment="test")
    research, resource = _session(database, settings)

    async def fail(self, *, target, profile):
        raise ToolExecutionError(error_code, message)

    monkeypatch.setattr(FfufAdapter, "execute", fail)
    result = await build_controller(
        database, settings, registry=_registry()
    ).request_web_discovery(research.id, resource.id, ActiveWebProfile.WEB_CONTENT_SMALL.value)
    assert result.actions[0].status is ResearchActionStatus.FAILED
    with database.session_factory() as session:
        repositories = RepositorySet(session)
        run = next(
            item
            for item in repositories.tool_runs.list_by_session(research.id)
            if item.tool_id == "ffuf"
        )
        assert run.status is ToolRunStatus.FAILED and run.error_code is error_code
        assert not any(
            item.provenance.source_type == "ffuf"
            for item in repositories.observations.list_by_session(research.id)
        )


@pytest.mark.asyncio
async def test_active_api_rejects_boolean_bypass_and_returns_waiting_action(
    tmp_path, monkeypatch
) -> None:
    settings = Settings(
        environment="test", database_url=f"sqlite:///{tmp_path / 'active-api.db'}"
    )
    app = create_app(settings)
    monkeypatch.setattr(FfufAdapter, "execute", _ffuf_success)
    async with app.router.lifespan_context(app):
        app.state.tool_registry = _registry()
        research, resource = _session(
            app.state.database,
            settings,
            approval=ApprovalMode.APPROVE_EVERY_ACTION,
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            bypass = await client.post(
                f"/sessions/{research.id}/web/discover",
                json={
                    "resource_id": str(resource.id),
                    "profile": "web_content_small",
                    "execute": True,
                    "operator_approved": True,
                },
            )
            assert bypass.status_code == 422
            requested = await client.post(
                f"/sessions/{research.id}/web/discover",
                json={
                    "resource_id": str(resource.id),
                    "profile": "web_content_small",
                    "execute": True,
                },
            )
            assert requested.status_code == 200
            payload = requested.json()
            assert payload["status"] == "WAITING_FOR_APPROVAL"
            assert payload["approval_status"] == "PENDING"
            assert payload["tool_run_id"] is None
            runs = await client.get(f"/sessions/{research.id}/web/assessment-runs")
            assert runs.status_code == 200
            assert runs.json()[0]["status"] == "WAITING_FOR_APPROVAL"
            approved = await client.post(
                f"/actions/{payload['action_id']}/approve", json={}
            )
            assert approved.status_code == 200
            assert approved.json()["status"] == "SATISFIED"


@pytest.mark.asyncio
async def test_direct_service_execution_requires_persisted_action(database) -> None:
    settings = Settings(environment="test")
    research, resource = _session(database, settings)
    service = ActiveWebAssessmentService(database, settings, _registry())
    with pytest.raises(ValueError, match="AUTHORIZED_ACTIVE_WEB_ACTION_REQUIRED"):
        await service.discover(
            research.id,
            resource.id,
            action_id=resource.id,
            profile=ActiveWebProfile.WEB_CONTENT_SMALL,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("stdout", "exit_code", "expected_error"),
    [
        (b"not-json", 0, ToolErrorCode.PARSER_FAILED),
        (b"bounded diagnostic", 2, ToolErrorCode.PROCESS_FAILED),
    ],
)
async def test_ffuf_malformed_and_nonzero_preserve_failed_artifact(
    database, monkeypatch, stdout, exit_code, expected_error
) -> None:
    settings = Settings(environment="test")
    research, resource = _session(database, settings)

    async def result(self, *, target, profile):
        return ActiveProcessResult(
            stdout=stdout,
            stderr=(
                "Authorization: Bearer phase15-secret\n"
                "Cookie=sid=phase15-secret\n"
                "NVIDIA_API_KEY=nvapi-phase15-secret"
            ),
            argv=self.argv(target=target, profile=profile),
            exit_code=exit_code,
        )

    monkeypatch.setattr(FfufAdapter, "execute", result)
    await build_controller(database, settings, registry=_registry()).request_web_discovery(
        research.id, resource.id, ActiveWebProfile.WEB_CONTENT_SMALL.value
    )
    with database.session_factory() as session:
        repositories = RepositorySet(session)
        run = next(
            item
            for item in repositories.tool_runs.list_by_session(research.id)
            if item.tool_id == "ffuf"
        )
        artifact = repositories.tool_artifacts.get(run.artifact_ids[0])
        assert run.status is ToolRunStatus.FAILED and run.error_code is expected_error
        assert artifact is not None and artifact.parser_status.value == "FAILED"
        assert "phase15-secret" not in (run.error or "")
        assert "[REDACTED]" in (run.error or "") or expected_error is ToolErrorCode.PARSER_FAILED
        assert not any(
            item.provenance.source_type == "ffuf"
            for item in repositories.observations.list_by_session(research.id)
        )


def test_active_preview_denies_unavailable_tool_and_exhausted_request_budget(database) -> None:
    settings = Settings(environment="test")
    research, resource = _session(database, settings, max_requests=1)
    unavailable = ActiveWebAssessmentService(database, settings, _registry(available=False))
    assert unavailable.preview_discovery(research.id, resource.id).policy_reason == (
        "TOOL_NOT_AVAILABLE"
    )
    budgeted = ActiveWebAssessmentService(database, settings, _registry())
    preview = budgeted.preview_discovery(research.id, resource.id)
    assert preview.policy_allowed is False
    assert preview.policy_reason == "RESEARCH_BUDGET_EXCEEDED"


@pytest.mark.asyncio
async def test_passive_and_active_nuclei_candidate_deduplicate_with_two_provenances(
    database, monkeypatch
) -> None:
    settings = Settings(environment="test")
    research, resource = _session(database, settings)
    WebImportService(database, settings).import_template_assessment(research.id, NUCLEI_OUTPUT)
    monkeypatch.setattr(NucleiAdapter, "execute", _nuclei_success)
    result = await build_controller(
        database, settings, registry=_registry()
    ).request_web_assessment(
        research.id, (resource.id,), ActiveWebProfile.SAFE_TEMPLATES.value
    )
    assert result.actions[0].status is ResearchActionStatus.SATISFIED
    with database.session_factory() as session:
        repositories = RepositorySet(session)
        candidates = repositories.web_template_candidates.list_by_session(research.id)
        provenance = repositories.web_candidate_provenance.list_by_candidate(candidates[0].id)
        findings = repositories.findings.list_by_session(research.id)
    assert len(candidates) == 1
    assert {item.source for item in provenance} == {
        "TEMPLATE_RESULT",
        "NUCLEI_ASSESSMENT",
    }
    assert findings == []

    foreign, _ = _session(database, settings)
    with pytest.raises(ValueError, match="cannot cross ResearchSession"):
        with database.session_factory.begin() as session:
            RepositorySet(session).web_candidate_provenance.add(
                provenance[0].model_copy(update={"research_session_id": foreign.id})
            )


@pytest.mark.asyncio
async def test_cross_session_nuclei_resource_is_rejected_before_process(
    database, monkeypatch
) -> None:
    settings = Settings(environment="test")
    first, _ = _session(database, settings)
    _, foreign = _session(database, settings)
    invoked = False

    async def execute(self, *, targets, profile):
        nonlocal invoked
        invoked = True
        return await _nuclei_success(self, targets=targets, profile=profile)

    monkeypatch.setattr(NucleiAdapter, "execute", execute)
    result = await build_controller(
        database, settings, registry=_registry()
    ).request_web_assessment(
        first.id, (foreign.id,), ActiveWebProfile.SAFE_TEMPLATES.value
    )
    assert result.actions[0].status is ResearchActionStatus.REJECTED
    assert result.actions[0].validation_reason == "WEB_RESOURCE_NOT_FOUND"
    assert invoked is False
