from pathlib import Path
import json

import pytest
from typer.testing import CliRunner

from app.collectors.pipeline import ObservationPipeline
from app.cli.main import cli
from app.config import get_settings
from app.config import Settings
from app.discovery.adapters import AdapterExecution
from app.discovery.engine import DiscoveryEngine
from app.discovery.parsers import NmapParser
from app.discovery.registry import ToolRegistry
from app.domain.assets import Asset, AssetKind
from app.domain.common import Provenance
from app.domain.discovery import ArtifactType
from app.domain.research import ResearchSession, ResearchTarget, TargetScope
from app.domain.research_planner import (
    ExpectedInformation,
    PlannerDecision,
    PlannerState,
    ResearchIntentProposal,
    ResearchIntentStatus,
    ResearchIntentType,
)
from app.execution.rust_executor import RustExecutorClient
from app.llm.providers.fake import FakeLLMProvider
from app.research_planner.engine import ResearchEngine
from app.storage.repositories import RepositorySet


class FixtureNmapAdapter:
    parser = NmapParser()

    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.invocations = 0

    def validate_request(self, request) -> None:
        assert request.tool == "nmap"
        assert request.profile == "service_discovery"

    async def execute(self, request) -> AdapterExecution:
        self.invocations += 1
        return AdapterExecution(
            raw_artifact=self.raw,
            artifact_type=ArtifactType.NMAP_XML,
            content_type="application/xml",
            parsed_records=(),
            parser_version=self.parser.version,
            argv=("/fixed/nmap", "PROFILE:nmap-service-discovery-v1"),
            exit_code=0,
        )


def _setup(database):
    provenance = Provenance(source_type="test", source_reference="phase10-integration")
    asset = Asset(name="lab", kind=AssetKind.API, provenance=provenance)
    research = ResearchSession(
        name="planner-lab",
        target=ResearchTarget(
            asset_id=asset.id,
            name="lab",
            base_url="http://127.0.0.1:8001",
            provenance=provenance,
        ),
        scope=TargetScope(
            hosts=("127.0.0.1",),
            ports=(8001,),
            schemes=("http",),
            provenance=provenance,
        ),
        provenance=provenance,
    )
    with database.session_factory.begin() as session:
        repositories = RepositorySet(session)
        repositories.assets.add(asset)
        repositories.research_sessions.add(research)
    return research


def _engine(database, research, adapter, decision, *, nmap_available=True, **setting_updates):
    settings = Settings(environment="test", **setting_updates)
    registry = ToolRegistry(
        binary_resolver=lambda name: (
            "/fixed/nmap" if name == "nmap" and nmap_available else None
        ),
        version_inspector=lambda _: "7.95",
    )
    discovery = DiscoveryEngine(
        database,
        registry,
        ObservationPipeline(
            database, RustExecutorClient(Path("native/rust/target/debug/aegis-executor"))
        ),
        nmap_adapter_factory=lambda _: adapter,
    )
    return ResearchEngine(
        database,
        settings,
        discovery,
        provider=FakeLLMProvider([decision], model="fake-research-planner-v1"),
    )


def _decision(research, subject=None):
    return PlannerDecision(
        session_id=research.id,
        state=PlannerState.CONTINUE,
        intents=(
            ResearchIntentProposal(
                intent_type=ResearchIntentType.DISCOVER_SERVICES,
                subject_entity_id=subject or research.target.asset_id,
                reason="service information is missing",
                expected_information=(ExpectedInformation.SERVICES,),
            ),
        ),
    )


@pytest.mark.asyncio
async def test_plan_only_then_execution_satisfaction_and_duplicate_stop(database) -> None:
    research = _setup(database)
    raw = b'<nmaprun><host><address addr="127.0.0.1"/><ports><port protocol="tcp" portid="8001"><state state="open"/><service name="http"/></port></ports></host></nmaprun>'
    adapter = FixtureNmapAdapter(raw)
    dry = await _engine(database, research, adapter, _decision(research)).step(
        research.id, execute=False
    )
    assert dry.intent_ids
    assert adapter.invocations == 0
    with database.session_factory() as session:
        assert RepositorySet(session).tool_runs.list_by_session(research.id) == []

    executed = await _engine(database, research, adapter, _decision(research)).step(research.id)
    assert executed.model_hash_after and executed.graph_hash_after
    assert adapter.invocations == 1
    with database.session_factory() as session:
        repositories = RepositorySet(session)
        intent = repositories.research_intents.get(executed.intent_ids[0])
        assert intent is not None
        assert intent.status is ResearchIntentStatus.SATISFIED
        assert intent.resulting_observation_ids
        assert len(repositories.system_services.list_by_session(research.id)) == 1
        findings_before = len(repositories.findings.list())

    duplicate = await _engine(database, research, adapter, _decision(research)).step(research.id)
    with database.session_factory() as session:
        repositories = RepositorySet(session)
        assert duplicate.intent_ids == (intent.id,)
        assert len(repositories.research_intents.list_by_session(research.id)) == 1
        assert len(repositories.tool_runs.list_by_session(research.id)) == 1
        assert len(repositories.findings.list()) == findings_before
    assert adapter.invocations == 1


@pytest.mark.asyncio
async def test_out_of_scope_proposal_never_creates_tool_run(database) -> None:
    research = _setup(database)
    adapter = FixtureNmapAdapter(b"<nmaprun/>")
    step = await _engine(
        database, research, adapter, _decision(research, subject=__import__("uuid").uuid4())
    ).step(research.id)
    with database.session_factory() as session:
        repositories = RepositorySet(session)
        intent = repositories.research_intents.list_by_step(step.id)[0]
        assert intent.status is ResearchIntentStatus.REJECTED
        assert repositories.tool_runs.list_by_session(research.id) == []
    assert adapter.invocations == 0


def test_research_plan_cli_invokes_zero_tool_processes(database, monkeypatch) -> None:
    research = _setup(database)
    monkeypatch.setenv("AEGIS_DATABASE_URL", str(database.engine.url))
    get_settings.cache_clear()
    result = CliRunner().invoke(
        cli, ["research", "plan", "--session", str(research.id)]
    )
    assert result.exit_code == 0, result.output
    output = json.loads(result.output)
    assert output["tool_processes_invoked"] == 0
    with database.session_factory() as session:
        assert RepositorySet(session).tool_runs.list_by_session(research.id) == []
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_research_loop_stops_at_configured_step_limit(database, monkeypatch) -> None:
    research = _setup(database)
    adapter = FixtureNmapAdapter(b"<nmaprun/>")
    engine = _engine(
        database,
        research,
        adapter,
        PlannerDecision(session_id=research.id, state=PlannerState.CONTINUE),
        research_max_steps=2,
    )
    calls = 0

    async def continuing_step(session_id, *, execute=True, tool_run_budget=None):
        nonlocal calls
        calls += 1
        return __import__("app.domain.research_planner", fromlist=["ResearchStep"]).ResearchStep(
            research_session_id=session_id,
            step_number=calls,
            context_hash="0" * 64,
            planner_provider="fake",
            planner_model="limit-fixture",
            decision=PlannerDecision(session_id=session_id, state=PlannerState.CONTINUE),
            status=__import__("app.domain.research_planner", fromlist=["ResearchStepStatus"]).ResearchStepStatus.COMPLETED,
            provenance=Provenance(source_type="test", source_reference="limit"),
        )

    monkeypatch.setattr(engine, "step", continuing_step)
    result = await engine.run(research.id)
    assert result.stop_state is PlannerState.STOP_LIMIT_REACHED
    assert len(result.steps) == 2
    assert result.total_tool_runs == 0


@pytest.mark.asyncio
async def test_tool_run_budget_and_unavailable_tool_fail_without_process(database) -> None:
    research = _setup(database)
    adapter = FixtureNmapAdapter(b"<nmaprun/>")
    budgeted = _engine(database, research, adapter, _decision(research))
    step = await budgeted.step(research.id, tool_run_budget=0)
    with database.session_factory() as session:
        intent = RepositorySet(session).research_intents.get(step.intent_ids[0])
        assert intent is not None
        assert intent.status is ResearchIntentStatus.UNSATISFIED
        assert intent.policy_reason == "RESEARCH_TOOL_RUN_LIMIT"
        assert RepositorySet(session).tool_runs.list_by_session(research.id) == []
    assert adapter.invocations == 0

    other = _setup(database)
    unavailable = _engine(
        database,
        other,
        adapter,
        _decision(other),
        nmap_available=False,
    )
    unavailable_step = await unavailable.step(other.id)
    with database.session_factory() as session:
        intent = RepositorySet(session).research_intents.get(unavailable_step.intent_ids[0])
        assert intent is not None
        assert intent.status is ResearchIntentStatus.UNSATISFIED
        assert intent.policy_reason == "TOOL_NOT_AVAILABLE"
        assert RepositorySet(session).tool_runs.list_by_session(other.id) == []
    assert adapter.invocations == 0


@pytest.mark.asyncio
async def test_research_duration_limit_stops_before_planning(database) -> None:
    research = _setup(database)
    adapter = FixtureNmapAdapter(b"<nmaprun/>")
    engine = _engine(
        database,
        research,
        adapter,
        _decision(research),
        research_max_duration_seconds=1,
    )
    values = iter((0.0, 2.0))
    engine.clock = lambda: next(values)
    result = await engine.run(research.id)
    assert result.stop_state is PlannerState.STOP_LIMIT_REACHED
    assert result.stop_reason == "research duration limit reached"
    assert result.steps == ()
