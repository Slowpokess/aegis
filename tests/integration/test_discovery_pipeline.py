import json
from pathlib import Path

import pytest

from typer.testing import CliRunner

from app.attack_graph.builder import AttackGraphBuilder
from app.attack_graph.errors import AttackGraphError
from app.attack_graph.queries import GraphQueryService
from app.cli.main import cli
from app.collectors.pipeline import ObservationPipeline
from app.config import get_settings
from app.discovery.adapters import AdapterExecution, DNSAdapter
from app.discovery.engine import DiscoveryEngine
from app.discovery.parsers import NmapParser
from app.discovery.registry import ToolRegistry
from app.domain.assets import Asset, AssetKind
from app.domain.attack_graph import GraphErrorCode
from app.domain.common import Provenance
from app.domain.discovery import (
    ArtifactType,
    DiscoveryPlanStatus,
    DiscoveryProfile,
    ParserStatus,
    PlanItemRequirement,
    ToolErrorCode,
    ToolRequest,
    ToolRunStatus,
    ToolTarget,
)
from app.domain.research import ResearchSession, ResearchTarget, TargetScope
from app.execution.rust_executor import RustExecutorClient
from app.storage.database import Database
from app.storage.repositories import RepositorySet
from app.system_model.builder import SystemModelBuilder


class FixtureNmapAdapter:
    parser = NmapParser()

    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.invoked = False

    def validate_request(self, request) -> None:
        assert request.tool == "nmap"
        assert request.profile == "service_discovery"

    async def execute(self, request) -> AdapterExecution:
        self.invoked = True
        return AdapterExecution(
            raw_artifact=self.raw,
            artifact_type=ArtifactType.NMAP_XML,
            content_type="application/xml",
            parsed_records=(),
            parser_version=self.parser.version,
            argv=("/fixed/nmap", "-Pn", "-n", "-p", "8001", "-oX", "-", "127.0.0.1"),
            exit_code=0,
        )


def _session(database: Database, port: int) -> ResearchSession:
    provenance = Provenance(source_type="configuration", source_reference="phase9-integration")
    asset = Asset(name="discovery-lab", kind=AssetKind.API, provenance=provenance)
    research = ResearchSession(
        name="discovery",
        target=ResearchTarget(
            asset_id=asset.id,
            name="controlled-lab",
            base_url=f"http://127.0.0.1:{port}",
            provenance=provenance,
        ),
        scope=TargetScope(
            hosts=("127.0.0.1",),
            ports=(port,),
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


def _registry() -> ToolRegistry:
    return ToolRegistry(
        binary_resolver=lambda name: "/fixed/nmap" if name == "nmap" else None,
        version_inspector=lambda _: "7.95",
    )


@pytest.mark.asyncio
async def test_discovery_artifact_observation_model_graph_and_cli_lineage(
    database: Database, live_lab: int, tmp_path, monkeypatch
) -> None:
    research = _session(database, live_lab)
    pipeline = ObservationPipeline(
        database, RustExecutorClient(Path("native/rust/target/debug/aegis-executor"))
    )
    await pipeline.observe(research_session_id=research.id, path="/health")
    initial_model = SystemModelBuilder(database).build(research.id)
    _, old_snapshot, _ = AttackGraphBuilder(database).build(research.id)

    raw = (
        f'<nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/>'
        f'<ports><port protocol="tcp" portid="{live_lab}"><state state="open"/>'
        '<service name="http" product="fixture"/></port></ports></host></nmaprun>'
    ).encode()
    adapter = FixtureNmapAdapter(raw)
    engine = DiscoveryEngine(
        database,
        _registry(),
        pipeline,
        nmap_adapter_factory=lambda _: adapter,
        dns_adapter=DNSAdapter(resolver=lambda _: ("127.0.0.1",)),
    )
    plan = engine.create_plan(research.id, DiscoveryProfile.STANDARD)
    assert [item.tool for item in plan.planned_tool_runs] == ["http", "nmap"]
    completed = await engine.run(plan.id)
    assert completed.status is DiscoveryPlanStatus.COMPLETED
    assert adapter.invoked is True

    with database.session_factory() as session:
        repositories = RepositorySet(session)
        runs = repositories.tool_runs.list_by_plan(plan.id)
        nmap_run = next(run for run in runs if run.tool_id == "nmap")
        artifact = repositories.tool_artifacts.list_by_run(nmap_run.id)[0]
    assert all(run.status is ToolRunStatus.COMPLETED for run in runs)
    assert artifact.parser_status is ParserStatus.COMPLETED
    assert artifact.sha256
    assert nmap_run.normalized_argv[0] == "/fixed/nmap"
    assert "--script" not in nmap_run.normalized_argv
    assert nmap_run.observation_ids

    enriched = SystemModelBuilder(database).build(research.id)
    assert enriched.model_sha256 != initial_model.model_sha256
    with database.session_factory() as session:
        repositories = RepositorySet(session)
        services = repositories.system_services.list_by_session(research.id)
        assert len(services) == 1
        service = services[0]
        assert len(service.observation_ids) >= 2
        assert artifact.id in service.evidence_ids
    query = GraphQueryService(database)
    with pytest.raises(AttackGraphError) as captured:
        query.load(old_snapshot.id)
    assert captured.value.code is GraphErrorCode.MODEL_STALE
    new_graph, new_snapshot, _ = AttackGraphBuilder(database).build(research.id)
    assert new_graph.graph_hash != old_snapshot.graph_hash
    assert query.load(new_snapshot.id).graph_hash == new_graph.graph_hash

    exported = engine.export(plan.id)
    encoded = json.dumps(exported, sort_keys=True)
    assert "content_base64" not in encoded
    for secret in ("alice-token", "bob-token", "admin-token", "Authorization", "Cookie"):
        assert secret not in encoded

    monkeypatch.setenv("AEGIS_DATABASE_URL", str(database.engine.url))
    get_settings.cache_clear()
    runner = CliRunner()
    for args in (
        ["tools", "list"],
        ["tools", "show", "nmap"],
        ["tools", "doctor"],
        ["tool-runs", "list", "--session", str(research.id)],
        ["tool-runs", "show", str(nmap_run.id)],
        ["artifacts", "show", str(artifact.id)],
        ["observations", "list", "--session", str(research.id)],
    ):
        result = runner.invoke(cli, args)
        assert result.exit_code == 0, result.output
        parsed_output = json.loads(result.output)
        if args[:2] == ["observations", "list"]:
            assert any(item.get("source_type") == "nmap" for item in parsed_output)
    export_path = tmp_path / "discovery.json"
    result = runner.invoke(
        cli,
        ["discover", "export", str(plan.id), "--format", "json", "--output", str(export_path)],
    )
    assert result.exit_code == 0, result.output
    json.loads(export_path.read_text())
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_parser_failure_preserves_raw_artifact_without_nmap_observations(
    database: Database, live_lab: int
) -> None:
    research = _session(database, live_lab)
    pipeline = ObservationPipeline(
        database, RustExecutorClient(Path("native/rust/target/debug/aegis-executor"))
    )
    adapter = FixtureNmapAdapter(b"<malformed")
    engine = DiscoveryEngine(
        database,
        _registry(),
        pipeline,
        nmap_adapter_factory=lambda _: adapter,
    )
    plan = engine.create_plan(research.id, DiscoveryProfile.STANDARD)
    completed = await engine.run(plan.id)
    assert completed.status is DiscoveryPlanStatus.PARTIAL
    with database.session_factory() as session:
        repositories = RepositorySet(session)
        nmap_run = next(
            run for run in repositories.tool_runs.list_by_plan(plan.id) if run.tool_id == "nmap"
        )
        artifact = repositories.tool_artifacts.list_by_run(nmap_run.id)[0]
    assert nmap_run.status is ToolRunStatus.FAILED
    assert nmap_run.observation_ids == []
    assert artifact.content_bytes() == b"<malformed"
    assert artifact.parser_status is ParserStatus.FAILED


@pytest.mark.asyncio
async def test_out_of_scope_request_is_rejected_without_adapter_invocation(
    database: Database,
) -> None:
    research = _session(database, 8001)
    adapter = FixtureNmapAdapter(b"<nmaprun/>")
    pipeline = ObservationPipeline(
        database, RustExecutorClient(Path("native/rust/target/debug/aegis-executor"))
    )
    engine = DiscoveryEngine(
        database,
        _registry(),
        pipeline,
        nmap_adapter_factory=lambda _: adapter,
    )
    plan = engine.create_plan(research.id, DiscoveryProfile.STANDARD)
    rejected = await engine._run_request(
        plan,
        research,
        ToolRequest(
            tool="nmap",
            profile="service_discovery",
            target=ToolTarget.from_scope("outside.invalid", (8001,), "http"),
            timeout_seconds=10,
            requirement=PlanItemRequirement.OPTIONAL,
        ),
    )
    assert rejected.status is ToolRunStatus.POLICY_REJECTED
    assert rejected.error_code is ToolErrorCode.TARGET_OUT_OF_SCOPE
    assert adapter.invoked is False
