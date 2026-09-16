import json
from pathlib import Path
from uuid import uuid4

import pytest

from typer.testing import CliRunner

from app.attack_graph.builder import AttackGraphBuilder
from app.attack_graph.errors import AttackGraphError
from app.attack_graph.queries import GraphQueryService
from app.cli.main import cli
from app.collectors.pipeline import ObservationPipeline
from app.config import get_settings
from app.domain.assets import Asset, AssetKind
from app.domain.attack_graph import CandidateSignalType, GraphErrorCode
from app.domain.common import Provenance
from app.domain.research import ResearchSession, ResearchTarget, TargetScope
from app.domain.research_planner import (
    ExpectedInformation,
    ResearchIntentProposal,
    ResearchIntentType,
)
from app.execution.identity import LaboratoryIdentityResolver
from app.execution.rust_executor import RustExecutorClient
from app.storage.database import Database
from app.storage.repositories import RepositorySet
from app.research_planner.resolver import CapabilityResolver
from app.research_planner.validator import PlannerValidator
from app.system_model.builder import SystemModelBuilder


def _executor_binary() -> Path:
    return Path("native/rust/target/debug/aegis-executor")


def _session(database: Database, port: int) -> ResearchSession:
    provenance = Provenance(source_type="configuration", source_reference="attack graph test")
    asset = Asset(name="graph-lab", kind=AssetKind.API, provenance=provenance)
    research = ResearchSession(
        name="attack-graph",
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


async def _observe(
    pipeline: ObservationPipeline, session_id, identity: str, path: str
) -> None:
    resolved = LaboratoryIdentityResolver().resolve(identity)
    await pipeline.observe(
        research_session_id=session_id,
        path=path,
        headers=resolved.headers,
        identity_name=resolved.name,
        identity_roles=list(resolved.roles),
    )


@pytest.mark.asyncio
async def test_system_model_graph_paths_signals_staleness_and_export(
    database: Database, live_lab: int, tmp_path, monkeypatch
) -> None:
    research = _session(database, live_lab)
    pipeline = ObservationPipeline(database, RustExecutorClient(_executor_binary()))
    for identity, path in (
        ("anonymous", "/health"),
        ("alice", "/api/profile"),
        ("bob", "/api/orders"),
        ("bob", "/api/orders/101"),
        ("alice", "/api/admin/stats"),
        ("admin", "/api/admin/stats"),
        ("anonymous", "/api/portal"),
    ):
        await _observe(pipeline, research.id, identity, path)
    model_build = SystemModelBuilder(database).build(research.id)

    graph_builder = AttackGraphBuilder(database)
    graph_a, snapshot_a, signals_a = graph_builder.build(research.id)
    graph_b, snapshot_b, signals_b = graph_builder.build(research.id)
    assert model_build.model_sha256 == graph_a.system_model_hash
    assert graph_a.graph_hash == graph_b.graph_hash
    assert graph_a.nodes and graph_a.edges
    assert snapshot_a.blocking_edge_count == 1
    assert snapshot_a.traversable_edge_count > 0
    assert len(signals_a) == len(signals_b) == 2
    cross_session_signal = signals_a[0].model_copy(
        update={
            "id": uuid4(),
            "research_session_id": uuid4(),
            "semantic_key": f"{signals_a[0].semantic_key}:cross-session",
        }
    )
    with database.session_factory.begin() as session:
        with pytest.raises(ValueError, match="cross research sessions"):
            RepositorySet(session).candidate_signals.add(cross_session_signal)

    query = GraphQueryService(database)
    admin_endpoint = f"endpoint:GET:http://127.0.0.1:{live_lab}/api/admin/stats"
    assert query.shortest_path(snapshot_a.id, "identity:alice", admin_endpoint) is None
    blocking = query.blocking_edges(snapshot_a.id, "identity:alice")
    assert len(blocking) == 1
    assert blocking[0].target_node_id == admin_endpoint
    assert blocking[0].observation_ids and blocking[0].evidence_ids

    admin_path = query.shortest_path(snapshot_a.id, "identity:admin", admin_endpoint)
    assert admin_path is not None
    assert admin_path.hop_count == 1
    assert admin_path.system_relationship_ids
    assert admin_path.observation_ids and admin_path.evidence_ids

    order_endpoint = f"endpoint:GET:http://127.0.0.1:{live_lab}/api/orders/101"
    order_path = query.shortest_path(snapshot_a.id, "identity:bob", "data:order:101")
    assert order_path is not None
    assert order_path.node_ids == ["identity:bob", order_endpoint, "data:order:101"]
    assert "data:order:101" in query.accessible_resources(snapshot_a.id, "identity:bob")
    cross = query.candidate_signals(
        snapshot_a.id, CandidateSignalType.CROSS_IDENTITY_RESOURCE_ACCESS.value
    )
    assert len(cross) == 1
    assert cross[0].details["accessor"] == "identity:bob"
    assert cross[0].details["owner"] == "identity:alice"
    assert cross[0].details["resource"] == "data:order:101"
    assert cross[0].observation_ids and cross[0].evidence_ids
    with database.session_factory() as session:
        repositories = RepositorySet(session)
        findings_before = len(repositories.findings.list_by_session(research.id))
        proposal = ResearchIntentProposal(
            intent_type=ResearchIntentType.VERIFY_CANDIDATE_SIGNAL,
            subject_entity_id=cross[0].subject_entity_id,
            target_entity_id=cross[0].target_entity_id,
            reason="determine whether additional observations are required",
            expected_information=(ExpectedInformation.CANDIDATE_EVIDENCE,),
            supporting_signal_ids=(cross[0].id,),
        )
        assert PlannerValidator().validate_intent(
            repositories, research.id, proposal
        )
        assert CapabilityResolver().resolve(proposal.intent_type).value == "HTTP_REQUEST"
        assert len(repositories.findings.list_by_session(research.id)) == findings_before
    role_diff = query.candidate_signals(
        snapshot_a.id, CandidateSignalType.ROLE_ACCESS_DIFFERENCE.value
    )
    assert len(role_diff) == 1
    assert role_diff[0].details["result_a"] != role_diff[0].details["result_b"]

    exported = query.export(snapshot_a.id)
    encoded = json.dumps(exported, sort_keys=True)
    for secret in ("alice-token", "bob-token", "admin-token", "Authorization", "Cookie"):
        assert secret not in encoded
    assert all(edge["observation_ids"] for edge in exported["edges"])
    assert all(edge["evidence_ids"] for edge in exported["edges"])

    monkeypatch.setenv("AEGIS_DATABASE_URL", str(database.engine.url))
    get_settings.cache_clear()
    runner = CliRunner()
    for args in (
        ["graph", "show", str(snapshot_a.id)],
        ["graph", "reachable", "--graph", str(snapshot_a.id), "--from", "identity:bob"],
        ["graph", "cross-identity", "--graph", str(snapshot_a.id)],
        ["graph", "role-diff", "--graph", str(snapshot_a.id)],
    ):
        result = runner.invoke(cli, args)
        assert result.exit_code == 0, result.output
        json.loads(result.output)
    export_path = tmp_path / "graph.json"
    result = runner.invoke(
        cli,
        ["graph", "export", str(snapshot_a.id), "--format", "json", "--output", str(export_path)],
    )
    assert result.exit_code == 0, result.output
    json.loads(export_path.read_text())

    await _observe(pipeline, research.id, "alice", "/api/account/settings")
    changed_model = SystemModelBuilder(database).build(research.id)
    assert changed_model.model_sha256 != graph_a.system_model_hash
    with pytest.raises(AttackGraphError) as captured:
        query.load(snapshot_a.id)
    assert captured.value.code is GraphErrorCode.MODEL_STALE
    new_graph, new_snapshot, _ = graph_builder.build(research.id)
    assert new_graph.system_model_hash == changed_model.model_sha256
    assert new_graph.graph_hash != graph_a.graph_hash
    assert query.snapshot(snapshot_a.id).status.value == "STALE"
    assert query.load(new_snapshot.id).graph_hash == new_graph.graph_hash

    get_settings.cache_clear()
