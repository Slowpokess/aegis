from pathlib import Path

import pytest

from app.collectors.pipeline import ObservationPipeline
from app.config import Settings
from app.discovery.adapters import AdapterExecution
from app.discovery.engine import DiscoveryEngine
from app.discovery.parsers import NmapParser
from app.discovery.registry import ToolRegistry
from app.domain.assets import Asset, AssetKind
from app.domain.common import Provenance
from app.domain.discovery import ArtifactType
from app.domain.research import ResearchSession, ResearchTarget, TargetScope
from app.domain.research_planner import ResearchIntentStatus
from app.domain.research_strategy import GapStatus, GapType
from app.execution.rust_executor import RustExecutorClient
from app.llm.providers.fake import FakeLLMProvider
from app.research_planner.engine import ResearchEngine
from app.research_planner.resolver import ToolResolver
from app.research_strategy.knowledge import KnowledgeService
from app.research_strategy.strategy import ResearchStrategyEngine
from app.storage.repositories import RepositorySet


class StrategyFixtureNmapAdapter:
    parser = NmapParser()

    def __init__(self) -> None:
        self.invocations = 0

    def validate_request(self, request) -> None:
        assert request.tool == "nmap"
        assert request.profile == "service_discovery"

    async def execute(self, request) -> AdapterExecution:
        self.invocations += 1
        return AdapterExecution(
            raw_artifact=(
                b'<nmaprun><host><address addr="127.0.0.1"/><ports>'
                b'<port protocol="tcp" portid="8001"><state state="open"/>'
                b'<service name="http"/></port></ports></host></nmaprun>'
            ),
            artifact_type=ArtifactType.NMAP_XML,
            content_type="application/xml",
            parsed_records=(),
            parser_version=self.parser.version,
            argv=("/fixed/nmap", "PROFILE:nmap-service-discovery-v1"),
            exit_code=0,
        )


def _research(database) -> ResearchSession:
    provenance = Provenance(source_type="test", source_reference="phase11-integration")
    asset = Asset(name="strategy-lab", kind=AssetKind.API, provenance=provenance)
    research = ResearchSession(
        name="strategy-lab",
        target=ResearchTarget(
            asset_id=asset.id,
            name="strategy-lab",
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


@pytest.mark.asyncio
async def test_strategy_intent_uses_phase10_discovery_and_resolves_gap(database) -> None:
    research = _research(database)
    adapter = StrategyFixtureNmapAdapter()
    registry = ToolRegistry(
        binary_resolver=lambda name: "/fixed/nmap" if name == "nmap" else None,
        version_inspector=lambda _: "7.95",
    )
    discovery = DiscoveryEngine(
        database,
        registry,
        ObservationPipeline(
            database,
            RustExecutorClient(Path("native/rust/target/debug/aegis-executor")),
        ),
        nmap_adapter_factory=lambda _: adapter,
    )
    strategy = ResearchStrategyEngine(
        database,
        ToolResolver(registry, discovery.policy),
    )
    initial_state, initial_snapshot, initial_gaps = KnowledgeService(database).build(
        research.id
    )
    gap = next(
        item
        for item in initial_gaps
        if item.gap_type is GapType.MISSING_SERVICE_INFORMATION
    )
    strategy_run, decision = strategy.plan(research.id)
    assert strategy_run.selected_intent_count == 1
    assert decision.intents[0].evidence_gap_ids == (gap.id,)
    assert adapter.invocations == 0

    step = await ResearchEngine(
        database,
        Settings(environment="test"),
        discovery,
        provider=FakeLLMProvider([decision], model="deterministic-strategy-v1"),
    ).step(research.id)
    assert adapter.invocations == 1
    assert step.model_hash_after and step.graph_hash_after
    final_state, final_snapshot, final_gaps = KnowledgeService(database).build(research.id)
    final_gap = next(item for item in final_gaps if item.id == gap.id)
    assert final_gap.status is GapStatus.RESOLVED
    assert initial_snapshot.sha256 != final_snapshot.sha256
    assert len(final_state.facts) > len(initial_state.facts)
    with database.session_factory() as session:
        repositories = RepositorySet(session)
        intent = repositories.research_intents.list_by_step(step.id)[0]
        assert intent.status is ResearchIntentStatus.SATISFIED
        assert intent.evidence_gap_ids == (gap.id,)
        assert len(repositories.tool_runs.list_by_session(research.id)) == 1
        assert len(repositories.tool_artifacts.list_by_run(intent.tool_run_ids[0])) == 1
        assert intent.resulting_observation_ids
        assert len(repositories.findings.list()) == 0
