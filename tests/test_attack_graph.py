from uuid import uuid4
from pathlib import Path

import pytest

from app.attack_graph.errors import AttackGraphError
from app.attack_graph.queries import GraphQueryService
from app.domain.attack_graph import (
    AttackGraph,
    EdgeDisposition,
    GraphEdge,
    GraphEdgeType,
    GraphErrorCode,
    GraphMode,
    GraphNode,
)
from app.domain.common import FactClassification
from app.domain.system_model import SystemEntityType
from app.storage.database import Database


def _node(name: str) -> GraphNode:
    lineage = uuid4()
    return GraphNode(
        node_id=name,
        node_type=SystemEntityType.ENDPOINT,
        system_entity_id=uuid4(),
        canonical_identifier=name,
        classification=FactClassification.OBSERVED,
        confidence=1.0,
        observation_ids=[lineage],
        evidence_ids=[uuid4()],
    )


def _edge(source: str, target: str, index: int) -> GraphEdge:
    return GraphEdge(
        edge_id=f"{index:064x}",
        source_node_id=source,
        target_node_id=target,
        edge_type=GraphEdgeType.CAN_ACCESS,
        disposition=EdgeDisposition.TRAVERSABLE,
        classification=FactClassification.OBSERVED,
        confidence=0.9,
        system_relationship_ids=[uuid4()],
        observation_ids=[uuid4()],
        evidence_ids=[uuid4()],
    )


def _graph() -> AttackGraph:
    return AttackGraph(
        graph_id=uuid4(),
        research_session_id=uuid4(),
        system_model_hash="a" * 64,
        graph_hash="b" * 64,
        mode=GraphMode.OBSERVED_ONLY,
        nodes=[_node(name) for name in ("a", "b", "c", "d")],
        edges=[
            _edge("a", "b", 1),
            _edge("a", "c", 2),
            _edge("b", "d", 3),
            _edge("c", "d", 4),
            _edge("d", "a", 5),
        ],
    )


def test_shortest_path_and_bounded_simple_paths_are_deterministic(
    database: Database, monkeypatch
) -> None:
    graph = _graph()
    query = GraphQueryService(database, max_depth=4, max_paths=1)
    monkeypatch.setattr(query, "load", lambda _graph_id: graph)

    shortest = query.shortest_path(graph.graph_id, "a", "d")
    assert shortest is not None
    assert shortest.node_ids == ["a", "b", "d"]
    assert shortest.hop_count == 2
    assert shortest.confidence == 0.9
    assert shortest.observation_ids and shortest.evidence_ids

    paths = query.paths(graph.graph_id, "a", "d")
    assert len(paths.paths) == 1
    assert paths.paths[0].node_ids == ["a", "b", "d"]
    assert paths.truncated is True
    assert paths.reason == "MAX_PATHS_REACHED"


def test_cycle_handling_depth_limit_and_unknown_node(database: Database, monkeypatch) -> None:
    graph = _graph()
    query = GraphQueryService(database, max_depth=1, max_paths=100)
    monkeypatch.setattr(query, "load", lambda _graph_id: graph)

    assert query.shortest_path(graph.graph_id, "a", "d") is None
    assert query.paths(graph.graph_id, "a", "d").paths == []
    assert query.reachable_from(graph.graph_id, "a") == ["b", "c", "d"]
    with pytest.raises(AttackGraphError) as captured:
        query.shortest_path(graph.graph_id, "missing", "d")
    assert captured.value.code is GraphErrorCode.NODE_NOT_FOUND


def test_blocking_edges_never_become_traversable(database: Database, monkeypatch) -> None:
    graph = _graph().model_copy(
        update={
            "edges": [
                _edge("a", "b", 1).model_copy(
                    update={"disposition": EdgeDisposition.BLOCKING}
                )
            ]
        }
    )
    query = GraphQueryService(database)
    monkeypatch.setattr(query, "load", lambda _graph_id: graph)
    assert query.shortest_path(graph.graph_id, "a", "b") is None
    assert query.blocking_edges(graph.graph_id, "a")[0].target_node_id == "b"


def test_attack_graph_layer_has_no_network_execution_or_ground_truth_dependency() -> None:
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in Path("app/attack_graph").glob("*.py")
    )
    for forbidden in (
        "import subprocess",
        "import requests",
        "import httpx",
        "lab.ground_truth",
        "lab/scenarios",
        "from evals",
        "import evals",
        "RustExecutorClient",
    ):
        assert forbidden not in source
