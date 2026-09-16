import hashlib
import json
from collections import deque
from typing import Any
from uuid import UUID

from app.attack_graph.builder import AttackGraphBuilder
from app.attack_graph.errors import AttackGraphError
from app.domain.attack_graph import (
    AttackGraph,
    AttackGraphSnapshot,
    AttackPath,
    CandidateSignalType,
    EdgeDisposition,
    GraphEdge,
    GraphErrorCode,
    GraphMode,
    GraphSnapshotStatus,
    PathQueryResult,
    PathType,
)
from app.domain.common import FactClassification
from app.domain.system_model import SystemEntityType
from app.storage.database import Database
from app.storage.repositories import RepositorySet
from app.system_model.serialization import model_sha256


class GraphQueryService:
    def __init__(
        self,
        database: Database,
        *,
        max_depth: int = 6,
        max_paths: int = 100,
        max_nodes: int = 10_000,
    ) -> None:
        if max_depth < 1 or max_paths < 1:
            raise ValueError("graph query limits must be positive")
        self.database = database
        self.max_depth = max_depth
        self.max_paths = max_paths
        self.max_nodes = max_nodes

    def load(self, graph_id: UUID, *, allow_stale: bool = False) -> AttackGraph:
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            snapshot = repositories.attack_graph_snapshots.get(graph_id)
            if snapshot is None:
                raise AttackGraphError(GraphErrorCode.MODEL_NOT_FOUND, "graph does not exist")
            current_hash = model_sha256(repositories, snapshot.research_session_id)
            if snapshot.system_model_hash != current_hash:
                if snapshot.status is not GraphSnapshotStatus.STALE:
                    repositories.attack_graph_snapshots.update(
                        snapshot.model_copy(update={"status": GraphSnapshotStatus.STALE})
                    )
                if not allow_stale:
                    raise AttackGraphError(
                        GraphErrorCode.MODEL_STALE,
                        "graph system-model hash differs from the current projection",
                    )
            elif snapshot.status is GraphSnapshotStatus.STALE and not allow_stale:
                raise AttackGraphError(GraphErrorCode.MODEL_STALE, "graph is marked stale")
        if snapshot.system_model_hash != current_hash:
            raise AttackGraphError(
                GraphErrorCode.MODEL_STALE,
                "stale graph cannot be reconstructed from the current system model",
            )
        graph, _, _ = AttackGraphBuilder(
            self.database, max_nodes=self.max_nodes
        ).build(snapshot.research_session_id, persist=False)
        if graph.graph_hash != snapshot.graph_hash:
            raise AttackGraphError(
                GraphErrorCode.MODEL_STALE,
                "stored graph hash differs from deterministic reconstruction",
            )
        return graph.model_copy(update={"graph_id": snapshot.id})

    def snapshot(self, graph_id: UUID) -> AttackGraphSnapshot:
        with self.database.session_factory() as session:
            snapshot = RepositorySet(session).attack_graph_snapshots.get(graph_id)
        if snapshot is None:
            raise AttackGraphError(GraphErrorCode.MODEL_NOT_FOUND, "graph does not exist")
        return snapshot

    def neighbors(self, graph_id: UUID, node_id: str) -> list[dict[str, Any]]:
        graph = self.load(graph_id)
        self._require_node(graph, node_id)
        return [
            {
                "node_id": edge.target_node_id,
                "edge_id": edge.edge_id,
                "edge_type": edge.edge_type.value,
                "disposition": edge.disposition.value,
            }
            for edge in self._outgoing(graph).get(node_id, [])
        ]

    def blocking_edges(self, graph_id: UUID, source_node_id: str) -> list[GraphEdge]:
        graph = self.load(graph_id)
        self._require_node(graph, source_node_id)
        return [
            edge
            for edge in self._outgoing(graph).get(source_node_id, [])
            if edge.disposition is EdgeDisposition.BLOCKING
        ]

    def reachable_from(self, graph_id: UUID, source_node_id: str) -> list[str]:
        graph = self.load(graph_id)
        self._require_node(graph, source_node_id)
        adjacency = self._traversable(graph)
        visited = {source_node_id}
        queue = deque([source_node_id])
        while queue:
            current = queue.popleft()
            for edge in adjacency.get(current, []):
                if edge.target_node_id not in visited:
                    visited.add(edge.target_node_id)
                    queue.append(edge.target_node_id)
        return sorted(visited - {source_node_id})

    def shortest_path(
        self, graph_id: UUID, source_node_id: str, target_node_id: str
    ) -> AttackPath | None:
        graph = self.load(graph_id)
        self._require_node(graph, source_node_id)
        self._require_node(graph, target_node_id)
        if source_node_id == target_node_id:
            return self._path(graph, [source_node_id], [])
        adjacency = self._traversable(graph)
        queue: deque[tuple[str, list[str], list[GraphEdge]]] = deque(
            [(source_node_id, [source_node_id], [])]
        )
        visited = {source_node_id}
        while queue:
            current, nodes, edges = queue.popleft()
            if len(edges) >= self.max_depth:
                continue
            for edge in adjacency.get(current, []):
                target = edge.target_node_id
                if target in visited:
                    continue
                next_nodes = [*nodes, target]
                next_edges = [*edges, edge]
                if target == target_node_id:
                    return self._path(graph, next_nodes, next_edges)
                visited.add(target)
                queue.append((target, next_nodes, next_edges))
        return None

    def paths(
        self,
        graph_id: UUID,
        source_node_id: str,
        target_node_id: str,
        *,
        max_depth: int | None = None,
        max_paths: int | None = None,
    ) -> PathQueryResult:
        graph = self.load(graph_id)
        self._require_node(graph, source_node_id)
        self._require_node(graph, target_node_id)
        depth_limit = min(max_depth or self.max_depth, self.max_depth)
        path_limit = min(max_paths or self.max_paths, self.max_paths)
        adjacency = self._traversable(graph)
        results: list[AttackPath] = []
        truncated = False

        def visit(current: str, nodes: list[str], edges: list[GraphEdge]) -> None:
            nonlocal truncated
            if len(results) >= path_limit:
                truncated = True
                return
            if current == target_node_id:
                results.append(self._path(graph, nodes, edges))
                return
            if len(edges) >= depth_limit:
                return
            for edge in adjacency.get(current, []):
                if edge.target_node_id in nodes:
                    continue
                visit(
                    edge.target_node_id,
                    [*nodes, edge.target_node_id],
                    [*edges, edge],
                )
                if truncated:
                    return

        visit(source_node_id, [source_node_id], [])
        results.sort(key=lambda item: (item.hop_count, item.node_ids, item.edge_ids))
        return PathQueryResult(
            paths=results,
            truncated=truncated,
            reason="MAX_PATHS_REACHED" if truncated else None,
        )

    def candidate_signals(self, graph_id: UUID, signal_type: str | None = None) -> list[Any]:
        self.load(graph_id)
        with self.database.session_factory() as session:
            signals = RepositorySet(session).candidate_signals.list_by_graph(graph_id)
        if signal_type:
            signals = [item for item in signals if item.signal_type.value == signal_type]
        return signals

    def accessible_resources(self, graph_id: UUID, identity_node_id: str) -> list[str]:
        graph = self.load(graph_id)
        reachable = set(self.reachable_from(graph_id, identity_node_id))
        return sorted(
            node.node_id
            for node in graph.nodes
            if node.node_type is SystemEntityType.DATA_OBJECT and node.node_id in reachable
        )

    def cross_identity_access(self, graph_id: UUID) -> list[Any]:
        return self.candidate_signals(
            graph_id, CandidateSignalType.CROSS_IDENTITY_RESOURCE_ACCESS.value
        )

    def role_access_differences(self, graph_id: UUID) -> list[Any]:
        return self.candidate_signals(
            graph_id, CandidateSignalType.ROLE_ACCESS_DIFFERENCE.value
        )

    def export(self, graph_id: UUID) -> dict[str, Any]:
        graph = self.load(graph_id)
        signals = self.candidate_signals(graph_id)
        return {
            "graph_version": graph.graph_version,
            "graph_id": str(graph.graph_id),
            "research_session_id": str(graph.research_session_id),
            "system_model_hash": graph.system_model_hash,
            "graph_hash": graph.graph_hash,
            "truncated": graph.truncated,
            "nodes": [node.model_dump(mode="json") for node in graph.nodes],
            "edges": [edge.model_dump(mode="json") for edge in graph.edges],
            "paths": [],
            "candidate_signals": [item.model_dump(mode="json") for item in signals],
        }

    @staticmethod
    def _require_node(graph: AttackGraph, node_id: str) -> None:
        if all(node.node_id != node_id for node in graph.nodes):
            raise AttackGraphError(GraphErrorCode.NODE_NOT_FOUND, f"node not found: {node_id}")

    @staticmethod
    def _outgoing(graph: AttackGraph) -> dict[str, list[GraphEdge]]:
        result: dict[str, list[GraphEdge]] = {}
        for edge in graph.edges:
            result.setdefault(edge.source_node_id, []).append(edge)
        for edges in result.values():
            edges.sort(key=lambda edge: (edge.target_node_id, edge.edge_type.value, edge.edge_id))
        return result

    @classmethod
    def _traversable(cls, graph: AttackGraph) -> dict[str, list[GraphEdge]]:
        return {
            source: [
                edge
                for edge in edges
                if edge.disposition is EdgeDisposition.TRAVERSABLE
                and (
                    graph.mode is GraphMode.ALLOW_INFERRED
                    or edge.classification is FactClassification.OBSERVED
                )
            ]
            for source, edges in cls._outgoing(graph).items()
        }

    @staticmethod
    def _path(
        graph: AttackGraph, node_ids: list[str], edges: list[GraphEdge]
    ) -> AttackPath:
        nodes = {node.node_id: node for node in graph.nodes}
        target_type = nodes[node_ids[-1]].node_type
        path_type = {
            SystemEntityType.DATA_OBJECT: PathType.RESOURCE_PATH,
            SystemEntityType.ROLE: PathType.ROLE_PATH,
        }.get(target_type, PathType.ACCESS_PATH)
        semantic = json.dumps(
            {"graph": graph.graph_hash, "nodes": node_ids, "edges": [e.edge_id for e in edges]},
            sort_keys=True,
            separators=(",", ":"),
        )
        relation_ids = _union_ids(edge.system_relationship_ids for edge in edges)
        observation_ids = _union_ids(edge.observation_ids for edge in edges)
        evidence_ids = _union_ids(edge.evidence_ids for edge in edges)
        confidence = min((edge.confidence for edge in edges), default=1.0)
        explanation = "; ".join(
            f"{edge.source_node_id} --{edge.edge_type.value}--> {edge.target_node_id}"
            for edge in edges
        ) or f"{node_ids[0]} is the queried node"
        return AttackPath(
            id=hashlib.sha256(semantic.encode()).hexdigest(),
            graph_id=graph.graph_id,
            path_type=path_type,
            source_node_id=node_ids[0],
            target_node_id=node_ids[-1],
            node_ids=node_ids,
            edge_ids=[edge.edge_id for edge in edges],
            hop_count=len(edges),
            confidence=confidence,
            contains_inferred_edges=any(
                edge.classification is FactClassification.INFERRED for edge in edges
            ),
            system_relationship_ids=relation_ids,
            observation_ids=observation_ids,
            evidence_ids=evidence_ids,
            explanation=explanation,
        )


def _union_ids(groups: Any) -> list[UUID]:
    return sorted({value for group in groups for value in group}, key=str)
