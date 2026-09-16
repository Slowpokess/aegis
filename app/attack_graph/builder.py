import hashlib
import json
import logging
from collections import defaultdict
from typing import Any
from uuid import UUID

from app.attack_graph.errors import AttackGraphError
from app.domain.attack_graph import (
    ATTACK_GRAPH_VERSION,
    AttackGraph,
    AttackGraphSnapshot,
    CandidateSignal,
    CandidateSignalType,
    EdgeDisposition,
    GraphEdge,
    GraphEdgeType,
    GraphErrorCode,
    GraphMode,
    GraphNode,
)
from app.domain.common import FactClassification, Provenance
from app.domain.system_model import RelationshipType, SystemEntityType
from app.storage.database import Database
from app.storage.repositories import RepositorySet
from app.system_model.serialization import model_sha256

logger = logging.getLogger("attack_graph")

_ENTITY_REPOSITORIES = {
    SystemEntityType.ASSET: "system_assets",
    SystemEntityType.SERVICE: "system_services",
    SystemEntityType.ENDPOINT: "system_endpoints",
    SystemEntityType.IDENTITY: "system_identities",
    SystemEntityType.ROLE: "system_roles",
    SystemEntityType.PERMISSION: "system_permissions",
    SystemEntityType.CAPABILITY: "system_capabilities",
    SystemEntityType.DATA_OBJECT: "system_data_objects",
    SystemEntityType.TRUST_BOUNDARY: "system_trust_boundaries",
}

_DISPOSITIONS = {
    RelationshipType.HOSTS: EdgeDisposition.TRAVERSABLE,
    RelationshipType.EXPOSES: EdgeDisposition.TRAVERSABLE,
    RelationshipType.CAN_ACCESS: EdgeDisposition.TRAVERSABLE,
    RelationshipType.RETURNS: EdgeDisposition.TRAVERSABLE,
    RelationshipType.CONTAINS: EdgeDisposition.TRAVERSABLE,
    RelationshipType.CROSSES_BOUNDARY: EdgeDisposition.TRAVERSABLE,
    RelationshipType.RESOLVES_TO: EdgeDisposition.INFORMATIONAL,
    RelationshipType.CANNOT_ACCESS: EdgeDisposition.BLOCKING,
    RelationshipType.CALLS: EdgeDisposition.INFORMATIONAL,
    RelationshipType.AUTHENTICATES_AS: EdgeDisposition.INFORMATIONAL,
    RelationshipType.HAS_ROLE: EdgeDisposition.INFORMATIONAL,
    RelationshipType.OWNS: EdgeDisposition.INFORMATIONAL,
    RelationshipType.READS: EdgeDisposition.INFORMATIONAL,
    RelationshipType.TRUSTS: EdgeDisposition.INFORMATIONAL,
}


class AttackGraphBuilder:
    def __init__(self, database: Database, *, max_nodes: int = 10_000) -> None:
        if max_nodes < 1:
            raise ValueError("max_nodes must be positive")
        self.database = database
        self.max_nodes = max_nodes

    def build(
        self,
        research_session_id: UUID,
        *,
        mode: GraphMode = GraphMode.OBSERVED_ONLY,
        persist: bool = True,
    ) -> tuple[AttackGraph, AttackGraphSnapshot, list[CandidateSignal]]:
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            if repositories.research_sessions.get(research_session_id) is None:
                raise AttackGraphError(
                    GraphErrorCode.MODEL_NOT_FOUND, "research session does not exist"
                )
            entities = self._load_entities(repositories, research_session_id)
            if not any(entities.values()):
                raise AttackGraphError(
                    GraphErrorCode.MODEL_NOT_FOUND, "system model contains no entities"
                )
            current_model_hash = model_sha256(repositories, research_session_id)
            nodes, truncated = self._project_nodes(entities, mode)
            node_by_entity = {
                (node.node_type, node.system_entity_id): node for node in nodes
            }
            relationships = repositories.system_relationships.list_by_session(
                research_session_id
            )
            edges = self._project_relationships(
                repositories,
                research_session_id,
                relationships,
                node_by_entity,
                mode,
            )
            edges.extend(self._project_capabilities(entities, node_by_entity, mode))
            edges.sort(key=lambda edge: (edge.source_node_id, edge.edge_type.value, edge.target_node_id))
            graph_hash = _graph_sha256(current_model_hash, nodes, edges)
            latest_builds = repositories.system_model_builds.list_by_session(
                research_session_id
            )
            snapshot = AttackGraphSnapshot(
                research_session_id=research_session_id,
                system_model_build_id=latest_builds[-1].id if latest_builds else None,
                system_model_hash=current_model_hash,
                graph_hash=graph_hash,
                node_count=len(nodes),
                edge_count=len(edges),
                traversable_edge_count=sum(
                    edge.disposition is EdgeDisposition.TRAVERSABLE for edge in edges
                ),
                blocking_edge_count=sum(
                    edge.disposition is EdgeDisposition.BLOCKING for edge in edges
                ),
                truncated=truncated,
                truncation_reason="MAX_NODES_REACHED" if truncated else None,
                provenance=_provenance(current_model_hash),
            )
            graph = AttackGraph(
                graph_id=snapshot.id,
                research_session_id=research_session_id,
                system_model_hash=current_model_hash,
                graph_hash=graph_hash,
                mode=mode,
                nodes=nodes,
                edges=edges,
                truncated=truncated,
                truncation_reason=snapshot.truncation_reason,
            )
            signals = self._candidate_signals(
                graph, relationships, entities, snapshot.id
            )
            if persist:
                repositories.attack_graph_snapshots.mark_stale_except(
                    research_session_id, current_model_hash
                )
                repositories.attack_graph_snapshots.add(snapshot)
                for signal in signals:
                    repositories.candidate_signals.add(signal)
        logger.info(
            "graph=%s session=%s model=%s graph_hash=%s nodes=%d edges=%d signals=%d truncated=%s",
            snapshot.id,
            research_session_id,
            current_model_hash,
            graph_hash,
            len(nodes),
            len(edges),
            len(signals),
            truncated,
        )
        return graph, snapshot, signals

    @staticmethod
    def _load_entities(
        repositories: RepositorySet, research_session_id: UUID
    ) -> dict[SystemEntityType, list[Any]]:
        return {
            entity_type: getattr(repositories, name).list_by_session(research_session_id)
            for entity_type, name in _ENTITY_REPOSITORIES.items()
        }

    def _project_nodes(
        self, entities: dict[SystemEntityType, list[Any]], mode: GraphMode
    ) -> tuple[list[GraphNode], bool]:
        nodes = [
            GraphNode(
                node_id=item.canonical_identifier,
                node_type=entity_type,
                system_entity_id=item.id,
                canonical_identifier=item.canonical_identifier,
                classification=item.classification,
                confidence=item.confidence,
                observation_ids=_sorted_ids(item.observation_ids),
                evidence_ids=_sorted_ids(item.evidence_ids),
            )
            for entity_type, items in entities.items()
            for item in items
            if mode is GraphMode.ALLOW_INFERRED
            or item.classification is FactClassification.OBSERVED
        ]
        nodes.sort(key=lambda item: (item.node_id, item.node_type.value))
        truncated = len(nodes) > self.max_nodes
        return nodes[: self.max_nodes], truncated

    def _project_relationships(
        self,
        repositories: RepositorySet,
        research_session_id: UUID,
        relationships: list[Any],
        node_by_entity: dict[tuple[SystemEntityType, UUID], GraphNode],
        mode: GraphMode,
    ) -> list[GraphEdge]:
        edges: list[GraphEdge] = []
        for relation in relationships:
            if (
                mode is GraphMode.OBSERVED_ONLY
                and relation.classification is not FactClassification.OBSERVED
            ):
                continue
            source = node_by_entity.get(
                (relation.source_entity_type, relation.source_entity_id)
            )
            target = node_by_entity.get(
                (relation.target_entity_type, relation.target_entity_id)
            )
            if source is None or target is None:
                if len(node_by_entity) >= self.max_nodes:
                    continue
                raise AttackGraphError(
                    GraphErrorCode.INVALID_RELATIONSHIP,
                    "system relationship references an unprojected entity",
                )
            self._validate_lineage(repositories, research_session_id, relation)
            edges.append(
                _edge(
                    source.node_id,
                    target.node_id,
                    GraphEdgeType(relation.relationship_type.value),
                    _DISPOSITIONS[relation.relationship_type],
                    relation.classification,
                    relation.confidence,
                    [relation.id],
                    [],
                    relation.observation_ids,
                    relation.evidence_ids,
                )
            )
        return edges

    @staticmethod
    def _validate_lineage(
        repositories: RepositorySet, research_session_id: UUID, relation: Any
    ) -> None:
        if relation.research_session_id != research_session_id:
            raise AttackGraphError(
                GraphErrorCode.CROSS_SESSION_REFERENCE,
                "relationship belongs to another research session",
            )
        if relation.classification is not FactClassification.OBSERVED:
            return
        if not relation.observation_ids or not relation.evidence_ids:
            raise AttackGraphError(
                GraphErrorCode.PROVENANCE_INVALID,
                "observed relationship has no evidence lineage",
            )
        evidence_ids = set(relation.evidence_ids)
        for observation_id in relation.observation_ids:
            observation = repositories.observations.get(observation_id)
            if observation is None or observation.research_session_id != research_session_id:
                raise AttackGraphError(
                    GraphErrorCode.PROVENANCE_INVALID,
                    "relationship references invalid observation lineage",
                )
            if not {observation.evidence_id, observation.tool_artifact_id} & evidence_ids:
                raise AttackGraphError(
                    GraphErrorCode.PROVENANCE_INVALID,
                    "relationship observation/evidence linkage is inconsistent",
                )
        for evidence_id in evidence_ids:
            evidence = repositories.evidence.get(evidence_id)
            artifact = repositories.tool_artifacts.get(evidence_id)
            evidence_session = evidence.research_session_id if evidence else None
            artifact_session = artifact.research_session_id if artifact else None
            if (
                evidence_session != research_session_id
                and artifact_session != research_session_id
            ):
                raise AttackGraphError(
                    GraphErrorCode.PROVENANCE_INVALID,
                    "relationship references invalid evidence lineage",
                )

    @staticmethod
    def _project_capabilities(
        entities: dict[SystemEntityType, list[Any]],
        node_by_entity: dict[tuple[SystemEntityType, UUID], GraphNode],
        mode: GraphMode,
    ) -> list[GraphEdge]:
        edges: list[GraphEdge] = []
        for capability in entities[SystemEntityType.CAPABILITY]:
            if (
                mode is GraphMode.OBSERVED_ONLY
                and capability.classification is not FactClassification.OBSERVED
            ):
                continue
            subject = node_by_entity.get(
                (capability.subject_entity_type, capability.subject_entity_id)
            )
            capability_node = node_by_entity.get(
                (SystemEntityType.CAPABILITY, capability.id)
            )
            resource = node_by_entity.get(
                (capability.resource_entity_type, capability.resource_entity_id)
            )
            if not subject or not capability_node or not resource:
                continue
            common = (
                capability.classification,
                capability.confidence,
                [],
                [capability.id],
                capability.observation_ids,
                capability.evidence_ids,
            )
            edges.append(
                _edge(
                    subject.node_id,
                    capability_node.node_id,
                    GraphEdgeType.HAS_CAPABILITY,
                    EdgeDisposition.TRAVERSABLE,
                    *common,
                )
            )
            edges.append(
                _edge(
                    capability_node.node_id,
                    resource.node_id,
                    GraphEdgeType.APPLIES_TO,
                    EdgeDisposition.TRAVERSABLE,
                    *common,
                )
            )
        return edges

    @staticmethod
    def _candidate_signals(
        graph: AttackGraph,
        relationships: list[Any],
        entities: dict[SystemEntityType, list[Any]],
        graph_id: UUID,
    ) -> list[CandidateSignal]:
        identity_by_id = {
            item.id: item for item in entities[SystemEntityType.IDENTITY]
        }
        role_by_id = {item.id: item for item in entities[SystemEntityType.ROLE]}
        endpoint_by_id = {
            item.id: item for item in entities[SystemEntityType.ENDPOINT]
        }
        data_by_id = {
            item.id: item for item in entities[SystemEntityType.DATA_OBJECT]
        }
        by_type: dict[RelationshipType, list[Any]] = defaultdict(list)
        for relation in relationships:
            by_type[relation.relationship_type].append(relation)
        signals: list[CandidateSignal] = []
        returns_by_endpoint = {
            item.source_entity_id: item for item in by_type[RelationshipType.RETURNS]
        }
        owners_by_resource: dict[UUID, list[Any]] = defaultdict(list)
        for item in by_type[RelationshipType.OWNS]:
            owners_by_resource[item.target_entity_id].append(item)
        for access in by_type[RelationshipType.CAN_ACCESS]:
            returned = returns_by_endpoint.get(access.target_entity_id)
            if returned is None:
                continue
            for ownership in owners_by_resource[returned.target_entity_id]:
                if access.source_entity_id == ownership.source_entity_id:
                    continue
                accessor = identity_by_id.get(access.source_entity_id)
                owner = identity_by_id.get(ownership.source_entity_id)
                endpoint = endpoint_by_id.get(access.target_entity_id)
                resource = data_by_id.get(returned.target_entity_id)
                if not accessor or not owner or not endpoint or not resource:
                    continue
                relations = [access, returned, ownership]
                signals.append(
                    CandidateSignal(
                        graph_id=graph_id,
                        research_session_id=graph.research_session_id,
                        signal_type=CandidateSignalType.CROSS_IDENTITY_RESOURCE_ACCESS,
                        semantic_key=(
                            f"cross-identity:{accessor.canonical_identifier}:"
                            f"{owner.canonical_identifier}:{resource.canonical_identifier}:"
                            f"{endpoint.canonical_identifier}"
                        ),
                        subject_entity_id=accessor.id,
                        target_entity_id=owner.id,
                        resource_entity_id=resource.id,
                        endpoint_entity_id=endpoint.id,
                        confidence=min(item.confidence for item in relations),
                        classification=FactClassification.OBSERVED,
                        system_relationship_ids=_sorted_ids(
                            [item.id for item in relations]
                        ),
                        observation_ids=_union_ids(
                            item.observation_ids for item in relations
                        ),
                        evidence_ids=_union_ids(item.evidence_ids for item in relations),
                        details={
                            "accessor": accessor.canonical_identifier,
                            "owner": owner.canonical_identifier,
                            "resource": resource.canonical_identifier,
                            "endpoint": endpoint.canonical_identifier,
                            "label": "candidate connectivity signal; not a finding",
                        },
                        provenance=_provenance(graph.graph_hash),
                    )
                )
        access_by_endpoint: dict[UUID, list[Any]] = defaultdict(list)
        for relation_type in (
            RelationshipType.CAN_ACCESS,
            RelationshipType.CANNOT_ACCESS,
        ):
            for item in by_type[relation_type]:
                access_by_endpoint[item.target_entity_id].append(item)
        for endpoint_id, access_items in access_by_endpoint.items():
            ordered = sorted(access_items, key=lambda item: str(item.source_entity_id))
            for index, first in enumerate(ordered):
                for second in ordered[index + 1 :]:
                    if first.relationship_type is second.relationship_type:
                        continue
                    first_identity = identity_by_id.get(first.source_entity_id)
                    second_identity = identity_by_id.get(second.source_entity_id)
                    if (
                        not first_identity
                        or not second_identity
                        or not first_identity.role_id
                        or not second_identity.role_id
                        or first_identity.role_id == second_identity.role_id
                    ):
                        continue
                    endpoint = endpoint_by_id.get(endpoint_id)
                    if endpoint is None:
                        continue
                    role_a = role_by_id[first_identity.role_id]
                    role_b = role_by_id[second_identity.role_id]
                    pair = sorted(
                        [(first_identity, role_a, first), (second_identity, role_b, second)],
                        key=lambda value: value[0].canonical_identifier,
                    )
                    identity_a, selected_role_a, relation_a = pair[0]
                    identity_b, selected_role_b, relation_b = pair[1]
                    signals.append(
                        CandidateSignal(
                            graph_id=graph_id,
                            research_session_id=graph.research_session_id,
                            signal_type=CandidateSignalType.ROLE_ACCESS_DIFFERENCE,
                            semantic_key=(
                                f"role-diff:{endpoint.canonical_identifier}:"
                                f"{identity_a.canonical_identifier}:"
                                f"{identity_b.canonical_identifier}"
                            ),
                            subject_entity_id=identity_a.id,
                            target_entity_id=identity_b.id,
                            endpoint_entity_id=endpoint.id,
                            confidence=min(relation_a.confidence, relation_b.confidence),
                            classification=FactClassification.OBSERVED,
                            system_relationship_ids=_sorted_ids(
                                [relation_a.id, relation_b.id]
                            ),
                            observation_ids=_union_ids(
                                [relation_a.observation_ids, relation_b.observation_ids]
                            ),
                            evidence_ids=_union_ids(
                                [relation_a.evidence_ids, relation_b.evidence_ids]
                            ),
                            details={
                                "endpoint": endpoint.canonical_identifier,
                                "identity_a": identity_a.canonical_identifier,
                                "role_a": selected_role_a.canonical_identifier,
                                "result_a": relation_a.relationship_type.value,
                                "identity_b": identity_b.canonical_identifier,
                                "role_b": selected_role_b.canonical_identifier,
                                "result_b": relation_b.relationship_type.value,
                                "label": "observed role access difference; not privilege escalation",
                            },
                            provenance=_provenance(graph.graph_hash),
                        )
                    )
        unique = {signal.semantic_key: signal for signal in signals}
        return [unique[key] for key in sorted(unique)]


def _edge(
    source: str,
    target: str,
    edge_type: GraphEdgeType,
    disposition: EdgeDisposition,
    classification: FactClassification,
    confidence: float,
    relationship_ids: list[UUID],
    entity_ids: list[UUID],
    observation_ids: list[UUID],
    evidence_ids: list[UUID],
) -> GraphEdge:
    semantic = f"{source}\0{edge_type.value}\0{target}\0{classification.value}"
    return GraphEdge(
        edge_id=hashlib.sha256(semantic.encode()).hexdigest(),
        source_node_id=source,
        target_node_id=target,
        edge_type=edge_type,
        disposition=disposition,
        classification=classification,
        confidence=confidence,
        system_relationship_ids=_sorted_ids(relationship_ids),
        system_entity_ids=_sorted_ids(entity_ids),
        observation_ids=_sorted_ids(observation_ids),
        evidence_ids=_sorted_ids(evidence_ids),
    )


def _graph_sha256(
    model_hash: str, nodes: list[GraphNode], edges: list[GraphEdge]
) -> str:
    payload = {
        "graph_version": ATTACK_GRAPH_VERSION,
        "system_model_hash": model_hash,
        "nodes": [
            {
                "id": node.node_id,
                "type": node.node_type.value,
                "classification": node.classification.value,
                "confidence": node.confidence,
            }
            for node in nodes
        ],
        "edges": [
            {
                "source": edge.source_node_id,
                "target": edge.target_node_id,
                "type": edge.edge_type.value,
                "disposition": edge.disposition.value,
                "classification": edge.classification.value,
                "confidence": edge.confidence,
            }
            for edge in edges
        ],
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _sorted_ids(values: list[UUID]) -> list[UUID]:
    return sorted(set(values), key=str)


def _union_ids(groups: Any) -> list[UUID]:
    return _sorted_ids([value for group in groups for value in group])


def _provenance(reference: str) -> Provenance:
    return Provenance(
        source_type="system_model",
        source_reference=reference,
        collector="attack-graph-v1",
        classification=FactClassification.OBSERVED,
    )
