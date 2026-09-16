import json
from uuid import UUID

from app.domain.attack_graph import GraphSnapshotStatus
from app.domain.observations import ObservationSource
from app.domain.research_planner import (
    ContextTrust,
    ResearchContext,
    ResearchContextItem,
)
from app.storage.database import Database
from app.storage.repositories import RepositorySet
from app.system_model.serialization import model_sha256

_ENTITY_REPOSITORIES = (
    ("asset", "system_assets"),
    ("service", "system_services"),
    ("endpoint", "system_endpoints"),
    ("identity", "system_identities"),
    ("role", "system_roles"),
    ("data_object", "system_data_objects"),
    ("relationship", "system_relationships"),
)


def _bounded_data(value: object, max_chars: int = 1000) -> dict[str, object]:
    if not isinstance(value, dict):
        return {"value": str(value)[:max_chars]}
    output: dict[str, object] = {}
    for key in sorted(value):
        item = value[key]
        if isinstance(item, str):
            output[str(key)] = item[:max_chars]
        elif isinstance(item, (int, float, bool)) or item is None:
            output[str(key)] = item
        elif isinstance(item, (list, tuple)):
            output[str(key)] = [str(part)[:max_chars] for part in item[:20]]
        else:
            output[str(key)] = str(item)[:max_chars]
    return output


class ResearchContextBuilder:
    def __init__(
        self,
        database: Database,
        *,
        max_context_bytes: int = 50_000,
        max_entities: int = 100,
        max_signals: int = 50,
        max_history: int = 25,
    ) -> None:
        self.database = database
        self.max_context_bytes = max_context_bytes
        self.max_entities = max_entities
        self.max_signals = max_signals
        self.max_history = max_history

    def build(self, research_session_id: UUID) -> ResearchContext:
        with self.database.session_factory() as session:
            repositories = RepositorySet(session)
            research = repositories.research_sessions.get(research_session_id)
            if research is None:
                raise ValueError("research session does not exist")
            entities: list[ResearchContextItem] = []
            for kind, repository_name in _ENTITY_REPOSITORIES:
                repository = getattr(repositories, repository_name)
                for entity in repository.list_by_session(research_session_id):
                    entities.append(
                        ResearchContextItem(
                            kind=kind,
                            entity_id=entity.id,
                            semantic_id=entity.canonical_identifier,
                            trust=ContextTrust.DERIVED_TRUSTED,
                            data={"classification": entity.classification.value},
                        )
                    )
            web_resources = repositories.web_resources.list_by_session(research_session_id)
            web_resource_keys = {item.id: item.canonical_key for item in web_resources}
            for resource in web_resources:
                entities.append(
                    ResearchContextItem(
                        kind="web_resource",
                        entity_id=resource.id,
                        semantic_id=resource.canonical_key,
                        trust=ContextTrust.DERIVED_TRUSTED,
                        data={
                            "method": resource.method,
                            "path": resource.path,
                            "resource_type": resource.resource_type.value,
                            "classification": resource.classification.value,
                        },
                    )
                )
            for template in repositories.http_request_templates.list_by_session(
                research_session_id
            ):
                entities.append(
                    ResearchContextItem(
                        kind="http_request_template",
                        entity_id=template.id,
                        semantic_id=f"request-template:{template.semantic_key}",
                        trust=ContextTrust.DERIVED_TRUSTED,
                        data={
                            "method": template.method,
                            "resource": web_resource_keys.get(template.web_resource_id, "unknown"),
                            "parameter_names": [item.name for item in template.parameters],
                            "parameter_locations": [
                                item.location.value for item in template.parameters
                            ],
                            "logical_identity_reference": template.logical_identity_reference,
                        },
                    )
                )
            for candidate in repositories.web_template_candidates.list_by_session(
                research_session_id
            ):
                entities.append(
                    ResearchContextItem(
                        kind="web_template_candidate",
                        entity_id=candidate.id,
                        semantic_id=f"web-template-candidate:{candidate.semantic_key}",
                        trust=ContextTrust.DERIVED_TRUSTED,
                        data={
                            "template_id": candidate.template_id,
                            "resource": web_resource_keys.get(candidate.web_resource_id, "unknown"),
                            "classification": candidate.classification.value,
                            "tool_reported_severity": (
                                candidate.tool_reported_severity.value
                                if candidate.tool_reported_severity
                                else None
                            ),
                        },
                    )
                )
            snapshots = repositories.web_surface_snapshots.list_by_session(research_session_id)
            if snapshots:
                web_snapshot = snapshots[-1]
                entities.append(
                    ResearchContextItem(
                        kind="web_surface_summary",
                        entity_id=web_snapshot.id,
                        semantic_id=f"web-surface:{web_snapshot.web_surface_sha256}",
                        trust=ContextTrust.DERIVED_TRUSTED,
                        data={
                            "version": web_snapshot.web_surface_version,
                            "resources": web_snapshot.resource_count,
                            "parameters": web_snapshot.parameter_count,
                            "request_templates": web_snapshot.request_template_count,
                            "candidates": web_snapshot.candidate_count,
                            "source_observations": web_snapshot.source_observation_count,
                        },
                    )
                )
            entities.sort(key=lambda item: (item.kind, item.semantic_id))
            graph_snapshots = repositories.attack_graph_snapshots.list_by_session(
                research_session_id
            )
            current = next(
                (
                    item
                    for item in reversed(graph_snapshots)
                    if item.status is GraphSnapshotStatus.CURRENT
                ),
                None,
            )
            signals = repositories.candidate_signals.list_by_graph(current.id) if current else []
            signal_items = tuple(
                ResearchContextItem(
                    kind="candidate_signal",
                    entity_id=signal.id,
                    semantic_id=signal.semantic_key,
                    trust=ContextTrust.DERIVED_TRUSTED,
                    data={"signal_type": signal.signal_type.value},
                )
                for signal in signals[: self.max_signals]
            )
            observations = repositories.observations.list_by_session(research_session_id)
            web_source_types = {
                "burp_http_exchange",
                "web_content_discovery",
                "web_template_match",
            }
            observation_items = tuple(
                ResearchContextItem(
                    kind="observation",
                    entity_id=observation.id,
                    semantic_id=f"observation:{observation.id}",
                    trust=(
                        ContextTrust.UNTRUSTED_TOOL_DATA
                        if observation.source is ObservationSource.TOOL
                        else ContextTrust.UNTRUSTED_TARGET_DATA
                    ),
                    data=_bounded_data(observation.normalized_data or observation.raw_data),
                )
                for observation in observations[-self.max_entities :]
                if observation.normalized_data.get("source_type") not in web_source_types
            )
            history = repositories.research_intents.list_by_session(research_session_id)
            history_values = [
                ResearchContextItem(
                    kind="research_intent",
                    entity_id=intent.id,
                    semantic_id=intent.semantic_key,
                    trust=ContextTrust.SYSTEM,
                    data={
                        "intent_type": intent.intent_type.value,
                        "status": intent.status.value,
                        "satisfaction": (
                            intent.satisfaction.value if intent.satisfaction else None
                        ),
                    },
                )
                for intent in history[-self.max_history :]
            ]
            plans = repositories.discovery_plans.list_by_session(research_session_id)
            history_values.extend(
                ResearchContextItem(
                    kind="discovery_plan",
                    entity_id=plan.id,
                    semantic_id=f"discovery:{plan.profile.value}:{','.join(item.value for item in plan.requested_capabilities)}",
                    trust=ContextTrust.SYSTEM,
                    data={"status": plan.status.value},
                )
                for plan in plans[-self.max_history :]
            )
            history_items = tuple(history_values[-self.max_history :])
            hypotheses = repositories.hypotheses.list_by_session(research_session_id)
            findings = repositories.findings.list_by_session(research_session_id)
            research_records = tuple(
                [
                    ResearchContextItem(
                        kind="hypothesis",
                        entity_id=item.id,
                        semantic_id=f"hypothesis:{item.id}",
                        trust=ContextTrust.DERIVED_TRUSTED,
                        data={"status": item.status.value},
                    )
                    for item in hypotheses[-self.max_history :]
                ]
                + [
                    ResearchContextItem(
                        kind="finding",
                        entity_id=item.id,
                        semantic_id=f"finding:{item.id}",
                        trust=ContextTrust.SYSTEM,
                        data={"verification_status": item.verification_status.value},
                    )
                    for item in findings[-self.max_history :]
                ]
            )[-self.max_history :]
            context = ResearchContext(
                session_id=research.id,
                target_asset_id=research.target.asset_id,
                scope={
                    "hosts": research.scope.hosts,
                    "ports": research.scope.ports,
                    "schemes": research.scope.schemes,
                },
                system_model_hash=model_sha256(repositories, research_session_id),
                attack_graph_id=current.id if current else None,
                attack_graph_hash=current.graph_hash if current else None,
                entities=tuple(entities[: self.max_entities]),
                candidate_signals=signal_items,
                observations=observation_items,
                history=history_items,
                research_records=research_records,
            )
        return self._fit(context)

    def _fit(self, context: ResearchContext) -> ResearchContext:
        limitations = list(context.limitations)
        candidate = context
        while len(candidate.canonical_bytes()) > self.max_context_bytes:
            if candidate.observations:
                candidate = candidate.model_copy(
                    update={"observations": candidate.observations[:-1]}
                )
            elif candidate.entities:
                candidate = candidate.model_copy(update={"entities": candidate.entities[:-1]})
            elif candidate.history:
                candidate = candidate.model_copy(update={"history": candidate.history[:-1]})
            elif candidate.candidate_signals:
                candidate = candidate.model_copy(
                    update={"candidate_signals": candidate.candidate_signals[:-1]}
                )
            elif candidate.research_records:
                candidate = candidate.model_copy(
                    update={"research_records": candidate.research_records[:-1]}
                )
            else:
                raise ValueError("planner context limit is too small for session scope")
            if "CONTEXT_TRUNCATED" not in limitations:
                limitations.append("CONTEXT_TRUNCATED")
            candidate = candidate.model_copy(update={"limitations": tuple(limitations)})
        json.loads(candidate.canonical_bytes())
        return candidate
