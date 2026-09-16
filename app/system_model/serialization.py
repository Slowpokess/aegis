import hashlib
import json
from typing import Any
from uuid import UUID

from app.domain.system_model import SYSTEM_MODEL_VERSION, SystemEntityType
from app.storage.repositories import RepositorySet


_COLLECTIONS = (
    ("assets", "system_assets"),
    ("services", "system_services"),
    ("endpoints", "system_endpoints"),
    ("identities", "system_identities"),
    ("roles", "system_roles"),
    ("permissions", "system_permissions"),
    ("capabilities", "system_capabilities"),
    ("data_objects", "system_data_objects"),
    ("trust_boundaries", "system_trust_boundaries"),
    ("relationships", "system_relationships"),
)


def export_model(repositories: RepositorySet, research_session_id: UUID) -> dict[str, Any]:
    output: dict[str, Any] = {
        "model_version": SYSTEM_MODEL_VERSION,
        "research_session_id": str(research_session_id),
    }
    for output_name, repository_name in _COLLECTIONS:
        repository = getattr(repositories, repository_name)
        output[output_name] = [
            item.model_dump(mode="json")
            for item in repository.list_by_session(research_session_id)
        ]
    output["model_sha256"] = model_sha256(repositories, research_session_id)
    return output


def model_sha256(repositories: RepositorySet, research_session_id: UUID) -> str:
    canonical_by_id: dict[tuple[str, str], str] = {}
    payload: dict[str, Any] = {"model_version": SYSTEM_MODEL_VERSION}
    for output_name, repository_name in _COLLECTIONS[:-1]:
        repository = getattr(repositories, repository_name)
        items = repository.list_by_session(research_session_id)
        entity_type = _entity_type_for_collection(output_name)
        for item in items:
            canonical_by_id[(entity_type.value, str(item.id))] = item.canonical_identifier
        payload[output_name] = [_canonical_fact(item) for item in items]
    relationships = repositories.system_relationships.list_by_session(research_session_id)
    payload["relationships"] = [
        {
            **_canonical_fact(item),
            "source": canonical_by_id[
                (item.source_entity_type.value, str(item.source_entity_id))
            ],
            "target": canonical_by_id[
                (item.target_entity_type.value, str(item.target_entity_id))
            ],
            "relationship_type": item.relationship_type.value,
        }
        for item in relationships
    ]
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _canonical_fact(item: Any) -> dict[str, Any]:
    dumped = item.model_dump(mode="json")
    excluded = {
        "id",
        "research_session_id",
        "provenance",
        "created_at",
        "updated_at",
        "first_seen",
        "last_seen",
        "parent_asset_id",
        "asset_id",
        "service_id",
        "role_id",
        "subject_entity_id",
        "resource_id",
        "resource_entity_id",
        "source_entity_id",
        "target_entity_id",
    }
    return {key: value for key, value in dumped.items() if key not in excluded}


def _entity_type_for_collection(name: str) -> SystemEntityType:
    return {
        "assets": SystemEntityType.ASSET,
        "services": SystemEntityType.SERVICE,
        "endpoints": SystemEntityType.ENDPOINT,
        "identities": SystemEntityType.IDENTITY,
        "roles": SystemEntityType.ROLE,
        "permissions": SystemEntityType.PERMISSION,
        "capabilities": SystemEntityType.CAPABILITY,
        "data_objects": SystemEntityType.DATA_OBJECT,
        "trust_boundaries": SystemEntityType.TRUST_BOUNDARY,
    }[name]
