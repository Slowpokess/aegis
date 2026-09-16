from typing import Any
from uuid import UUID

from app.domain.system_model import RelationshipType
from app.storage.database import Database
from app.storage.repositories import RepositorySet
from app.system_model.serialization import export_model


class SystemModelQueryService:
    def __init__(self, database: Database) -> None:
        self.database = database

    def summary(self, research_session_id: UUID) -> dict[str, Any]:
        with self.database.session_factory() as session:
            repositories = RepositorySet(session)
            result = export_model(repositories, research_session_id)
            builds = repositories.system_model_builds.list_by_session(research_session_id)
        return {
            "model_version": result["model_version"],
            "research_session_id": str(research_session_id),
            "assets": len(result["assets"]),
            "services": len(result["services"]),
            "endpoints": len(result["endpoints"]),
            "identities": len(result["identities"]),
            "roles": len(result["roles"]),
            "permissions": len(result["permissions"]),
            "capabilities": len(result["capabilities"]),
            "data_objects": len(result["data_objects"]),
            "trust_boundaries": len(result["trust_boundaries"]),
            "relationships": len(result["relationships"]),
            "builds": len(builds),
            "model_sha256": result["model_sha256"],
        }

    def export(self, research_session_id: UUID) -> dict[str, Any]:
        with self.database.session_factory() as session:
            return export_model(RepositorySet(session), research_session_id)

    def endpoint_access(self, research_session_id: UUID, path: str) -> list[dict[str, Any]]:
        with self.database.session_factory() as session:
            repositories = RepositorySet(session)
            endpoints = [
                item
                for item in repositories.system_endpoints.list_by_session(research_session_id)
                if item.path == path
            ]
            identities = {
                item.id: item
                for item in repositories.system_identities.list_by_session(research_session_id)
            }
            endpoint_ids = {item.id for item in endpoints}
            relationships = [
                item
                for item in repositories.system_relationships.list_by_session(
                    research_session_id
                )
                if item.target_entity_id in endpoint_ids
                and item.relationship_type
                in {RelationshipType.CAN_ACCESS, RelationshipType.CANNOT_ACCESS}
            ]
        return [
            {
                "identity": identities[item.source_entity_id].name,
                "relationship": item.relationship_type.value,
                "endpoint": path,
                "observation_ids": [str(value) for value in item.observation_ids],
                "evidence_ids": [str(value) for value in item.evidence_ids],
                "classification": item.classification.value,
            }
            for item in relationships
            if item.source_entity_id in identities
        ]

    def owners(self, research_session_id: UUID, resource_identifier: str) -> list[dict[str, Any]]:
        with self.database.session_factory() as session:
            repositories = RepositorySet(session)
            objects = [
                item
                for item in repositories.system_data_objects.list_by_session(
                    research_session_id
                )
                if item.resource_identifier == resource_identifier
            ]
            identities = {
                item.id: item
                for item in repositories.system_identities.list_by_session(research_session_id)
            }
            object_ids = {item.id for item in objects}
            relationships = [
                item
                for item in repositories.system_relationships.list_by_session(
                    research_session_id
                )
                if item.target_entity_id in object_ids
                and item.relationship_type is RelationshipType.OWNS
            ]
        return [
            {
                "identity": identities[item.source_entity_id].name,
                "resource": resource_identifier,
                "observation_ids": [str(value) for value in item.observation_ids],
                "evidence_ids": [str(value) for value in item.evidence_ids],
            }
            for item in relationships
            if item.source_entity_id in identities
        ]
