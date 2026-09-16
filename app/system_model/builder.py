from collections.abc import Iterable
from typing import Any, TypeVar
from uuid import UUID

from app.domain.common import FactClassification, Provenance, utc_now
from app.domain.system_model import (
    CapabilityType,
    DataObjectType,
    ModelBuildStatus,
    PermissionEffect,
    ProcessedModelObservation,
    RelationshipType,
    SystemAsset,
    SystemAssetType,
    SystemCapability,
    SystemDataObject,
    SystemEndpoint,
    SystemEntityType,
    SystemFact,
    SystemIdentity,
    SystemIdentityType,
    SystemModelBuild,
    SystemPermission,
    SystemRelationship,
    SystemRole,
    SystemService,
)
from app.logging_config import system_model_log
from app.storage.database import Database
from app.storage.repositories import RepositorySet, SystemFactRepository
from app.system_model.mapper import (
    DNSObservationMapper,
    HTTPObservationMapper,
    MappedHTTPObservation,
    NmapObservationMapper,
    TLSObservationMapper,
    WebSurfaceObservationMapper,
)
from app.system_model.serialization import model_sha256

FactT = TypeVar("FactT", bound=SystemFact)


class SystemModelBuilder:
    """Build a rebuildable, evidence-backed projection from deterministic observations."""

    def __init__(self, database: Database) -> None:
        self.database = database
        self.http_mapper = HTTPObservationMapper()
        self.nmap_mapper = NmapObservationMapper()
        self.dns_mapper = DNSObservationMapper()
        self.tls_mapper = TLSObservationMapper()
        self.web_surface_mapper = WebSurfaceObservationMapper()

    def build(self, research_session_id: UUID, *, rebuild: bool = False) -> SystemModelBuild:
        build = SystemModelBuild(
            research_session_id=research_session_id,
            provenance=Provenance(
                source_type="system_model",
                source_reference=str(research_session_id),
                collector="aegis-system-model-builder",
                classification=FactClassification.OBSERVED,
            ),
        )
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            if repositories.research_sessions.get(research_session_id) is None:
                raise ValueError("research session does not exist")
            repositories.system_model_builds.add(build)
        system_model_log.info(
            "build started build_id=%s session_id=%s rebuild=%s",
            build.id,
            research_session_id,
            rebuild,
        )
        try:
            with self.database.session_factory.begin() as session:
                repositories = RepositorySet(session)
                research_session = repositories.research_sessions.get(research_session_id)
                if research_session is None:
                    raise ValueError("research session does not exist")
                if rebuild:
                    self._delete_projection(repositories, research_session_id)
                processed = repositories.processed_model_observations.observation_ids(
                    research_session_id
                )
                observations = [
                    item
                    for item in repositories.observations.list_by_session(research_session_id)
                    if item.id not in processed
                ]
                counters = {
                    "processed": 0,
                    "unsupported": 0,
                    "entities_created": 0,
                    "entities_updated": 0,
                    "relationships_created": 0,
                    "relationships_updated": 0,
                }
                for observation in observations:
                    if self.http_mapper.supports(observation):
                        evidence = (
                            repositories.evidence.get(observation.evidence_id)
                            if observation.evidence_id
                            else None
                        )
                        if evidence is None:
                            raise ValueError("HTTP observation evidence does not exist")
                        if evidence.research_session_id != research_session_id:
                            raise ValueError("observation evidence belongs to another session")
                        mapped = self.http_mapper.map(observation, evidence)
                        self._map_http(
                            repositories,
                            research_session,
                            observation,
                            evidence.id,
                            mapped,
                            counters,
                        )
                    elif self.nmap_mapper.supports(observation):
                        artifact = self._tool_artifact(
                            repositories, observation, research_session_id
                        )
                        self._map_nmap(
                            repositories,
                            research_session,
                            observation,
                            artifact.id,
                            self.nmap_mapper.map(observation),
                            counters,
                        )
                    elif self.web_surface_mapper.supports(observation):
                        artifact = self._tool_artifact(
                            repositories, observation, research_session_id
                        )
                        self._map_http(
                            repositories,
                            research_session,
                            observation,
                            artifact.id,
                            self.web_surface_mapper.map(observation),
                            counters,
                        )
                    elif self.dns_mapper.supports(observation):
                        artifact = self._tool_artifact(
                            repositories, observation, research_session_id
                        )
                        self._map_dns(
                            repositories,
                            observation,
                            artifact.id,
                            self.dns_mapper.map(observation),
                            counters,
                        )
                    elif self.tls_mapper.supports(observation):
                        self._tool_artifact(repositories, observation, research_session_id)
                        self.tls_mapper.map(observation)
                    else:
                        counters["unsupported"] += 1
                        self._mark_processed(
                            repositories, research_session_id, observation.id, build.id
                        )
                        continue
                    self._mark_processed(
                        repositories, research_session_id, observation.id, build.id
                    )
                    counters["processed"] += 1
                self._link_web_resources(repositories, research_session_id)
                completed = build.model_copy(
                    update={
                        "status": ModelBuildStatus.COMPLETED,
                        "finished_at": utc_now(),
                        "observations_processed": counters["processed"],
                        "unsupported_observations": counters["unsupported"],
                        "entities_created": counters["entities_created"],
                        "entities_updated": counters["entities_updated"],
                        "relationships_created": counters["relationships_created"],
                        "relationships_updated": counters["relationships_updated"],
                        "model_sha256": model_sha256(repositories, research_session_id),
                    }
                )
                repositories.system_model_builds.update(completed)
        except Exception as error:
            with self.database.session_factory.begin() as session:
                repositories = RepositorySet(session)
                failed = build.model_copy(
                    update={
                        "status": ModelBuildStatus.FAILED,
                        "finished_at": utc_now(),
                        "error": str(error),
                    }
                )
                repositories.system_model_builds.update(failed)
            raise
        system_model_log.info(
            "build completed build_id=%s session_id=%s observations=%s entities_created=%s "
            "relationships_created=%s model_sha256=%s",
            completed.id,
            research_session_id,
            completed.observations_processed,
            completed.entities_created,
            completed.relationships_created,
            completed.model_sha256,
        )
        return completed

    @staticmethod
    def _tool_artifact(
        repositories: RepositorySet, observation: Any, research_session_id: UUID
    ) -> Any:
        if observation.tool_artifact_id is None:
            raise ValueError("tool observation has no artifact lineage")
        artifact = repositories.tool_artifacts.get(observation.tool_artifact_id)
        if artifact is None or artifact.research_session_id != research_session_id:
            raise ValueError("tool observation artifact belongs to another session")
        return artifact

    def _map_nmap(
        self,
        repositories: RepositorySet,
        research_session: Any,
        observation: Any,
        artifact_id: UUID,
        mapped: Any,
        counters: dict[str, int],
    ) -> None:
        if mapped.state != "open":
            return
        host = self._upsert(
            repositories.system_assets,
            SystemAsset,
            f"host:{mapped.address.lower()}",
            observation,
            artifact_id,
            counters,
            asset_type=SystemAssetType.HOST,
            name=mapped.address.lower(),
            metadata={"host": mapped.address.lower()},
        )
        app_canonical = f"application:{research_session.target.base_url.rstrip('/')}"
        application = self._upsert(
            repositories.system_assets,
            SystemAsset,
            app_canonical,
            observation,
            artifact_id,
            counters,
            asset_type=SystemAssetType.APPLICATION,
            name=research_session.target.name,
            parent_asset_id=host.id,
            metadata={"base_url": research_session.target.base_url},
        )
        service_name = (mapped.service_name or mapped.protocol).lower()
        if service_name in {"http", "http-proxy"}:
            scheme = "http"
            service_type = "HTTP"
        elif service_name in {"https", "ssl/http"}:
            scheme = "https"
            service_type = "HTTP"
        else:
            scheme = mapped.protocol.lower()
            service_type = service_name.upper()
        canonical = f"service:{scheme}://{mapped.address.lower()}:{mapped.port}"
        existing = repositories.system_services.get_by_canonical(
            observation.research_session_id, canonical
        )
        service = self._upsert(
            repositories.system_services,
            SystemService,
            canonical,
            observation,
            artifact_id,
            counters,
            asset_id=application.id,
            protocol=existing.protocol if existing else scheme.upper(),
            port=mapped.port,
            service_type=existing.service_type if existing else service_type,
            observed_state=existing.observed_state if existing else "OPEN",
        )
        self._relationship(
            repositories,
            host,
            SystemEntityType.ASSET,
            RelationshipType.HOSTS,
            application,
            SystemEntityType.ASSET,
            observation,
            artifact_id,
            counters,
        )
        self._relationship(
            repositories,
            application,
            SystemEntityType.ASSET,
            RelationshipType.EXPOSES,
            service,
            SystemEntityType.SERVICE,
            observation,
            artifact_id,
            counters,
        )

    def _map_dns(
        self,
        repositories: RepositorySet,
        observation: Any,
        artifact_id: UUID,
        mapped: Any,
        counters: dict[str, int],
    ) -> None:
        domain = self._upsert(
            repositories.system_assets,
            SystemAsset,
            f"domain:{mapped.requested_hostname.lower()}",
            observation,
            artifact_id,
            counters,
            asset_type=SystemAssetType.DOMAIN,
            name=mapped.requested_hostname.lower(),
            metadata={"hostname": mapped.requested_hostname.lower()},
        )
        for address in mapped.addresses:
            host = self._upsert(
                repositories.system_assets,
                SystemAsset,
                f"host:{address.lower()}",
                observation,
                artifact_id,
                counters,
                asset_type=SystemAssetType.HOST,
                name=address.lower(),
                metadata={"host": address.lower()},
            )
            self._relationship(
                repositories,
                domain,
                SystemEntityType.ASSET,
                RelationshipType.RESOLVES_TO,
                host,
                SystemEntityType.ASSET,
                observation,
                artifact_id,
                counters,
            )

    def _map_http(
        self,
        repositories: RepositorySet,
        research_session: Any,
        observation: Any,
        evidence_id: UUID,
        mapped: MappedHTTPObservation,
        counters: dict[str, int],
    ) -> None:
        host = self._upsert(
            repositories.system_assets,
            SystemAsset,
            f"host:{mapped.host}",
            observation,
            evidence_id,
            counters,
            asset_type=SystemAssetType.HOST,
            name=mapped.host,
            metadata={"host": mapped.host},
        )
        app_canonical = f"application:{research_session.target.base_url.rstrip('/')}"
        application = self._upsert(
            repositories.system_assets,
            SystemAsset,
            app_canonical,
            observation,
            evidence_id,
            counters,
            asset_type=SystemAssetType.APPLICATION,
            name=research_session.target.name,
            parent_asset_id=host.id,
            metadata={"base_url": research_session.target.base_url},
        )
        service_canonical = f"service:{mapped.scheme}://{mapped.host}:{mapped.port}"
        service = self._upsert(
            repositories.system_services,
            SystemService,
            service_canonical,
            observation,
            evidence_id,
            counters,
            asset_id=application.id,
            protocol=mapped.scheme.upper(),
            port=mapped.port,
            service_type="HTTP",
            observed_state="RESPONDED",
        )
        endpoint_canonical = (
            f"endpoint:{mapped.method}:{mapped.scheme}://{mapped.host}:{mapped.port}{mapped.path}"
        )
        endpoint = self._upsert(
            repositories.system_endpoints,
            SystemEndpoint,
            endpoint_canonical,
            observation,
            evidence_id,
            counters,
            service_id=service.id,
            scheme=mapped.scheme,
            host=mapped.host,
            port=mapped.port,
            method=mapped.method,
            path=mapped.path,
            authentication_observed=(
                mapped.identity_name not in {None, "anonymous"}
                if mapped.identity_name is not None
                else None
            ),
        )
        self._relationship(
            repositories,
            host,
            SystemEntityType.ASSET,
            RelationshipType.HOSTS,
            application,
            SystemEntityType.ASSET,
            observation,
            evidence_id,
            counters,
        )
        self._relationship(
            repositories,
            application,
            SystemEntityType.ASSET,
            RelationshipType.EXPOSES,
            service,
            SystemEntityType.SERVICE,
            observation,
            evidence_id,
            counters,
        )
        self._relationship(
            repositories,
            service,
            SystemEntityType.SERVICE,
            RelationshipType.EXPOSES,
            endpoint,
            SystemEntityType.ENDPOINT,
            observation,
            evidence_id,
            counters,
        )
        identity = None
        if mapped.identity_name:
            role = self._role(repositories, mapped, observation, evidence_id, counters)
            identity = self._identity(
                repositories, mapped.identity_name, role, observation, evidence_id, counters
            )
            if role:
                self._relationship(
                    repositories,
                    identity,
                    SystemEntityType.IDENTITY,
                    RelationshipType.HAS_ROLE,
                    role,
                    SystemEntityType.ROLE,
                    observation,
                    evidence_id,
                    counters,
                )
            self._map_access(
                repositories,
                identity,
                endpoint,
                mapped,
                observation,
                evidence_id,
                counters,
            )
        for data, owner in self._data_objects(mapped):
            data_object = self._upsert(
                repositories.system_data_objects,
                SystemDataObject,
                data["canonical_identifier"],
                observation,
                evidence_id,
                counters,
                data_type=data["data_type"],
                name=data["name"],
                resource_identifier=data["resource_identifier"],
                metadata=data["metadata"],
            )
            self._relationship(
                repositories,
                endpoint,
                SystemEntityType.ENDPOINT,
                RelationshipType.RETURNS,
                data_object,
                SystemEntityType.DATA_OBJECT,
                observation,
                evidence_id,
                counters,
            )
            if identity and mapped.status_code is not None and 200 <= mapped.status_code < 300:
                self._relationship(
                    repositories,
                    identity,
                    SystemEntityType.IDENTITY,
                    RelationshipType.READS,
                    data_object,
                    SystemEntityType.DATA_OBJECT,
                    observation,
                    evidence_id,
                    counters,
                )
            if owner:
                owner_identity = self._identity(
                    repositories, owner, None, observation, evidence_id, counters
                )
                self._relationship(
                    repositories,
                    owner_identity,
                    SystemEntityType.IDENTITY,
                    RelationshipType.OWNS,
                    data_object,
                    SystemEntityType.DATA_OBJECT,
                    observation,
                    evidence_id,
                    counters,
                )

    def _map_access(
        self,
        repositories: RepositorySet,
        identity: SystemIdentity,
        endpoint: SystemEndpoint,
        mapped: MappedHTTPObservation,
        observation: Any,
        evidence_id: UUID,
        counters: dict[str, int],
    ) -> None:
        if mapped.status_code is not None and 200 <= mapped.status_code < 300:
            relation = RelationshipType.CAN_ACCESS
            effect = PermissionEffect.ALLOW
        elif mapped.status_code in {401, 403}:
            relation = RelationshipType.CANNOT_ACCESS
            effect = PermissionEffect.DENY
        else:
            return
        self._relationship(
            repositories,
            identity,
            SystemEntityType.IDENTITY,
            relation,
            endpoint,
            SystemEntityType.ENDPOINT,
            observation,
            evidence_id,
            counters,
        )
        permission_canonical = (
            f"permission:{identity.canonical_identifier}:{mapped.method}:"
            f"{endpoint.canonical_identifier}:{effect.value}"
        )
        self._upsert(
            repositories.system_permissions,
            SystemPermission,
            permission_canonical,
            observation,
            evidence_id,
            counters,
            subject_entity_type=SystemEntityType.IDENTITY,
            subject_entity_id=identity.id,
            action=mapped.method,
            resource_type=SystemEntityType.ENDPOINT,
            resource_id=endpoint.id,
            effect=effect,
        )
        if effect is PermissionEffect.ALLOW:
            capability_canonical = (
                f"capability:{identity.canonical_identifier}:READ_ENDPOINT:"
                f"{endpoint.canonical_identifier}"
            )
            self._upsert(
                repositories.system_capabilities,
                SystemCapability,
                capability_canonical,
                observation,
                evidence_id,
                counters,
                subject_entity_type=SystemEntityType.IDENTITY,
                subject_entity_id=identity.id,
                capability_type=CapabilityType.READ_ENDPOINT,
                resource_entity_type=SystemEntityType.ENDPOINT,
                resource_entity_id=endpoint.id,
            )

    def _role(
        self,
        repositories: RepositorySet,
        mapped: MappedHTTPObservation,
        observation: Any,
        evidence_id: UUID,
        counters: dict[str, int],
    ) -> SystemRole | None:
        role_name = mapped.identity_roles[0] if mapped.identity_roles else None
        if mapped.identity_name == "anonymous":
            role_name = "anonymous"
        if not role_name:
            return None
        return self._upsert(
            repositories.system_roles,
            SystemRole,
            f"role:{role_name.lower()}",
            observation,
            evidence_id,
            counters,
            name=role_name,
        )

    def _identity(
        self,
        repositories: RepositorySet,
        name: str,
        role: SystemRole | None,
        observation: Any,
        evidence_id: UUID,
        counters: dict[str, int],
    ) -> SystemIdentity:
        lowered = name.lower()
        identity_type = (
            SystemIdentityType.ANONYMOUS
            if lowered == "anonymous"
            else (
                SystemIdentityType.ADMINISTRATOR
                if role and role.name.lower() == "admin"
                else SystemIdentityType.USER
            )
        )
        return self._upsert(
            repositories.system_identities,
            SystemIdentity,
            f"identity:{lowered}",
            observation,
            evidence_id,
            counters,
            name=name,
            identity_type=identity_type,
            role_id=role.id if role else None,
        )

    def _relationship(
        self,
        repositories: RepositorySet,
        source: SystemFact,
        source_type: SystemEntityType,
        relationship_type: RelationshipType,
        target: SystemFact,
        target_type: SystemEntityType,
        observation: Any,
        evidence_id: UUID,
        counters: dict[str, int],
    ) -> SystemRelationship:
        if source.research_session_id != target.research_session_id:
            raise ValueError("system relationship cannot cross research sessions")
        canonical = (
            f"relationship:{source.canonical_identifier}:{relationship_type.value}:"
            f"{target.canonical_identifier}"
        )
        return self._upsert(
            repositories.system_relationships,
            SystemRelationship,
            canonical,
            observation,
            evidence_id,
            counters,
            relationship=True,
            source_entity_type=source_type,
            source_entity_id=source.id,
            relationship_type=relationship_type,
            target_entity_type=target_type,
            target_entity_id=target.id,
        )

    def _upsert(
        self,
        repository: SystemFactRepository[Any, Any],
        model: type[FactT],
        canonical_identifier: str,
        observation: Any,
        evidence_id: UUID,
        counters: dict[str, int],
        *,
        relationship: bool = False,
        **fields: Any,
    ) -> FactT:
        existing = repository.get_by_canonical(
            observation.research_session_id, canonical_identifier
        )
        counter_prefix = "relationships" if relationship else "entities"
        if existing:
            update_fields = {key: value for key, value in fields.items() if value is not None}
            observation_ids = sorted({*existing.observation_ids, observation.id}, key=str)
            evidence_ids = sorted({*existing.evidence_ids, evidence_id}, key=str)
            updated = existing.model_copy(
                update={
                    "observation_ids": observation_ids,
                    "evidence_ids": evidence_ids,
                    "first_seen": min(existing.first_seen, observation.timestamp),
                    "last_seen": max(existing.last_seen, observation.timestamp),
                    "updated_at": utc_now(),
                    **update_fields,
                }
            )
            repository.update(updated)
            counters[f"{counter_prefix}_updated"] += 1
            return updated
        created = model(
            research_session_id=observation.research_session_id,
            canonical_identifier=canonical_identifier,
            source_type=observation.provenance.source_type,
            observation_ids=[observation.id],
            evidence_ids=[evidence_id],
            classification=FactClassification.OBSERVED,
            confidence=1.0,
            first_seen=observation.timestamp,
            last_seen=observation.timestamp,
            provenance=Provenance(
                source_type=observation.provenance.source_type,
                source_reference=str(observation.id),
                collector="aegis-system-model-builder",
                classification=FactClassification.OBSERVED,
                metadata={"evidence_id": str(evidence_id)},
            ),
            **fields,
        )
        repository.add(created)
        counters[f"{counter_prefix}_created"] += 1
        return created

    @staticmethod
    def _data_objects(
        mapped: MappedHTTPObservation,
    ) -> Iterable[tuple[dict[str, Any], str | None]]:
        if not mapped.path.startswith("/api/orders") or mapped.json_body is None:
            return []
        resources: list[dict[str, Any]] = []
        if isinstance(mapped.json_body, dict):
            if isinstance(mapped.json_body.get("orders"), list):
                resources = [item for item in mapped.json_body["orders"] if isinstance(item, dict)]
            elif "id" in mapped.json_body:
                resources = [mapped.json_body]
        output: list[tuple[dict[str, Any], str | None]] = []
        for resource in resources:
            resource_id = resource.get("id")
            if not isinstance(resource_id, (str, int)):
                continue
            owner = resource.get("owner")
            output.append(
                (
                    {
                        "canonical_identifier": f"data:order:{resource_id}",
                        "data_type": DataObjectType.ORDER,
                        "name": f"order {resource_id}",
                        "resource_identifier": f"order:{resource_id}",
                        "metadata": {"id": resource_id},
                    },
                    owner if isinstance(owner, str) and owner else None,
                )
            )
        return output

    @staticmethod
    def _delete_projection(repositories: RepositorySet, research_session_id: UUID) -> None:
        for resource in repositories.web_resources.list_by_session(research_session_id):
            if resource.system_endpoint_id is not None:
                repositories.web_resources.update(
                    resource.model_copy(
                        update={"system_endpoint_id": None, "updated_at": utc_now()}
                    )
                )
        repositories.processed_model_observations.delete_by_session(research_session_id)
        for repository in (
            repositories.system_relationships,
            repositories.system_capabilities,
            repositories.system_permissions,
            repositories.system_trust_boundaries,
            repositories.system_data_objects,
            repositories.system_endpoints,
            repositories.system_services,
            repositories.system_identities,
            repositories.system_roles,
            repositories.system_assets,
        ):
            repository.delete_by_session(research_session_id)

    @staticmethod
    def _link_web_resources(repositories: RepositorySet, research_session_id: UUID) -> None:
        for resource in repositories.web_resources.list_by_session(research_session_id):
            endpoint_key = (
                f"endpoint:{resource.method}:{resource.scheme}://"
                f"{resource.host}:{resource.effective_port}{resource.path}"
            )
            endpoint = repositories.system_endpoints.get_by_canonical(
                research_session_id, endpoint_key
            )
            endpoint_id = endpoint.id if endpoint else None
            if resource.system_endpoint_id != endpoint_id:
                repositories.web_resources.update(
                    resource.model_copy(
                        update={"system_endpoint_id": endpoint_id, "updated_at": utc_now()}
                    )
                )

    @staticmethod
    def _mark_processed(
        repositories: RepositorySet,
        research_session_id: UUID,
        observation_id: UUID,
        build_id: UUID,
    ) -> None:
        repositories.processed_model_observations.add(
            ProcessedModelObservation(
                research_session_id=research_session_id,
                observation_id=observation_id,
                build_id=build_id,
                provenance=Provenance(
                    source_type="system_model",
                    source_reference=str(observation_id),
                    collector="aegis-system-model-builder",
                    classification=FactClassification.OBSERVED,
                ),
            )
        )
