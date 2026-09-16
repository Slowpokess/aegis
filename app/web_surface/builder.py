import hashlib
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit
from uuid import UUID

from app.domain.common import FactClassification, Provenance, utc_now
from app.domain.active_web import WebCandidateProvenance
from app.domain.observations import Observation, ObservationSource
from app.domain.research import TargetScope
from app.domain.web_surface import (
    AssessmentSeverity,
    ContentSource,
    HTTPRequestTemplate,
    ParameterDescriptor,
    WebParameter,
    WebParameterLocation,
    WebResource,
    WebResourceProvenance,
    WebResourceType,
    WebSurfaceSnapshot,
    WebTemplateCandidate,
    WebCandidateClassification,
    web_surface_sha256,
)
from app.storage.database import Database
from app.storage.repositories import RepositorySet
from app.web_surface.pipeline import canonical_resource_key, canonical_url


@dataclass(frozen=True)
class _SurfaceFact:
    url: str
    method: str
    resource_type: WebResourceType
    status_code: int | None
    content_type: str | None
    request_content_type: str | None
    parameters: tuple[ParameterDescriptor, ...]
    logical_identity_reference: str | None
    source: ContentSource
    observation: Observation
    template: dict[str, object] | None = None


_TYPE_PRIORITY = {
    WebResourceType.UNKNOWN: 0,
    WebResourceType.DIRECTORY: 1,
    WebResourceType.STATIC_RESOURCE: 2,
    WebResourceType.PAGE: 3,
    WebResourceType.API_ROUTE: 4,
    WebResourceType.REDIRECT: 5,
    WebResourceType.FORM_TARGET: 6,
}


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _content_type(headers: dict[str, str]) -> str | None:
    value = next((value for name, value in headers.items() if name.lower() == "content-type"), None)
    return _media_type(value)


def _media_type(value: str | None) -> str | None:
    normalized = value.split(";", 1)[0].strip().lower() if value else ""
    return normalized or None


class WebSurfaceBuilder:
    """Deterministic projection from immutable HTTP/tool Observations."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def build(self, research_session_id: UUID, *, rebuild: bool = False) -> WebSurfaceSnapshot:
        with self.database.session_factory.begin() as session:
            r = RepositorySet(session)
            research = r.research_sessions.get(research_session_id)
            if research is None:
                raise ValueError("research session does not exist")
            if rebuild:
                self._delete_projection(r, research_session_id)
            observations = sorted(
                r.observations.list_by_session(research_session_id),
                key=lambda item: (item.timestamp, str(item.id)),
            )
            for observation in observations:
                fact = self._fact(r, research.scope, observation)
                if fact is not None:
                    self._upsert_fact(r, research_session_id, fact)
            resources = r.web_resources.list_by_session(research_session_id)
            parameters = r.web_parameters.list_by_session(research_session_id)
            templates = r.http_request_templates.list_by_session(research_session_id)
            candidates = r.web_template_candidates.list_by_session(research_session_id)
            provenance = r.web_resource_provenance.list_by_session(research_session_id)
            snapshot = WebSurfaceSnapshot(
                research_session_id=research_session_id,
                resource_count=len(resources),
                parameter_count=len(parameters),
                request_template_count=len(templates),
                candidate_count=len(candidates),
                source_observation_count=len({item.observation_id for item in provenance}),
                web_surface_sha256=web_surface_sha256(
                    resources, parameters, templates, candidates, provenance
                ),
                provenance=Provenance(
                    source_type="web_surface_snapshot",
                    source_reference=str(research_session_id),
                    collector="web-surface-builder-v1",
                ),
            )
            r.web_surface_snapshots.add(snapshot)
            return snapshot

    @staticmethod
    def _delete_projection(r: RepositorySet, session_id: UUID) -> None:
        r.web_candidate_provenance.delete_by_session(session_id)
        r.web_template_candidates.delete_by_session(session_id)
        r.http_request_templates.delete_by_session(session_id)
        r.web_parameters.delete_by_session(session_id)
        r.web_resource_provenance.delete_by_session(session_id)
        r.web_resources.delete_by_session(session_id)

    def _fact(
        self, r: RepositorySet, scope: TargetScope, observation: Observation
    ) -> _SurfaceFact | None:
        if observation.source is ObservationSource.HTTP:
            if observation.evidence_id is None:
                return None
            evidence = r.evidence.get(observation.evidence_id)
            if evidence is None:
                return None
            url = evidence.request.url
            scope.validate_url(url)
            parsed = urlsplit(url)
            parameters = [
                ParameterDescriptor(name=name, location=WebParameterLocation.QUERY)
                for name, _ in parse_qsl(parsed.query)
            ]
            parameters.extend(
                ParameterDescriptor(name=name, location=WebParameterLocation.HEADER_METADATA)
                for name in evidence.request.headers
                if name.lower()
                not in {"authorization", "cookie", "proxy-authorization", "set-cookie"}
            )
            identity = observation.provenance.metadata.get("identity")
            identity_name = identity.get("name") if isinstance(identity, dict) else None
            content_type = _content_type(evidence.response.headers)
            resource_type = self._resource_type(
                parsed.path or "/",
                evidence.response.status_code,
                content_type,
                ContentSource.HTTP_EXECUTOR,
            )
            return _SurfaceFact(
                url=url,
                method=evidence.request.method.upper(),
                resource_type=resource_type,
                status_code=evidence.response.status_code,
                content_type=content_type,
                request_content_type=_content_type(evidence.request.headers),
                parameters=tuple(parameters),
                logical_identity_reference=(
                    identity_name if isinstance(identity_name, str) else None
                ),
                source=ContentSource.HTTP_EXECUTOR,
                observation=observation,
            )
        data = observation.normalized_data
        source_type = data.get("source_type")
        if source_type == "burp_http_exchange":
            url = str(data.get("url") or "")
            scope.validate_url(url)
            parameters = [
                ParameterDescriptor(name=str(name), location=WebParameterLocation.QUERY)
                for name in data.get("query_parameter_names", [])
                if isinstance(name, str) and name
            ]
            parameters.extend(
                ParameterDescriptor(name=str(name), location=WebParameterLocation.BODY_FIELD)
                for name in data.get("body_parameter_names", [])
                if isinstance(name, str) and name
            )
            parameters.extend(
                ParameterDescriptor(name=str(name), location=WebParameterLocation.HEADER_METADATA)
                for name in data.get("header_names", [])
                if isinstance(name, str) and name
            )
            status = int(data["status_code"])
            content_type = _media_type(
                str(data["content_type"]) if data.get("content_type") else None
            )
            return _SurfaceFact(
                url=url,
                method=str(data["method"]),
                resource_type=self._resource_type(
                    str(data["path"]), status, content_type, ContentSource.TRAFFIC
                ),
                status_code=status,
                content_type=content_type,
                request_content_type=_media_type(
                    str(data["request_content_type"]) if data.get("request_content_type") else None
                ),
                parameters=tuple(parameters),
                logical_identity_reference=None,
                source=ContentSource.TRAFFIC,
                observation=observation,
            )
        if source_type == "web_content_discovery":
            url = str(data.get("url") or "")
            scope.validate_url(url)
            parameters = tuple(
                ParameterDescriptor.model_validate(item)
                for item in data.get("parameters", [])
                if isinstance(item, dict)
            )
            return _SurfaceFact(
                url=url,
                method=str(data["method"]),
                resource_type=WebResourceType(str(data["resource_type"])),
                status_code=(int(data["status_code"]) if data.get("status_code") else None),
                content_type=_media_type(
                    str(data["content_type"]) if data.get("content_type") else None
                ),
                request_content_type=None,
                parameters=parameters,
                logical_identity_reference=None,
                source=ContentSource(str(data["source"])),
                observation=observation,
            )
        if source_type == "ffuf_web_discovery":
            url = str(data.get("url") or "")
            scope.validate_url(url)
            parsed = urlsplit(url)
            status = int(data["status_code"])
            content_type = _media_type(
                str(data["content_type"]) if data.get("content_type") else None
            )
            return _SurfaceFact(
                url=url,
                method="GET",
                resource_type=self._resource_type(
                    parsed.path or "/", status, content_type, ContentSource.FFUF_DISCOVERY
                ),
                status_code=status,
                content_type=content_type,
                request_content_type=None,
                parameters=tuple(
                    ParameterDescriptor(name=name, location=WebParameterLocation.QUERY)
                    for name, _ in parse_qsl(parsed.query)
                ),
                logical_identity_reference=None,
                source=ContentSource.FFUF_DISCOVERY,
                observation=observation,
            )
        if source_type == "web_template_match":
            url = str(data.get("matched_url") or "")
            scope.validate_url(url)
            return _SurfaceFact(
                url=url,
                method="GET",
                resource_type=WebResourceType.UNKNOWN,
                status_code=None,
                content_type=None,
                request_content_type=None,
                parameters=(),
                logical_identity_reference=None,
                source=(
                    ContentSource.NUCLEI_ASSESSMENT
                    if observation.provenance.source_type == "nuclei"
                    else ContentSource.TEMPLATE_RESULT
                ),
                observation=observation,
                template=dict(data),
            )
        return None

    @staticmethod
    def _resource_type(
        path: str,
        status: int | None,
        content_type: str | None,
        source: ContentSource,
    ) -> WebResourceType:
        if source is ContentSource.HTML_FORM:
            return WebResourceType.FORM_TARGET
        if status is not None and 300 <= status < 400:
            return WebResourceType.REDIRECT
        if path.startswith("/api/") or "json" in (content_type or "").lower():
            return WebResourceType.API_ROUTE
        if "html" in (content_type or "").lower():
            return WebResourceType.PAGE
        return WebResourceType.UNKNOWN

    def _upsert_fact(self, r: RepositorySet, session_id: UUID, fact: _SurfaceFact) -> None:
        normalized_url = canonical_url(fact.url)
        parsed = urlsplit(normalized_url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        canonical_key = canonical_resource_key(fact.method, normalized_url)
        resource = r.web_resources.get_by_canonical(session_id, canonical_key)
        endpoint_canonical = (
            f"endpoint:{fact.method.upper()}:{parsed.scheme}://"
            f"{parsed.hostname}:{port}{parsed.path or '/'}"
        )
        endpoint = r.system_endpoints.get_by_canonical(session_id, endpoint_canonical)
        if resource is None:
            resource = WebResource(
                research_session_id=session_id,
                canonical_key=canonical_key,
                scheme=parsed.scheme,
                host=parsed.hostname or "",
                effective_port=port,
                method=fact.method.upper(),
                path=parsed.path or "/",
                resource_type=fact.resource_type,
                latest_status_code=fact.status_code,
                content_type=fact.content_type,
                classification=FactClassification.OBSERVED,
                system_endpoint_id=endpoint.id if endpoint else None,
                first_seen=fact.observation.timestamp,
                last_seen=fact.observation.timestamp,
                provenance=Provenance(
                    source_type="web_surface",
                    source_reference=str(fact.observation.id),
                    collector="web-surface-builder-v1",
                ),
            )
            r.web_resources.add(resource)
        else:
            resource_type = (
                fact.resource_type
                if _TYPE_PRIORITY[fact.resource_type] > _TYPE_PRIORITY[resource.resource_type]
                else resource.resource_type
            )
            newer = fact.observation.timestamp >= resource.last_seen
            resource = resource.model_copy(
                update={
                    "resource_type": resource_type,
                    "latest_status_code": (
                        fact.status_code
                        if newer and fact.status_code is not None
                        else resource.latest_status_code
                    ),
                    "content_type": fact.content_type or resource.content_type,
                    "system_endpoint_id": endpoint.id if endpoint else resource.system_endpoint_id,
                    "first_seen": min(resource.first_seen, fact.observation.timestamp),
                    "last_seen": max(resource.last_seen, fact.observation.timestamp),
                    "updated_at": utc_now(),
                }
            )
            r.web_resources.update(resource)
        if (
            r.web_resource_provenance.get_semantic(
                resource.id, fact.observation.id, fact.source.value
            )
            is None
        ):
            r.web_resource_provenance.add(
                WebResourceProvenance(
                    research_session_id=session_id,
                    web_resource_id=resource.id,
                    observation_id=fact.observation.id,
                    tool_artifact_id=fact.observation.tool_artifact_id,
                    evidence_id=fact.observation.evidence_id,
                    source=fact.source,
                    classification=FactClassification.OBSERVED,
                    observed_at=fact.observation.timestamp,
                    provenance=Provenance(
                        source_type="web_resource_provenance",
                        source_reference=str(fact.observation.id),
                    ),
                )
            )
        for descriptor in sorted(
            set(fact.parameters), key=lambda item: (item.location.value, item.name)
        ):
            existing = r.web_parameters.get_semantic(
                resource.id, descriptor.name, descriptor.location.value
            )
            if existing is None:
                r.web_parameters.add(
                    WebParameter(
                        research_session_id=session_id,
                        web_resource_id=resource.id,
                        name=descriptor.name,
                        location=descriptor.location,
                        classification=FactClassification.OBSERVED,
                        first_seen=fact.observation.timestamp,
                        last_seen=fact.observation.timestamp,
                        provenance=Provenance(
                            source_type="web_parameter",
                            source_reference=str(fact.observation.id),
                        ),
                    )
                )
            else:
                r.web_parameters.update(
                    existing.model_copy(
                        update={
                            "first_seen": min(existing.first_seen, fact.observation.timestamp),
                            "last_seen": max(existing.last_seen, fact.observation.timestamp),
                            "updated_at": utc_now(),
                        }
                    )
                )
        self._upsert_template(r, session_id, resource, fact)
        if fact.template is not None:
            self._upsert_candidate(r, session_id, resource, fact)

    @staticmethod
    def _upsert_template(
        r: RepositorySet, session_id: UUID, resource: WebResource, fact: _SurfaceFact
    ) -> None:
        semantic = _sha256(f"{resource.canonical_key}\x00{fact.logical_identity_reference or ''}")
        existing = r.http_request_templates.get_by_semantic(session_id, semantic)
        parameters = tuple(
            sorted(set(fact.parameters), key=lambda item: (item.location.value, item.name))
        )
        if existing is None:
            r.http_request_templates.add(
                HTTPRequestTemplate(
                    research_session_id=session_id,
                    web_resource_id=resource.id,
                    semantic_key=semantic,
                    method=resource.method,
                    content_type=fact.request_content_type,
                    parameters=parameters,
                    logical_identity_reference=fact.logical_identity_reference,
                    source_observation_ids=(fact.observation.id,),
                    provenance=Provenance(
                        source_type="http_request_template",
                        source_reference=str(fact.observation.id),
                    ),
                )
            )
            return
        merged_parameters = tuple(
            sorted(
                set((*existing.parameters, *parameters)),
                key=lambda item: (item.location.value, item.name),
            )
        )
        source_ids = tuple(dict.fromkeys((*existing.source_observation_ids, fact.observation.id)))
        r.http_request_templates.update(
            existing.model_copy(
                update={
                    "content_type": fact.request_content_type or existing.content_type,
                    "parameters": merged_parameters,
                    "source_observation_ids": source_ids,
                    "updated_at": utc_now(),
                }
            )
        )

    @staticmethod
    def _upsert_candidate(
        r: RepositorySet, session_id: UUID, resource: WebResource, fact: _SurfaceFact
    ) -> None:
        data = fact.template or {}
        template_id = str(data["template_id"])
        matcher = str(data["matcher_name"]) if data.get("matcher_name") else None
        semantic = _sha256(f"{resource.canonical_key}\x00{template_id}\x00{matcher or ''}")
        candidate = r.web_template_candidates.get_by_semantic(session_id, semantic)
        if fact.observation.tool_artifact_id is None:
            raise ValueError("template candidate requires artifact lineage")
        if candidate is None:
            severity = None
            if data.get("tool_reported_severity"):
                severity = AssessmentSeverity(str(data["tool_reported_severity"]))
            candidate = WebTemplateCandidate(
                research_session_id=session_id,
                web_resource_id=resource.id,
                semantic_key=semantic,
                tool_artifact_id=fact.observation.tool_artifact_id,
                observation_id=fact.observation.id,
                template_id=template_id,
                template_name=str(data["template_name"]),
                matcher_name=matcher,
                tool_reported_severity=severity,
                tool_metadata=(
                    dict(data["tool_metadata"])
                    if isinstance(data.get("tool_metadata"), dict)
                    else {}
                ),
                classification=WebCandidateClassification.TOOL_REPORTED,
                provenance=Provenance(
                    source_type="web_template_candidate",
                    source_reference=str(fact.observation.id),
                    classification=FactClassification.OBSERVED,
                ),
            )
            r.web_template_candidates.add(candidate)
        if (
            r.web_candidate_provenance.get_semantic(
                candidate.id, fact.observation.id, fact.source.value
            )
            is not None
        ):
            return
        artifact = r.tool_artifacts.get(fact.observation.tool_artifact_id)
        if artifact is None:
            raise ValueError("template candidate artifact does not exist")
        r.web_candidate_provenance.add(
            WebCandidateProvenance(
                research_session_id=session_id,
                web_template_candidate_id=candidate.id,
                web_resource_id=resource.id,
                tool_artifact_id=artifact.id,
                observation_id=fact.observation.id,
                tool_run_id=artifact.tool_run_id,
                source=fact.source.value,
                provenance=Provenance(
                    source_type="web_candidate_provenance",
                    source_reference=str(fact.observation.id),
                    classification=FactClassification.OBSERVED,
                ),
            )
        )
