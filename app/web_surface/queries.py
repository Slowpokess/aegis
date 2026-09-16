from uuid import UUID

from app.storage.database import Database
from app.storage.repositories import RepositorySet


class WebSurfaceQueryService:
    def __init__(self, database: Database) -> None:
        self.database = database

    def summary(self, session_id: UUID) -> dict[str, object]:
        with self.database.session_factory() as session:
            r = RepositorySet(session)
            research = r.research_sessions.get(session_id)
            if research is None:
                raise ValueError("research session does not exist")
            snapshots = r.web_surface_snapshots.list_by_session(session_id)
            resources = r.web_resources.list_by_session(session_id)
            parameters = r.web_parameters.list_by_session(session_id)
            templates = r.http_request_templates.list_by_session(session_id)
            candidates = r.web_template_candidates.list_by_session(session_id)
            sources = r.web_resource_provenance.list_by_session(session_id)
        return {
            "version": "web-surface-v1",
            "snapshot": snapshots[-1].model_dump(mode="json") if snapshots else None,
            "counts": {
                "resources": len(resources),
                "parameters": len(parameters),
                "request_templates": len(templates),
                "template_candidates": len(candidates),
                "sources": len(sources),
                "forms": sum(item.resource_type.value == "FORM_TARGET" for item in resources),
            },
            "methods": {
                method: sum(item.method == method for item in resources)
                for method in sorted({item.method for item in resources})
            },
            "classifications": {
                "resources": "OBSERVED",
                "template_candidates": "TOOL_REPORTED",
                "findings": "VERIFIED",
            },
        }

    def resources(self, session_id: UUID) -> list[dict[str, object]]:
        with self.database.session_factory() as session:
            r = RepositorySet(session)
            resources = r.web_resources.list_by_session(session_id)
            return [self._resource_row(r, item) for item in resources]

    def resource(self, resource_id: UUID) -> dict[str, object]:
        with self.database.session_factory() as session:
            r = RepositorySet(session)
            resource = r.web_resources.get(resource_id)
            if resource is None:
                raise ValueError("web resource does not exist")
            row = self._resource_row(r, resource)
            sources = r.web_resource_provenance.list_by_resource(resource.id)
            observation_ids = {item.observation_id for item in sources}
            evidence_ids = {item.evidence_id for item in sources if item.evidence_id}
            hypotheses = [
                item
                for item in r.hypotheses.list_by_session(resource.research_session_id)
                if observation_ids.intersection(item.observation_ids)
            ]
            findings = [
                item
                for item in r.findings.list_by_session(resource.research_session_id)
                if observation_ids.intersection(item.observation_ids)
                or evidence_ids.intersection(item.evidence_ids)
            ]
            row.update(
                {
                    "sources": [item.model_dump(mode="json") for item in sources],
                    "parameters": [
                        item.model_dump(mode="json")
                        for item in r.web_parameters.list_by_resource(resource.id)
                    ],
                    "request_templates": [
                        item.model_dump(mode="json")
                        for item in r.http_request_templates.list_by_resource(resource.id)
                    ],
                    "template_candidates": [
                        {
                            **item.model_dump(mode="json"),
                            "sources": [
                                source.model_dump(mode="json")
                                for source in r.web_candidate_provenance.list_by_candidate(item.id)
                            ],
                        }
                        for item in r.web_template_candidates.list_by_resource(resource.id)
                    ],
                    "observation_ids": [str(item) for item in sorted(observation_ids, key=str)],
                    "evidence_ids": [str(item) for item in sorted(evidence_ids, key=str)],
                    "hypotheses": [item.model_dump(mode="json") for item in hypotheses],
                    "findings": [item.model_dump(mode="json") for item in findings],
                }
            )
            return row

    def parameters(self, session_id: UUID) -> list[dict[str, object]]:
        with self.database.session_factory() as session:
            values = RepositorySet(session).web_parameters.list_by_session(session_id)
        return [item.model_dump(mode="json") for item in values]

    def templates(self, session_id: UUID) -> list[dict[str, object]]:
        with self.database.session_factory() as session:
            values = RepositorySet(session).http_request_templates.list_by_session(session_id)
        return [item.model_dump(mode="json") for item in values]

    def candidates(self, session_id: UUID) -> list[dict[str, object]]:
        with self.database.session_factory() as session:
            r = RepositorySet(session)
            values = r.web_template_candidates.list_by_session(session_id)
            return [
                {
                    **item.model_dump(mode="json"),
                    "sources": [
                        source.model_dump(mode="json")
                        for source in r.web_candidate_provenance.list_by_candidate(item.id)
                    ],
                }
                for item in values
            ]

    def export(self, session_id: UUID) -> dict[str, object]:
        return {
            "summary": self.summary(session_id),
            "resources": self.resources(session_id),
            "parameters": self.parameters(session_id),
            "request_templates": self.templates(session_id),
            "template_candidates": self.candidates(session_id),
        }

    @staticmethod
    def _resource_row(r: RepositorySet, resource: object) -> dict[str, object]:
        sources = r.web_resource_provenance.list_by_resource(resource.id)
        parameters = r.web_parameters.list_by_resource(resource.id)
        candidates = r.web_template_candidates.list_by_resource(resource.id)
        findings = r.findings.list_by_session(resource.research_session_id)
        observation_ids = {item.observation_id for item in sources}
        evidence_ids = {item.evidence_id for item in sources if item.evidence_id}
        return {
            **resource.model_dump(mode="json"),
            "source_count": len(sources),
            "sources": sorted({item.source.value for item in sources}),
            "parameter_count": len(parameters),
            "candidate_count": len(candidates),
            "finding_count": sum(
                bool(
                    observation_ids.intersection(item.observation_ids)
                    or evidence_ids.intersection(item.evidence_ids)
                )
                for item in findings
            ),
        }
