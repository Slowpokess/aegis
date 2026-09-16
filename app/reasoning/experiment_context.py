import hashlib
import json
import re
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.execution.identity import LaboratoryIdentityResolver
from app.storage.database import Database
from app.storage.repositories import RepositorySet

PATH_PATTERN = re.compile(r"/[-A-Za-z0-9_./{}]+")


class ExperimentContextResult(BaseModel):
    model_config = ConfigDict(frozen=True)
    canonical_json: str
    sha256: str
    allowed_paths: frozenset[str]
    research_session_id: UUID


class ExperimentContextBuilder:
    def __init__(self, database: Database) -> None:
        self.database = database

    def build(self, hypothesis_id: UUID) -> ExperimentContextResult:
        with self.database.session_factory() as session:
            repositories = RepositorySet(session)
            hypothesis = repositories.hypotheses.get(hypothesis_id)
            if hypothesis is None or hypothesis.research_session_id is None:
                raise ValueError("hypothesis does not exist or has no research session")
            research_session = repositories.research_sessions.get(hypothesis.research_session_id)
            if research_session is None:
                raise ValueError("research session does not exist")
            observations = []
            paths: set[str] = set()
            for observation_id in hypothesis.observation_ids:
                observation = repositories.observations.get(observation_id)
                if observation is None or observation.research_session_id != research_session.id:
                    raise ValueError("hypothesis observation lineage is invalid")
                evidence = repositories.evidence.get(observation.evidence_id)  # type: ignore[arg-type]
                if evidence is None or evidence.research_session_id != research_session.id:
                    raise ValueError("hypothesis evidence lineage is invalid")
                path = urlsplit(evidence.request.url).path
                paths.add(path)
                identity = observation.provenance.metadata.get("identity", {"name": "anonymous", "roles": []})
                observations.append(
                    {
                        "observation_id": str(observation.id),
                        "evidence_id": str(evidence.id),
                        "request": {
                            "method": evidence.request.method,
                            "path": path,
                            "identity": identity,
                        },
                        "response": observation.normalized_data,
                        "trust": observation.trust.value,
                        "target_content_boundary": "UNTRUSTED TARGET DATA",
                    }
                )
            for item in hypothesis.missing_information:
                description = item if isinstance(item, str) else item.description
                paths.update(PATH_PATTERN.findall(description))
            payload = {
                "hypothesis": {
                    "id": str(hypothesis.id),
                    "title": hypothesis.title,
                    "description": hypothesis.description,
                    "assumptions": hypothesis.assumptions,
                    "missing_information": [
                        item if isinstance(item, str) else item.model_dump(mode="json")
                        for item in hypothesis.missing_information
                    ],
                },
                "target": {
                    "base_url": research_session.target.base_url,
                    "scope": research_session.scope.model_dump(mode="json"),
                },
                "allowed_identities": sorted(LaboratoryIdentityResolver().allowed_names),
                "allowed_methods": ["GET", "HEAD", "OPTIONS"],
                "allowed_paths": sorted(paths),
                "observations": observations,
            }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return ExperimentContextResult(
            canonical_json=canonical,
            sha256=hashlib.sha256(canonical.encode()).hexdigest(),
            allowed_paths=frozenset(paths),
            research_session_id=research_session.id,
        )
