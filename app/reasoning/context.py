import hashlib
import json
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.domain.common import Identifier, TrustClassification
from app.execution.protocol import redact_headers
from app.storage.database import Database
from app.storage.repositories import RepositorySet


class ContextModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ContextIdentity(ContextModel):
    name: str
    roles: list[str] = Field(default_factory=list)


class ContextRequest(ContextModel):
    method: str
    path: str
    headers: dict[str, str]
    identity: ContextIdentity | None = None


class ContextResponse(ContextModel):
    status_code: int
    content_type: str | None
    body_length: int
    redirect_location: str | None
    is_json: bool
    json_top_level_type: str | None
    target_content_boundary: str = "UNTRUSTED TARGET DATA"
    target_content: str
    target_content_truncated: bool


class ObservationContext(ContextModel):
    observation_id: Identifier
    evidence_id: Identifier
    request: ContextRequest
    response: ContextResponse
    trust: TrustClassification


class HypothesisContext(ContextModel):
    research_session_id: Identifier
    observations: list[ObservationContext]


class ContextBuildResult(ContextModel):
    context: HypothesisContext
    canonical_json: str
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class ContextBuildError(ValueError):
    pass


class HypothesisContextBuilder:
    def __init__(
        self,
        database: Database,
        *,
        max_observations: int = 50,
        max_body_characters: int = 2000,
        max_total_characters: int = 50_000,
    ) -> None:
        self.database = database
        self.max_observations = max_observations
        self.max_body_characters = max_body_characters
        self.max_total_characters = max_total_characters

    def build(self, research_session_id: UUID) -> ContextBuildResult:
        with self.database.session_factory() as session:
            repositories = RepositorySet(session)
            if repositories.research_sessions.get(research_session_id) is None:
                raise ContextBuildError("research session does not exist")
            observations = repositories.observations.list_by_session(research_session_id)
            selected = sorted(observations, key=lambda item: (item.timestamp, str(item.id)))[
                -self.max_observations :
            ]
            context_observations: list[ObservationContext] = []
            for observation in selected:
                if observation.evidence_id is None:
                    raise ContextBuildError("observation has no evidence reference")
                evidence = repositories.evidence.get(observation.evidence_id)
                if evidence is None:
                    raise ContextBuildError("observation evidence does not exist")
                if (
                    observation.research_session_id != research_session_id
                    or evidence.research_session_id != research_session_id
                    or observation.request_id != evidence.request_id
                ):
                    raise ContextBuildError("observation provenance chain is inconsistent")
                normalized = observation.normalized_data
                identity_metadata = observation.provenance.metadata.get("identity")
                identity = None
                if isinstance(identity_metadata, dict) and isinstance(
                    identity_metadata.get("name"), str
                ):
                    roles = identity_metadata.get("roles", [])
                    identity = ContextIdentity(
                        name=identity_metadata["name"],
                        roles=[role for role in roles if isinstance(role, str)],
                    )
                body = evidence.response.body[: self.max_body_characters]
                parsed_url = urlsplit(evidence.request.url)
                path = parsed_url.path + (f"?{parsed_url.query}" if parsed_url.query else "")
                item = ObservationContext(
                    observation_id=observation.id,
                    evidence_id=evidence.id,
                    request=ContextRequest(
                        method=evidence.request.method,
                        path=path,
                        headers=redact_headers(evidence.request.headers),
                        identity=identity,
                    ),
                    response=ContextResponse(
                        status_code=evidence.response.status_code,
                        content_type=self._optional_string(normalized.get("content_type")),
                        body_length=evidence.response.body_bytes or len(evidence.response.body),
                        redirect_location=self._optional_string(
                            normalized.get("redirect_location")
                        ),
                        is_json=normalized.get("is_json") is True,
                        json_top_level_type=self._optional_string(
                            normalized.get("json_top_level_type")
                        ),
                        target_content=body,
                        target_content_truncated=(
                            evidence.response.truncated
                            or len(evidence.response.body) > self.max_body_characters
                        ),
                    ),
                    trust=observation.trust,
                )
                candidate = HypothesisContext(
                    research_session_id=research_session_id,
                    observations=[*context_observations, item],
                )
                if len(self._canonical(candidate)) > self.max_total_characters:
                    break
                context_observations.append(item)
        if not context_observations:
            raise ContextBuildError("no observations fit the configured context limits")
        context = HypothesisContext(
            research_session_id=research_session_id,
            observations=context_observations,
        )
        canonical = self._canonical(context)
        return ContextBuildResult(
            context=context,
            canonical_json=canonical,
            sha256=hashlib.sha256(canonical.encode()).hexdigest(),
        )

    @staticmethod
    def _canonical(context: HypothesisContext) -> str:
        return json.dumps(
            context.model_dump(mode="json"),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )

    @staticmethod
    def _optional_string(value: object) -> str | None:
        return value if isinstance(value, str) else None
