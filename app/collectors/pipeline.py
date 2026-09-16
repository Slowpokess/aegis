from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict

from app.domain.common import FactClassification, Provenance, TrustClassification
from app.domain.evidence import Evidence, HTTPRequestRecord, HTTPResponseRecord
from app.domain.experiments import ExperimentRole
from app.domain.observations import Observation, ObservationSource
from app.domain.research import ResearchSessionStatus
from app.execution.protocol import ExecutorRequest, HttpMethod
from app.execution.rust_executor import RustExecutorClient
from app.logging_config import research_log, storage_log
from app.storage.database import Database
from app.storage.repositories import RepositorySet
from app.collectors.normalization import ObservationNormalizer


class ObservationResult(BaseModel):
    model_config = ConfigDict(frozen=True)
    evidence: Evidence
    observation: Observation


class ObservationPipeline:
    def __init__(
        self,
        database: Database,
        executor: RustExecutorClient,
        normalizer: ObservationNormalizer | None = None,
    ) -> None:
        self.database = database
        self.executor = executor
        self.normalizer = normalizer or ObservationNormalizer()

    async def observe(
        self,
        *,
        research_session_id: UUID,
        path: str,
        method: HttpMethod = HttpMethod.GET,
        headers: dict[str, str] | None = None,
        timeout_ms: int = 5000,
        max_response_bytes: int = 100_000,
        follow_redirects: bool = False,
        identity_name: str | None = None,
        identity_roles: list[str] | None = None,
        experiment_id: UUID | None = None,
        experiment_role: ExperimentRole | None = None,
    ) -> ObservationResult:
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("observation path must be an absolute target path")
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            research_session = repositories.research_sessions.get(research_session_id)
            if research_session is None:
                raise ValueError("research session does not exist")
            if research_session.status in {
                ResearchSessionStatus.COMPLETED,
                ResearchSessionStatus.FAILED,
            }:
                raise ValueError("research session is not executable")
            if research_session.status is ResearchSessionStatus.CREATED:
                research_session = research_session.start()
                repositories.research_sessions.update(research_session)

        url = f"{research_session.target.base_url.rstrip('/')}{path}"
        research_session.scope.validate_url(url)
        request_id = f"REQ-{uuid4()}"
        research_log.info(
            "observation started session_id=%s request_id=%s method=%s url=%s",
            research_session.id,
            request_id,
            method.value,
            url,
        )
        executor_request = ExecutorRequest(
            request_id=request_id,
            method=method,
            url=url,
            headers=headers or {},
            timeout_ms=timeout_ms,
            max_response_bytes=max_response_bytes,
            follow_redirects=follow_redirects,
        )
        execution = await self.executor.execute(executor_request)
        result = execution.result
        provenance_metadata = {
            "research_session_id": str(research_session.id),
            "request_id": request_id,
            "executor": execution.executor,
            "executor_version": execution.executor_version,
            "protocol_version": execution.protocol_version,
            "evidence_sha256": result.evidence_sha256,
        }
        if experiment_id is not None:
            provenance_metadata["experiment_id"] = str(experiment_id)
        if experiment_role is not None:
            provenance_metadata["experiment_role"] = experiment_role.value
        if identity_name is not None:
            provenance_metadata["identity"] = {
                "name": identity_name,
                "roles": identity_roles or [],
            }
        evidence = Evidence(
            experiment_id=experiment_id,
            experiment_role=experiment_role,
            research_session_id=research_session.id,
            request_id=request_id,
            request=HTTPRequestRecord(
                method=method.value,
                url=url,
                headers=executor_request.headers,
            ),
            response=HTTPResponseRecord(
                status_code=result.status_code,
                headers=result.headers,
                body=result.body,
                body_base64=result.body_base64,
                body_bytes=result.body_bytes,
                effective_url=result.effective_url,
                elapsed_ms=result.elapsed_ms,
                truncated=result.truncated,
            ),
            executor=execution.executor,
            executor_version=execution.executor_version,
            protocol_version=execution.protocol_version,
            provenance=Provenance(
                source_type="http",
                source_reference=url,
                collector=execution.executor,
                classification=FactClassification.OBSERVED,
                metadata=provenance_metadata,
            ),
            integrity_hash=result.evidence_sha256,
        )
        observation = Observation(
            asset_id=research_session.target.asset_id,
            research_session_id=research_session.id,
            request_id=request_id,
            evidence_id=evidence.id,
            source=ObservationSource.HTTP,
            raw_data={
                "status_code": result.status_code,
                "headers": result.headers,
                "body_base64": result.body_base64,
                "body_bytes": result.body_bytes,
                "truncated": result.truncated,
            },
            normalized_data=self.normalizer.normalize(result),
            trust=TrustClassification.UNTRUSTED,
            normalized_data_trust=TrustClassification.TRUSTED,
            provenance=Provenance(
                source_type="http",
                source_reference=str(evidence.id),
                collector="aegis-python-normalizer",
                classification=FactClassification.OBSERVED,
                metadata={**provenance_metadata, "evidence_id": str(evidence.id)},
            ),
        )
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            repositories.evidence.add(evidence)
            repositories.observations.add(observation)
        storage_log.info(
            "observation persisted session_id=%s request_id=%s evidence_id=%s observation_id=%s",
            research_session.id,
            request_id,
            evidence.id,
            observation.id,
        )
        return ObservationResult(evidence=evidence, observation=observation)
