from pathlib import Path
from uuid import uuid4

import pytest

from app.domain.assets import Asset, AssetKind
from app.domain.common import FactClassification, Provenance, TrustClassification
from app.domain.evidence import Evidence, HTTPRequestRecord, HTTPResponseRecord
from app.domain.hypotheses import HypothesisStatus
from app.domain.llm_runs import LLMRunStatus
from app.domain.observations import Observation, ObservationSource
from app.domain.research import ResearchSession, ResearchTarget, TargetScope
from app.llm.base import LLMProviderError, LLMProviderErrorCode, LLMRole
from app.llm.providers.fake import FakeLLMProvider
from app.reasoning.hypotheses import HypothesisEngine
from app.storage.database import Database
from app.storage.repositories import RepositorySet


def store_dataset(database: Database) -> tuple[ResearchSession, Observation, Evidence]:
    provenance = Provenance(source_type="configuration", source_reference="phase3-integration")
    asset = Asset(name="lab", kind=AssetKind.API, provenance=provenance)
    scope = TargetScope(
        hosts=("127.0.0.1",), ports=(8001,), schemes=("http",), provenance=provenance
    )
    target = ResearchTarget(
        asset_id=asset.id,
        name="lab",
        base_url="http://127.0.0.1:8001",
        provenance=provenance,
    )
    research = ResearchSession(name="phase3", target=target, scope=scope, provenance=provenance)
    evidence = Evidence(
        research_session_id=research.id,
        request_id="REQ-PHASE3",
        request=HTTPRequestRecord(
            method="GET",
            url="http://127.0.0.1:8001/api/orders/101",
            headers={"Authorization": "Bearer bob-token"},
        ),
        response=HTTPResponseRecord(
            status_code=200,
            headers={"content-type": "application/json"},
            body='{"id":101,"owner":"alice"}',
            body_bytes=26,
            elapsed_ms=1,
        ),
        executor="aegis-executor",
        executor_version="0.2.0",
        protocol_version=1,
        integrity_hash="a" * 64,
        provenance=provenance,
    )
    observation = Observation(
        asset_id=asset.id,
        research_session_id=research.id,
        request_id=evidence.request_id,
        evidence_id=evidence.id,
        source=ObservationSource.HTTP,
        raw_data={"body_bytes": 26},
        normalized_data={
            "content_type": "application/json",
            "redirect_location": None,
            "is_json": True,
            "json_top_level_type": "object",
        },
        trust=TrustClassification.UNTRUSTED,
        provenance=Provenance(
            source_type="http",
            source_reference=str(evidence.id),
            metadata={"identity": {"name": "bob", "roles": ["user"]}},
        ),
    )
    with database.session_factory.begin() as session:
        repositories = RepositorySet(session)
        repositories.assets.add(asset)
        repositories.research_sessions.add(research)
        repositories.evidence.add(evidence)
        repositories.observations.add(observation)
    return research, observation, evidence


def proposal(observation: Observation, evidence: Evidence) -> dict[str, object]:
    return {
        "title": "Possible object authorization behavior",
        "description": "The /api/orders/101 response may warrant an ownership comparison.",
        "observation_ids": [str(observation.id)],
        "evidence_ids": [str(evidence.id)],
        "assumptions": ["The order identifier is stable across identities."],
        "missing_information": [
            {
                "description": "Need an observation using the resource owner identity.",
                "related_observation_ids": [str(observation.id)],
            }
        ],
        "confidence": 0.63,
    }


@pytest.mark.asyncio
async def test_observations_to_fake_provider_to_validated_persistent_hypothesis(
    database: Database,
) -> None:
    research, observation, evidence = store_dataset(database)
    valid = proposal(observation, evidence)
    duplicate = {**valid, "title": " POSSIBLE object authorization behavior "}
    hallucinated = {**valid, "observation_ids": [str(uuid4())], "confidence": 0.99}
    provider = FakeLLMProvider(
        [{"hypotheses": [valid, duplicate, hallucinated]}],
        input_tokens=101,
        output_tokens=37,
    )

    result = await HypothesisEngine(database, provider).generate(research.id)

    assert result.context_observation_count == 1
    assert result.llm_run.status is LLMRunStatus.COMPLETED
    assert result.llm_run.generated_count == 3
    assert result.llm_run.accepted_count == 1
    assert result.llm_run.rejected_count == 2
    assert result.llm_run.total_tokens == 138
    hypothesis = result.hypotheses[0]
    assert hypothesis.status is HypothesisStatus.NEW
    assert hypothesis.provenance.classification is FactClassification.INFERRED
    assert hypothesis.observation_ids == [observation.id]
    assert hypothesis.evidence_ids == [evidence.id]
    assert hypothesis.llm_run_id == result.llm_run.id
    assert provider.requests[0][0][0].role is LLMRole.SYSTEM
    assert "bob-token" not in provider.requests[0][1].context_sha256
    user_message = provider.requests[0][0][1].content
    assert "bob-token" not in user_message
    assert "<redacted>" in user_message
    assert "UNTRUSTED TARGET DATA" in user_message

    with database.session_factory() as session:
        repositories = RepositorySet(session)
        assert repositories.llm_runs.get(result.llm_run.id) == result.llm_run
        assert repositories.hypotheses.list_by_session(research.id) == [hypothesis]
        assert repositories.evidence.get(evidence.id) == evidence
        assert repositories.observations.get(observation.id) == observation


@pytest.mark.asyncio
async def test_provider_failure_persists_typed_failed_llm_run(database: Database) -> None:
    research, _, _ = store_dataset(database)
    provider = FakeLLMProvider(
        [LLMProviderError(LLMProviderErrorCode.TIMEOUT, "timeout", attempts=2)]
    )

    with pytest.raises(LLMProviderError):
        await HypothesisEngine(database, provider).generate(research.id)

    with database.session_factory() as session:
        runs = RepositorySet(session).llm_runs.list_by_session(research.id)
    assert len(runs) == 1
    assert runs[0].status is LLMRunStatus.FAILED
    assert runs[0].error_code == "TIMEOUT"
    assert runs[0].attempts == 2
    assert runs[0].latency_ms is not None


def test_reasoning_layers_have_no_executor_or_ground_truth_dependency() -> None:
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for root in (Path("app/reasoning"), Path("app/llm"))
        for path in root.rglob("*.py")
    )
    assert "lab.ground_truth" not in source
    assert "lab/scenarios" not in source
    assert "RustExecutorClient" not in source
