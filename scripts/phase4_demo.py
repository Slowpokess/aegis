"""Controlled Phase 4 demonstration against the localhost laboratory only."""

import argparse
import asyncio
import base64
import json
from pathlib import Path

from app.collectors.pipeline import ObservationPipeline
from app.config import Settings
from app.domain.assets import Asset, AssetKind
from app.domain.common import FactClassification, Provenance
from app.domain.research import ResearchSession, ResearchTarget, TargetScope
from app.execution.experiments import ExperimentRunner
from app.execution.identity import LaboratoryIdentityResolver
from app.execution.protocol import canonical_evidence_sha256
from app.execution.rust_executor import RustExecutorClient
from app.execution.rust_policy import RustPolicyClient
from app.llm.providers.fake import FakeLLMProvider
from app.reasoning.experiments import ExperimentEngine
from app.reasoning.hypotheses import HypothesisEngine
from app.storage.database import Database
from app.storage.repositories import RepositorySet


async def run(database_path: Path) -> dict[str, object]:
    if database_path.exists():
        raise RuntimeError("demo database must not already exist")
    database = Database(f"sqlite:///{database_path}")
    database.create_schema()
    provenance = Provenance(source_type="configuration", source_reference="phase4-demo")
    asset = Asset(name="phase4-lab", kind=AssetKind.API, provenance=provenance)
    scope = TargetScope(
        hosts=("127.0.0.1",), ports=(8001,), schemes=("http",), provenance=provenance
    )
    research = ResearchSession(
        name="phase4-demo",
        target=ResearchTarget(
            asset_id=asset.id,
            name="phase4-lab",
            base_url="http://127.0.0.1:8001",
            provenance=provenance,
        ),
        scope=scope,
        provenance=provenance,
    )
    with database.session_factory.begin() as session:
        repositories = RepositorySet(session)
        repositories.assets.add(asset)
        repositories.research_sessions.add(research)
    resolver = LaboratoryIdentityResolver()
    pipeline = ObservationPipeline(
        database,
        RustExecutorClient(Path("native/rust/target/debug/aegis-executor")),
    )
    observations = []
    for identity_name, path in (
        ("anonymous", "/health"),
        ("alice", "/api/profile"),
        ("bob", "/api/orders"),
        ("bob", "/api/orders/101"),
        ("alice", "/api/admin/stats"),
        ("admin", "/api/admin/stats"),
        ("anonymous", "/api/portal"),
    ):
        identity = resolver.resolve(identity_name)
        observations.append(
            await pipeline.observe(
                research_session_id=research.id,
                path=path,
                headers=identity.headers,
                identity_name=identity.name,
                identity_roles=list(identity.roles),
                follow_redirects=False,
            )
        )
    order_observation = observations[3]
    hypothesis_response = {
        "hypotheses": [
            {
                "title": "Possible ownership authorization inconsistency",
                "description": "The observed order response needs an owner identity control.",
                "observation_ids": [str(order_observation.observation.id)],
                "evidence_ids": [str(order_observation.evidence.id)],
                "assumptions": ["The resource path identifies the same object."],
                "missing_information": [
                    {
                        "description": "Need owner baseline at /api/orders/101",
                        "related_observation_ids": [str(order_observation.observation.id)],
                    }
                ],
                "confidence": 0.63,
            }
        ]
    }
    hypothesis_result = await HypothesisEngine(
        database, FakeLLMProvider([hypothesis_response], model="fake-hypothesis-v1")
    ).generate(research.id)
    hypothesis = hypothesis_result.hypotheses[0]
    experiment_response = {
        "description": "Compare the same observed resource across logical identities",
        "changed_variable": "identity",
        "constants": ["GET", "/api/orders/101"],
        "preconditions": ["both identities are configured laboratory identities"],
        "candidate": {"method": "GET", "path": "/api/orders/101", "identity": "bob"},
        "control": {"method": "GET", "path": "/api/orders/101", "identity": "alice"},
        "expected_if_true": "candidate and control return the same object representation",
        "expected_if_false": "candidate is denied while control succeeds",
        "risk": "LOW",
    }
    experiment_result = await ExperimentEngine(
        database, FakeLLMProvider([experiment_response], model="fake-experiment-v1")
    ).generate(hypothesis.id)
    settings = Settings(database_url=f"sqlite:///{database_path}")
    runner = ExperimentRunner(
        database,
        RustPolicyClient(settings.policy_path),
        pipeline,
        settings,
    )
    policy_check = await runner.check(experiment_result.experiment.id)
    execution = await runner.run(experiment_result.experiment.id)
    with database.session_factory() as session:
        repositories = RepositorySet(session)
        stored_evidence = repositories.evidence.list_by_session(research.id)
        stored_observations = repositories.observations.list_by_session(research.id)
        stored_experiment = repositories.experiments.get(experiment_result.experiment.id)
        stored_hypothesis = repositories.hypotheses.get(hypothesis.id)
    verified_hashes = 0
    for evidence in stored_evidence:
        body = base64.b64decode(evidence.response.body_base64 or "")
        if canonical_evidence_sha256(
            method=evidence.request.method,
            url=evidence.request.url,
            request_headers=evidence.request.headers,
            status_code=evidence.response.status_code,
            response_headers=evidence.response.headers,
            body=body,
        ) == evidence.integrity_hash:
            verified_hashes += 1
    output = {
        "research_session_id": str(research.id),
        "hypothesis_id": str(hypothesis.id),
        "hypothesis_status": stored_hypothesis.status.value,
        "experiment_id": str(experiment_result.experiment.id),
        "experiment_status": stored_experiment.status.value,
        "experiment_llm_run_id": str(experiment_result.llm_run.id),
        "prompt_version": experiment_result.llm_run.prompt_version,
        "candidate": experiment_result.experiment.candidate.model_dump(mode="json"),
        "control": experiment_result.experiment.control.model_dump(mode="json"),
        "candidate_policy": policy_check.candidate.reason_code.value,
        "control_policy": policy_check.control.reason_code.value,
        "execution_id": str(execution.execution.id),
        "execution_status": execution.execution.status.value,
        "candidate_evidence_id": str(execution.execution.candidate_evidence_id),
        "control_evidence_id": str(execution.execution.control_evidence_id),
        "candidate_observation_id": str(execution.execution.candidate_observation_id),
        "control_observation_id": str(execution.execution.control_observation_id),
        "evidence_count": len(stored_evidence),
        "observation_count": len(stored_observations),
        "hashes_verified": verified_hashes,
        "classification": FactClassification.INFERRED.value,
    }
    database.dispose()
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(asyncio.run(run(args.database)), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
