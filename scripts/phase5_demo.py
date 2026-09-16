"""Phase 5 deterministic verification demonstration against localhost only."""

import argparse
import asyncio
import base64
import json
from pathlib import Path

from app.collectors.pipeline import ObservationPipeline
from app.config import Settings
from app.domain.assets import Asset, AssetKind
from app.domain.common import Provenance, utc_now
from app.domain.experiments import ExperimentExecution, ExperimentExecutionStatus
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
from app.verification.verifier import VerificationEngine


def verification_spec(*, field: str | None = None) -> dict[str, object]:
    comparisons: list[dict[str, object]] = []
    if field:
        comparisons.append(
            {
                "type": "JSON_FIELD_VALUE",
                "operator": "EQUAL",
                "field": field,
                "required": True,
                "impact": True,
            }
        )
        if field == "id":
            comparisons.append(
                {
                    "type": "JSON_FIELD_VALUE",
                    "operator": "EQUAL",
                    "field": "owner",
                    "required": True,
                    "impact": True,
                }
            )
    else:
        comparisons.append(
            {
            "type": "NORMALIZED_JSON",
            "operator": "EQUAL",
            "required": True,
            "impact": True,
            }
        )
    return {
        "rule_id": "http-candidate-control",
        "rule_version": "v1",
        "comparisons": [
            {
                "type": "STATUS_CODE",
                "operator": "EQUAL",
                "required": True,
                "impact": False,
            },
            *comparisons,
        ],
    }


async def create_case(
    *,
    database: Database,
    pipeline: ObservationPipeline,
    runner: ExperimentRunner,
    verifier: VerificationEngine,
    research: ResearchSession,
    path: str,
    candidate_identity: str,
    control_identity: str,
    impact_field: str | None = None,
    runs: int = 1,
) -> tuple[object, object, list[object], object]:
    resolver = LaboratoryIdentityResolver()
    identity = resolver.resolve(candidate_identity)
    seed = await pipeline.observe(
        research_session_id=research.id,
        path=path,
        headers=identity.headers,
        identity_name=identity.name,
        identity_roles=list(identity.roles),
    )
    hypothesis_response = {
        "hypotheses": [
            {
                "title": f"Possible access-control behavior at {path}",
                "description": "A candidate/control comparison is required.",
                "observation_ids": [str(seed.observation.id)],
                "evidence_ids": [str(seed.evidence.id)],
                "assumptions": ["The same target resource is used in both requests."],
                "missing_information": [
                    {
                        "description": f"Need control identity observation at {path}",
                        "related_observation_ids": [str(seed.observation.id)],
                    }
                ],
                "confidence": 0.6,
            }
        ]
    }
    hypothesis = (
        await HypothesisEngine(
            database,
            FakeLLMProvider([hypothesis_response], model="fake-hypothesis-v1"),
        ).generate(research.id)
    ).hypotheses[0]
    experiment_response = {
        "description": "Compare the same resource under candidate and control identities",
        "changed_variable": "identity",
        "constants": ["method", "path"],
        "preconditions": ["logical identities are configured by the control plane"],
        "candidate": {"method": "GET", "path": path, "identity": candidate_identity},
        "control": {"method": "GET", "path": path, "identity": control_identity},
        "expected_if_true": "the declared candidate/control relation matches",
        "expected_if_false": "the declared relation does not match",
        "risk": "LOW",
        "verification_spec": verification_spec(field=impact_field),
    }
    experiment = (
        await ExperimentEngine(
            database,
            FakeLLMProvider([experiment_response], model="fake-experiment-v2"),
        ).generate(hypothesis.id)
    ).experiment
    executions = []
    for _ in range(runs):
        executed = await runner.run(experiment.id)
        executions.append(executed)
        verifier.verify_execution(executed.execution.id)
    aggregate = verifier.aggregate_experiment(experiment.id)
    return hypothesis, experiment, executions, aggregate


async def run(database_path: Path) -> dict[str, object]:
    if database_path.exists():
        raise RuntimeError("demo database must not already exist")
    database = Database(f"sqlite:///{database_path}")
    database.create_schema()
    provenance = Provenance(source_type="configuration", source_reference="phase5-demo")
    asset = Asset(name="phase5-lab", kind=AssetKind.API, provenance=provenance)
    research = ResearchSession(
        name="phase5-demo",
        target=ResearchTarget(
            asset_id=asset.id,
            name="phase5-lab",
            base_url="http://127.0.0.1:8001",
            provenance=provenance,
        ),
        scope=TargetScope(
            hosts=("127.0.0.1",),
            ports=(8001,),
            schemes=("http",),
            provenance=provenance,
        ),
        provenance=provenance,
    )
    with database.session_factory.begin() as session:
        repositories = RepositorySet(session)
        repositories.assets.add(asset)
        repositories.research_sessions.add(research)
    settings = Settings(database_url=f"sqlite:///{database_path}")
    pipeline = ObservationPipeline(database, RustExecutorClient(settings.executor_path))
    runner = ExperimentRunner(
        database,
        RustPolicyClient(settings.policy_path),
        pipeline,
        settings,
    )
    verifier = VerificationEngine(database)

    supported = await create_case(
        database=database,
        pipeline=pipeline,
        runner=runner,
        verifier=verifier,
        research=research,
        path="/api/orders/101",
        candidate_identity="bob",
        control_identity="alice",
        impact_field="id",
        runs=2,
    )
    false_positive = await create_case(
        database=database,
        pipeline=pipeline,
        runner=runner,
        verifier=verifier,
        research=research,
        path="/api/orders/101/receipt",
        candidate_identity="bob",
        control_identity="alice",
    )
    role_boundary = await create_case(
        database=database,
        pipeline=pipeline,
        runner=runner,
        verifier=verifier,
        research=research,
        path="/api/admin/stats",
        candidate_identity="alice",
        control_identity="admin",
    )

    # LAB-006-like: actual seed observation exists, but comparative execution is incomplete.
    resolver = LaboratoryIdentityResolver()
    alice = resolver.resolve("alice")
    insufficient_seed = await pipeline.observe(
        research_session_id=research.id,
        path="/api/account/settings/restricted",
        headers=alice.headers,
        identity_name=alice.name,
        identity_roles=list(alice.roles),
    )
    insufficient_hypothesis, insufficient_experiment, _, _ = await create_case(
        database=database,
        pipeline=pipeline,
        runner=runner,
        verifier=verifier,
        research=research,
        path="/api/account/settings/restricted",
        candidate_identity="alice",
        control_identity="admin",
    )
    incomplete = ExperimentExecution(
        experiment_id=insufficient_experiment.id,
        research_session_id=research.id,
        status=ExperimentExecutionStatus.FAILED,
        finished_at=utc_now(),
        error_code="MISSING_CONTROL_EVIDENCE",
        provenance=provenance,
    )
    with database.session_factory.begin() as session:
        RepositorySet(session).experiment_executions.add(incomplete)
    inconclusive = verifier.verify_execution(incomplete.id)

    supported_execution = supported[2][0]
    hashes = []
    for result in (supported_execution.candidate, supported_execution.control):
        evidence = result.evidence
        body = base64.b64decode(evidence.response.body_base64 or "")
        hashes.append(
            canonical_evidence_sha256(
                method=evidence.request.method,
                url=evidence.request.url,
                request_headers=evidence.request.headers,
                status_code=evidence.response.status_code,
                response_headers=evidence.response.headers,
                body=body,
            )
            == evidence.integrity_hash
        )
    with database.session_factory() as session:
        repositories = RepositorySet(session)
        supported_verification = repositories.verification_results.list_by_execution(
            supported_execution.execution.id
        )[-1]
        false_positive_verification = (
            repositories.verification_results.list_by_execution(
                false_positive[2][0].execution.id
            )[-1]
        )
        metrics = {
            "verification_runs": len(repositories.verification_results.list()),
            "supported": sum(
                item.verdict.value == "SUPPORTED"
                for item in repositories.verification_results.list()
            ),
            "rejected": sum(
                item.verdict.value == "REJECTED"
                for item in repositories.verification_results.list()
            ),
            "inconclusive": sum(
                item.verdict.value == "INCONCLUSIVE"
                for item in repositories.verification_results.list()
            ),
            "findings": len(repositories.findings.list_by_session(research.id)),
        }
    output = {
        "research_session_id": str(research.id),
        "supported": {
            "hypothesis_id": str(supported[0].id),
            "experiment_id": str(supported[1].id),
            "execution_ids": [str(item.execution.id) for item in supported[2]],
            "candidate_evidence_id": str(supported_execution.candidate.evidence.id),
            "control_evidence_id": str(supported_execution.control.evidence.id),
            "candidate_observation_id": str(supported_execution.candidate.observation.id),
            "control_observation_id": str(supported_execution.control.observation.id),
            "verdict": supported[3].verdict.value,
            "verification_result_id": str(supported_verification.id),
            "rule": (
                f"{supported_verification.rule_id}/"
                f"{supported_verification.rule_version}"
            ),
            "comparisons": [
                item.model_dump(mode="json")
                for item in supported_verification.comparisons
            ],
            "finding_id": str(supported[3].finding.id),
            "reproduction_count": supported[3].reproduction_count,
            "hashes_valid": all(hashes),
        },
        "false_positive": {
            "scenario": "LAB-005-like",
            "verdict": false_positive[3].verdict.value,
            "verification_result_id": str(false_positive_verification.id),
            "finding_created": false_positive[3].finding is not None,
        },
        "role_boundary": {
            "scenario": "LAB-007-like",
            "verdict": role_boundary[3].verdict.value,
            "finding_created": role_boundary[3].finding is not None,
        },
        "inconclusive": {
            "scenario": "LAB-006-like",
            "seed_observation_id": str(insufficient_seed.observation.id),
            "hypothesis_id": str(insufficient_hypothesis.id),
            "execution_id": str(incomplete.id),
            "verdict": inconclusive.verification.verdict.value,
            "verification_result_id": str(inconclusive.verification.id),
            "finding_created": inconclusive.finding is not None,
        },
        "metrics": metrics,
    }
    database.dispose()
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(asyncio.run(run(args.database)), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
