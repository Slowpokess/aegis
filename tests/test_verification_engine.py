import base64
import json
from dataclasses import dataclass
from uuid import uuid4

from app.domain.common import FactClassification, Provenance, TrustClassification, utc_now
from app.domain.evidence import Evidence, HTTPRequestRecord, HTTPResponseRecord
from app.domain.experiments import (
    Experiment,
    ExperimentExecution,
    ExperimentExecutionStatus,
    ExperimentRole,
    ExperimentStatus,
    HTTPExperimentAction,
)
from app.domain.hypotheses import Hypothesis, HypothesisStatus
from app.domain.observations import Observation, ObservationSource
from app.domain.verification import (
    ComparisonOperator,
    ComparisonSpec,
    ComparisonType,
    VerificationSpec,
    VerificationVerdict,
)
from app.execution.protocol import canonical_evidence_sha256
from app.storage.database import Database
from app.storage.repositories import RepositorySet
from app.verification.verifier import VerificationEngine
from tests.integration.test_hypothesis_engine import store_dataset


@dataclass
class Dataset:
    hypothesis: Hypothesis
    experiment: Experiment
    execution: ExperimentExecution


def _captured(
    research,
    experiment,
    role,
    identity,
    body,
    *,
    status=200,
    integrity_valid=True,
):
    raw = json.dumps(body, sort_keys=True)
    encoded = raw.encode()
    headers = {"Authorization": f"Bearer {identity}-token"}
    response_headers = {"content-type": "application/json"}
    digest = canonical_evidence_sha256(
        method="GET",
        url="http://127.0.0.1:8001/api/orders/101",
        request_headers=headers,
        status_code=status,
        response_headers=response_headers,
        body=encoded,
    )
    evidence = Evidence(
        research_session_id=research.id,
        experiment_id=experiment.id,
        experiment_role=role,
        request_id=f"REQ-{role.value}",
        request=HTTPRequestRecord(
            method="GET",
            url="http://127.0.0.1:8001/api/orders/101",
            headers=headers,
        ),
        response=HTTPResponseRecord(
            status_code=status,
            headers=response_headers,
            body=raw,
            body_base64=base64.b64encode(encoded).decode(),
            body_bytes=len(encoded),
            elapsed_ms=1,
        ),
        executor="aegis-executor",
        executor_version="0.2.0",
        protocol_version=1,
        integrity_hash=digest if integrity_valid else "f" * 64,
        provenance=Provenance(source_type="http", source_reference=role.value),
    )
    observation = Observation(
        asset_id=research.target.asset_id,
        research_session_id=research.id,
        request_id=evidence.request_id,
        evidence_id=evidence.id,
        source=ObservationSource.HTTP,
        raw_data={"body_bytes": len(encoded)},
        normalized_data={"status_code": status, "is_json": True},
        trust=TrustClassification.UNTRUSTED,
        provenance=Provenance(source_type="http", source_reference=str(evidence.id)),
    )
    return evidence, observation


def verification_spec() -> VerificationSpec:
    return VerificationSpec(
        rule_id="http-json-resource-access",
        rule_version="v1",
        comparisons=[
            ComparisonSpec(
                type=ComparisonType.STATUS_CODE,
                operator=ComparisonOperator.EQUAL,
            ),
            ComparisonSpec(
                type=ComparisonType.JSON_FIELD_VALUE,
                field="id",
                operator=ComparisonOperator.EQUAL,
                impact=True,
            ),
        ],
    )


def store_verification_dataset(
    database: Database,
    *,
    candidate_body=None,
    control_body=None,
    candidate_status=200,
    control_status=200,
    spec=True,
    integrity_valid=True,
    execution_status=ExperimentExecutionStatus.EXECUTED,
) -> Dataset:
    research, initial_observation, initial_evidence = store_dataset(database)
    hypothesis = Hypothesis(
        research_session_id=research.id,
        title="Possible object authorization inconsistency",
        description="Compare access to one resource.",
        observation_ids=[initial_observation.id],
        evidence_ids=[initial_evidence.id],
        confidence=0.8,
        status=HypothesisStatus.TESTING,
        provenance=Provenance(
            source_type="llm",
            source_reference="test",
            classification=FactClassification.INFERRED,
        ),
    )
    action = HTTPExperimentAction(method="GET", path="/api/orders/101", identity="bob")
    experiment = Experiment(
        research_session_id=research.id,
        hypothesis_id=hypothesis.id,
        description="Owner/non-owner comparison",
        changed_variable="identity",
        candidate=action,
        control=action.model_copy(update={"identity": "alice"}),
        expected_if_true="same object returned",
        expected_if_false="candidate denied",
        status=ExperimentStatus.EXECUTED,
        verification_spec=verification_spec() if spec else None,
        provenance=hypothesis.provenance,
    )
    candidate, candidate_obs = _captured(
        research,
        experiment,
        ExperimentRole.CANDIDATE,
        "bob",
        candidate_body or {"id": 101, "owner": "alice"},
        status=candidate_status,
        integrity_valid=integrity_valid,
    )
    control, control_obs = _captured(
        research,
        experiment,
        ExperimentRole.CONTROL,
        "alice",
        control_body or {"id": 101, "owner": "alice"},
        status=control_status,
    )
    execution = ExperimentExecution(
        experiment_id=experiment.id,
        research_session_id=research.id,
        status=execution_status,
        finished_at=utc_now(),
        candidate_evidence_id=candidate.id if execution_status is ExperimentExecutionStatus.EXECUTED else None,
        candidate_observation_id=candidate_obs.id if execution_status is ExperimentExecutionStatus.EXECUTED else None,
        control_evidence_id=control.id if execution_status is ExperimentExecutionStatus.EXECUTED else None,
        control_observation_id=control_obs.id if execution_status is ExperimentExecutionStatus.EXECUTED else None,
        provenance=hypothesis.provenance,
    )
    with database.session_factory.begin() as session:
        repositories = RepositorySet(session)
        repositories.hypotheses.add(hypothesis)
        repositories.experiments.add(experiment)
        repositories.evidence.add(candidate)
        repositories.evidence.add(control)
        repositories.observations.add(candidate_obs)
        repositories.observations.add(control_obs)
        repositories.experiment_executions.add(execution)
    return Dataset(hypothesis, experiment, execution)


def test_supported_creates_finding_and_persists_lineage(database: Database) -> None:
    dataset = store_verification_dataset(database)
    result = VerificationEngine(database).verify_execution(dataset.execution.id)
    assert result.verification.verdict is VerificationVerdict.SUPPORTED
    assert result.verification.evidence_integrity_valid
    assert result.finding is not None
    assert result.finding.verification_status.value == "SUPPORTED"
    with database.session_factory() as session:
        repositories = RepositorySet(session)
        assert repositories.verification_results.get(result.verification.id) == result.verification
        assert repositories.findings.get(result.finding.id) == result.finding
        assert repositories.hypotheses.get(dataset.hypothesis.id).status is HypothesisStatus.SUPPORTED


def test_contradiction_rejects_without_finding(database: Database) -> None:
    dataset = store_verification_dataset(
        database, candidate_body={"id": 999}, candidate_status=403
    )
    result = VerificationEngine(database).verify_execution(dataset.execution.id)
    assert result.verification.verdict is VerificationVerdict.REJECTED
    assert result.finding is None


def test_missing_spec_failed_execution_and_hash_mismatch_are_inconclusive(database: Database) -> None:
    for kwargs in ({"spec": False}, {"integrity_valid": False}, {"execution_status": ExperimentExecutionStatus.FAILED}):
        dataset = store_verification_dataset(database, **kwargs)
        result = VerificationEngine(database).verify_execution(dataset.execution.id)
        assert result.verification.verdict is VerificationVerdict.INCONCLUSIVE
        assert result.finding is None


def test_missing_lineage_wrong_role_cross_session_and_truncation_are_inconclusive(
    database: Database,
) -> None:
    datasets = [store_verification_dataset(database) for _ in range(4)]
    with database.session_factory.begin() as session:
        repositories = RepositorySet(session)
        missing = datasets[0]
        repositories.experiment_executions.update(
            missing.execution.model_copy(update={"candidate_evidence_id": uuid4()})
        )

        wrong_role = datasets[1]
        candidate = repositories.evidence.get(wrong_role.execution.candidate_evidence_id)
        repositories.evidence.update(
            candidate.model_copy(update={"experiment_role": ExperimentRole.CONTROL})
        )

        cross_session = datasets[2]
        candidate = repositories.evidence.get(cross_session.execution.candidate_evidence_id)
        repositories.evidence.update(
            candidate.model_copy(
                update={
                    "research_session_id": datasets[3].experiment.research_session_id,
                    "request_id": "REQ-CROSS-SESSION",
                }
            )
        )

        truncated = datasets[3]
        candidate = repositories.evidence.get(truncated.execution.candidate_evidence_id)
        repositories.evidence.update(
            candidate.model_copy(
                update={
                    "response": candidate.response.model_copy(update={"truncated": True})
                }
            )
        )

    engine = VerificationEngine(database)
    for dataset in datasets:
        result = engine.verify_execution(dataset.execution.id)
        assert result.verification.verdict is VerificationVerdict.INCONCLUSIVE
        assert result.finding is None


def test_repeat_aggregation_and_disputed_finding_history(database: Database) -> None:
    dataset = store_verification_dataset(database)
    engine = VerificationEngine(database, min_verification_runs=2)
    first = engine.verify_execution(dataset.execution.id)
    assert first.finding is None
    with database.session_factory() as session:
        repositories = RepositorySet(session)
        original = repositories.experiment_executions.get(dataset.execution.id)
    repeated = original.model_copy(update={"id": None})
    repeated = ExperimentExecution.model_validate(
        {**repeated.model_dump(mode="python", exclude={"id"})}
    )
    with database.session_factory.begin() as session:
        RepositorySet(session).experiment_executions.add(repeated)
    supported = engine.verify_execution(repeated.id)
    assert supported.finding is not None
    assert engine.aggregate_experiment(dataset.experiment.id).reproduction_count == 2

    # Preserve the same runtime lineage but verify a deliberately contradictory typed rule.
    with database.session_factory.begin() as session:
        repositories = RepositorySet(session)
        experiment = repositories.experiments.get(dataset.experiment.id)
        contradictory = verification_spec().model_copy(
            update={
                "comparisons": [
                    ComparisonSpec(
                        type=ComparisonType.JSON_FIELD_VALUE,
                        field="id",
                        operator=ComparisonOperator.NOT_EQUAL,
                        impact=True,
                    )
                ]
            }
        )
        repositories.experiments.update(experiment.model_copy(update={"verification_spec": contradictory}))
        third = ExperimentExecution.model_validate(
            {**dataset.execution.model_dump(mode="python", exclude={"id"})}
        )
        repositories.experiment_executions.add(third)
    engine.verify_execution(third.id)
    aggregate = engine.aggregate_experiment(dataset.experiment.id)
    assert aggregate.verdict is VerificationVerdict.INCONCLUSIVE
    assert aggregate.finding is not None
    assert aggregate.finding.verification_status.value == "INCONCLUSIVE"


def test_verification_code_has_no_ground_truth_dependency() -> None:
    from pathlib import Path

    source = "\n".join(
        path.read_text(encoding="utf-8")
        for root in (Path("app/verification"), Path("app/domain"), Path("app/storage"))
        for path in root.rglob("*.py")
    )
    assert "lab.ground_truth" not in source
    assert "lab/scenarios" not in source
