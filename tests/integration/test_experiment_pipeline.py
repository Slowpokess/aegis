import base64
import asyncio
import json
from pathlib import Path

import pytest

from typer.testing import CliRunner

from app.collectors.pipeline import ObservationPipeline
from app.cli.main import cli
from app.config import Settings
from app.domain.experiments import ExperimentExecutionStatus, ExperimentRole, ExperimentStatus
from app.domain.common import FactClassification
from app.domain.hypotheses import Hypothesis, HypothesisStatus, MissingInformation
from app.execution.experiments import ExperimentRunner
from app.execution.protocol import canonical_evidence_sha256
from app.execution.rust_executor import RustExecutorClient
from app.execution.rust_policy import RustPolicyClient
from app.execution.rust_policy import PolicyClientError
from app.llm.providers.fake import FakeLLMProvider
from app.reasoning.experiments import ExperimentEngine
from app.storage.database import Database
from app.storage.repositories import RepositorySet
from tests.integration.test_hypothesis_engine import store_dataset


def experiment_proposal(path: str = "/api/orders/101", headers: dict[str, str] | None = None):
    return {
        "description": "Compare owner and non-owner access to one observed resource",
        "changed_variable": "identity",
        "constants": ["GET", path],
        "preconditions": ["both identities are valid laboratory identities"],
        "candidate": {
            "type": "http",
            "method": "GET",
            "path": path,
            "identity": "bob",
            "headers": headers or {},
            "follow_redirects": False,
            "timeout_ms": 5000,
            "max_response_bytes": 100000,
        },
        "control": {
            "type": "http",
            "method": "GET",
            "path": path,
            "identity": "alice",
            "headers": {},
            "follow_redirects": False,
            "timeout_ms": 5000,
            "max_response_bytes": 100000,
        },
        "expected_if_true": "both identities receive the same object",
        "expected_if_false": "the non-owner is denied",
        "risk": "LOW",
    }


def add_hypothesis(database: Database, research, observation, evidence) -> Hypothesis:
    hypothesis = Hypothesis(
        research_session_id=research.id,
        title="Possible ownership authorization inconsistency",
        description="Observed object access requires an owner/non-owner control.",
        observation_ids=[observation.id],
        evidence_ids=[evidence.id],
        assumptions=["object identity remains stable"],
        missing_information=[
            MissingInformation(
                description="Need owner comparison at /api/orders/101",
                related_observation_ids=[observation.id],
            )
        ],
        confidence=0.63,
        provenance=observation.provenance.model_copy(
            update={"classification": FactClassification.INFERRED}
        ),
    )
    with database.session_factory.begin() as session:
        RepositorySet(session).hypotheses.add(hypothesis)
    return hypothesis


@pytest.mark.asyncio
async def test_generation_persistence_and_protected_credential_rejection(database: Database) -> None:
    research, observation, evidence = store_dataset(database)
    hypothesis = add_hypothesis(database, research, observation, evidence)
    valid = await ExperimentEngine(
        database, FakeLLMProvider([experiment_proposal()], model="fake-experiment-v1")
    ).generate(hypothesis.id)
    assert valid.experiment.status is ExperimentStatus.VALIDATED
    assert valid.llm_run.purpose.value == "EXPERIMENT_GENERATION"

    injected = await ExperimentEngine(
        database,
        FakeLLMProvider(
            [experiment_proposal(headers={"Authorization": "Bearer attacker-controlled"})]
        ),
    ).generate(hypothesis.id)
    assert injected.experiment.status is ExperimentStatus.DRAFT
    assert injected.validation.errors[0]["code"] == "HEADER_NOT_ALLOWED"
    with database.session_factory() as session:
        assert len(RepositorySet(session).experiments.list_by_session(research.id)) == 2


@pytest.mark.asyncio
async def test_out_of_scope_proposal_never_reaches_executor(database: Database) -> None:
    research, observation, evidence = store_dataset(database)
    hypothesis = add_hypothesis(database, research, observation, evidence)
    generated = await ExperimentEngine(
        database,
        FakeLLMProvider([experiment_proposal(path="https://outside.invalid/api/orders/101")]),
    ).generate(hypothesis.id)

    class ExecutorMustNotRun:
        calls = 0

        async def execute(self, request):  # pragma: no cover - a failure sentinel
            self.calls += 1
            raise AssertionError("executor was invoked for rejected experiment")

    sentinel = ExecutorMustNotRun()
    settings = Settings(database_url="sqlite://")
    runner = ExperimentRunner(
        database,
        RustPolicyClient(Path("native/rust/target/debug/aegis-policy")),
        ObservationPipeline(database, sentinel),  # type: ignore[arg-type]
        settings,
    )
    assert generated.experiment.status is ExperimentStatus.DRAFT
    with pytest.raises(ValueError, match="DRAFT"):
        await runner.run(generated.experiment.id)
    assert sentinel.calls == 0


@pytest.mark.asyncio
async def test_policy_unavailable_and_rate_limit_are_fail_closed(database: Database) -> None:
    research, observation, evidence = store_dataset(database)
    hypothesis = add_hypothesis(database, research, observation, evidence)
    generated = await ExperimentEngine(
        database, FakeLLMProvider([experiment_proposal()])
    ).generate(hypothesis.id)

    class ExecutorMustNotRun:
        calls = 0

        async def execute(self, request):
            self.calls += 1
            raise AssertionError("executor must remain behind policy")

    sentinel = ExecutorMustNotRun()
    missing_policy_runner = ExperimentRunner(
        database,
        RustPolicyClient(Path("/nonexistent/aegis-policy")),
        ObservationPipeline(database, sentinel),  # type: ignore[arg-type]
        Settings(database_url="sqlite://"),
    )
    with pytest.raises(PolicyClientError):
        await missing_policy_runner.run(generated.experiment.id)
    assert sentinel.calls == 0

    rate_limited_runner = ExperimentRunner(
        database,
        RustPolicyClient(Path("native/rust/target/debug/aegis-policy")),
        ObservationPipeline(database, sentinel),  # type: ignore[arg-type]
        Settings(database_url="sqlite://", policy_max_requests_per_minute=1),
    )
    result = await rate_limited_runner.run(generated.experiment.id)
    assert result.execution.status is ExperimentExecutionStatus.POLICY_REJECTED
    assert result.execution.error_code == "RATE_LIMIT_EXCEEDED"
    assert sentinel.calls == 0


@pytest.mark.asyncio
async def test_hypothesis_experiment_policy_executor_lab_lineage(
    database: Database, live_lab: int, monkeypatch
) -> None:
    research, observation, evidence = store_dataset(database)
    # Point this test's immutable target at its local fixture while preserving the dataset lineage.
    scoped = research.model_copy(
        update={
            "target": research.target.model_copy(
                update={"base_url": f"http://127.0.0.1:{live_lab}"}
            ),
            "scope": research.scope.model_copy(update={"ports": (live_lab,)}),
        }
    )
    with database.session_factory.begin() as session:
        RepositorySet(session).research_sessions.update(scoped)
    hypothesis = add_hypothesis(database, scoped, observation, evidence)
    generated = await ExperimentEngine(
        database, FakeLLMProvider([experiment_proposal()], model="fake-experiment-v1")
    ).generate(hypothesis.id)
    settings = Settings(
        database_url="sqlite://",
        executor_path=Path("native/rust/target/debug/aegis-executor"),
        policy_path=Path("native/rust/target/debug/aegis-policy"),
    )
    runner = ExperimentRunner(
        database,
        RustPolicyClient(settings.policy_path),
        ObservationPipeline(database, RustExecutorClient(settings.executor_path)),
        settings,
    )
    checked = await runner.check(generated.experiment.id)
    assert checked.allowed
    with database.session_factory() as session:
        assert RepositorySet(session).experiment_executions.list_by_experiment(
            generated.experiment.id
        ) == []

    first = await runner.run(generated.experiment.id)
    second = await runner.run(generated.experiment.id)
    assert first.execution.status is ExperimentExecutionStatus.EXECUTED
    assert second.execution.status is ExperimentExecutionStatus.EXECUTED
    assert first.control is not None and first.candidate is not None
    assert first.control.evidence.experiment_role is ExperimentRole.CONTROL
    assert first.candidate.evidence.experiment_role is ExperimentRole.CANDIDATE
    assert first.control.evidence.response.status_code == 200
    assert first.candidate.evidence.response.status_code == 200
    assert first.control.evidence.id != second.control.evidence.id  # type: ignore[union-attr]
    for result in (first.control, first.candidate):
        body = base64.b64decode(result.evidence.response.body_base64 or "")
        assert canonical_evidence_sha256(
            method=result.evidence.request.method,
            url=result.evidence.request.url,
            request_headers=result.evidence.request.headers,
            status_code=result.evidence.response.status_code,
            response_headers=result.evidence.response.headers,
            body=body,
        ) == result.evidence.integrity_hash
    with database.session_factory() as session:
        repositories = RepositorySet(session)
        assert len(repositories.experiment_executions.list_by_experiment(generated.experiment.id)) == 2
        assert repositories.hypotheses.get(hypothesis.id).status is HypothesisStatus.TESTING  # type: ignore[union-attr]
        assert repositories.experiments.get(generated.experiment.id).status is ExperimentStatus.EXECUTED  # type: ignore[union-attr]

    from app.config import get_settings

    monkeypatch.setenv("AEGIS_DATABASE_URL", str(database.engine.url))
    monkeypatch.setenv("AEGIS_EXECUTOR_PATH", str(settings.executor_path))
    monkeypatch.setenv("AEGIS_POLICY_PATH", str(settings.policy_path))
    get_settings.cache_clear()
    cli_run = await asyncio.to_thread(
        CliRunner().invoke, cli, ["experiments", "run", str(generated.experiment.id)]
    )
    assert cli_run.exit_code == 0, cli_run.output
    assert json.loads(cli_run.output)["execution"]["status"] == "EXECUTED"
    with database.session_factory() as session:
        assert len(
            RepositorySet(session).experiment_executions.list_by_experiment(
                generated.experiment.id
            )
        ) == 3
    get_settings.cache_clear()
