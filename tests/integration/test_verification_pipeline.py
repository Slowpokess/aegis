import asyncio
import json
from pathlib import Path

import pytest

from typer.testing import CliRunner

from app.cli.main import cli
from app.collectors.pipeline import ObservationPipeline
from app.config import Settings, get_settings
from app.domain.verification import VerificationVerdict
from app.execution.experiments import ExperimentRunner
from app.execution.rust_executor import RustExecutorClient
from app.execution.rust_policy import RustPolicyClient
from app.domain.operator import ApprovalMode, ResearchBudgetTemplate, ResearchPolicyProfile
from app.operator.reporting import ReportService
from app.operator.service import ProjectService
from app.llm.providers.fake import FakeLLMProvider
from app.reasoning.experiments import ExperimentEngine
from app.storage.database import Database
from app.storage.repositories import RepositorySet
from app.verification.verifier import VerificationEngine
from tests.integration.test_experiment_pipeline import (
    add_hypothesis,
    experiment_proposal,
)
from tests.integration.test_hypothesis_engine import store_dataset


def proposal_with_verification() -> dict[str, object]:
    return {
        **experiment_proposal(),
        "verification_spec": {
            "rule_id": "http-json-resource-access",
            "rule_version": "v1",
            "comparisons": [
                {
                    "type": "STATUS_CODE",
                    "operator": "EQUAL",
                    "required": True,
                    "impact": False,
                },
                {
                    "type": "JSON_FIELD_VALUE",
                    "operator": "EQUAL",
                    "field": "id",
                    "required": True,
                    "impact": True,
                },
                {
                    "type": "JSON_FIELD_VALUE",
                    "operator": "EQUAL",
                    "field": "owner",
                    "required": True,
                    "impact": True,
                },
            ],
        },
    }


@pytest.mark.asyncio
async def test_full_observation_hypothesis_experiment_execution_verification_finding(
    database: Database, live_lab: int, monkeypatch
) -> None:
    research, observation, evidence = store_dataset(database)
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
        database,
        FakeLLMProvider([proposal_with_verification()], model="fake-experiment-v2"),
    ).generate(hypothesis.id)
    settings = Settings(
        database_url=str(database.engine.url),
        executor_path=Path("native/rust/target/debug/aegis-executor"),
        policy_path=Path("native/rust/target/debug/aegis-policy"),
    )
    executed = await ExperimentRunner(
        database,
        RustPolicyClient(settings.policy_path),
        ObservationPipeline(database, RustExecutorClient(settings.executor_path)),
        settings,
    ).run(generated.experiment.id)
    verified = VerificationEngine(database).verify_execution(executed.execution.id)

    assert verified.verification.verdict is VerificationVerdict.SUPPORTED
    assert verified.finding is not None
    assert all(item.matched for item in verified.verification.comparisons)
    with database.session_factory() as session:
        repositories = RepositorySet(session)
        assert repositories.evidence.get(executed.candidate.evidence.id) is not None
        assert repositories.observations.get(executed.control.observation.id) is not None
        assert repositories.findings.get(verified.finding.id) is not None

    monkeypatch.setenv("AEGIS_DATABASE_URL", str(database.engine.url))
    monkeypatch.setenv("AEGIS_MIN_VERIFICATION_RUNS", "1")
    get_settings.cache_clear()
    experiment_result = await asyncio.to_thread(
        CliRunner().invoke,
        cli,
        ["verify", "experiment", str(generated.experiment.id)],
    )
    assert experiment_result.exit_code == 0, experiment_result.output
    assert json.loads(experiment_result.output)["verdict"] == "SUPPORTED"
    listed = CliRunner().invoke(cli, ["findings", "list", "--session", str(scoped.id)])
    assert listed.exit_code == 0, listed.output
    finding_id = json.loads(listed.output)[0]["id"]
    shown = CliRunner().invoke(cli, ["findings", "show", finding_id])
    assert shown.exit_code == 0, shown.output
    assert "bob-token" not in shown.output
    assert json.loads(shown.output)["verification_status"] == "SUPPORTED"

    project_service = ProjectService(database, settings)
    project = project_service.create("verified-finding-report")
    project = project_service.configure(
        project.id,
        scope=scoped.scope,
        identity_names=("alice", "bob"),
        profile=ResearchPolicyProfile.CONSERVATIVE,
        approval_mode=ApprovalMode.AUTO,
        budget=ResearchBudgetTemplate(),
    )
    with database.session_factory.begin() as session:
        RepositorySet(session).research_sessions.update(
            scoped.model_copy(
                update={"project_id": project.id, "project_scope_revision": project.scope_revision}
            )
        )
    report = ReportService(database, settings).build_core(scoped.id)
    assert len(report["findings"]) == 1
    reported = report["findings"][0]
    assert reported["verification_status"] == "SUPPORTED"
    assert reported["claim"] == verified.finding.claim
    assert set(reported["evidence_ids"]) == {str(item) for item in verified.finding.evidence_ids}
    assert set(reported["observation_ids"]) == {
        str(item) for item in verified.finding.observation_ids
    }
    get_settings.cache_clear()
