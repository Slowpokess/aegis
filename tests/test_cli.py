from typer.testing import CliRunner
from uuid import UUID
import json

from app.domain.common import Provenance
from app.domain.evidence import Evidence, HTTPRequestRecord, HTTPResponseRecord
from app.domain.assets import Asset, AssetKind
from app.domain.research import ResearchSession, ResearchTarget, TargetScope
from app.storage.database import Database
from app.storage.repositories import RepositorySet

from app.cli.main import cli
from app.llm.base import LLMProviderError, LLMProviderErrorCode
from app.llm.providers.fake import FakeLLMProvider
from tests.integration.test_hypothesis_engine import proposal, store_dataset
from tests.integration.test_experiment_pipeline import add_hypothesis, experiment_proposal


def test_init_db_command_creates_database(tmp_path) -> None:
    database_path = tmp_path / "cli.db"

    result = CliRunner().invoke(
        cli,
        ["init-db", "--database-url", f"sqlite:///{database_path}"],
    )

    assert result.exit_code == 0, result.output
    assert "Database schema initialized." in result.output
    assert database_path.exists()


def test_info_command_does_not_expose_database_password(monkeypatch) -> None:
    from app.config import get_settings

    monkeypatch.setenv("AEGIS_DATABASE_URL", "postgresql://researcher:secret@localhost/aegis")
    get_settings.cache_clear()
    result = CliRunner().invoke(cli, ["info"])

    assert result.exit_code == 0, result.output
    assert "secret" not in result.output
    assert "***" in result.output
    get_settings.cache_clear()


def test_research_create_persists_immutable_scope(tmp_path, monkeypatch) -> None:
    from app.config import get_settings

    database_url = f"sqlite:///{tmp_path / 'research.db'}"
    monkeypatch.setenv("AEGIS_DATABASE_URL", database_url)
    get_settings.cache_clear()
    result = CliRunner().invoke(
        cli,
        [
            "research",
            "create",
            "--name",
            "phase2-test",
            "--host",
            "127.0.0.1",
            "--port",
            "8001",
            "--scheme",
            "http",
        ],
    )

    assert result.exit_code == 0, result.output
    session_id = UUID(result.output.strip())
    database = Database(database_url)
    with database.session_factory() as session:
        research = RepositorySet(session).research_sessions.get(session_id)
    database.dispose()
    assert research is not None
    assert research.scope.hosts == ("127.0.0.1",)
    assert research.scope.ports == (8001,)
    get_settings.cache_clear()


def test_evidence_show_redacts_authorization_header(tmp_path, monkeypatch) -> None:
    from app.config import get_settings

    database_url = f"sqlite:///{tmp_path / 'evidence.db'}"
    monkeypatch.setenv("AEGIS_DATABASE_URL", database_url)
    get_settings.cache_clear()
    database = Database(database_url)
    database.create_schema()
    provenance = Provenance(source_type="test", source_reference="CLI redaction")
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
    research = ResearchSession(name="lab", target=target, scope=scope, provenance=provenance)
    evidence = Evidence(
        research_session_id=research.id,
        request_id="REQ-CLI",
        request=HTTPRequestRecord(
            method="GET",
            url="http://127.0.0.1:8001/api/profile",
            headers={"Authorization": "Bearer alice-token"},
        ),
        response=HTTPResponseRecord(status_code=200, body="{}", elapsed_ms=1),
        executor="aegis-executor",
        executor_version="0.2.0",
        protocol_version=1,
        provenance=provenance,
        integrity_hash="a" * 64,
    )
    with database.session_factory.begin() as session:
        repositories = RepositorySet(session)
        repositories.assets.add(asset)
        repositories.research_sessions.add(research)
        repositories.evidence.add(evidence)
    database.dispose()

    result = CliRunner().invoke(cli, ["evidence", "show", str(evidence.id)])

    assert result.exit_code == 0, result.output
    assert "alice-token" not in result.output
    assert "<redacted>" in result.output
    get_settings.cache_clear()


def test_hypothesis_generate_list_and_show_commands(tmp_path, monkeypatch) -> None:
    from app.config import get_settings

    database_url = f"sqlite:///{tmp_path / 'hypothesis-cli.db'}"
    monkeypatch.setenv("AEGIS_DATABASE_URL", database_url)
    monkeypatch.setenv("AEGIS_LLM_PROVIDER", "fake")
    get_settings.cache_clear()
    database = Database(database_url)
    database.create_schema()
    research, observation, evidence = store_dataset(database)
    database.dispose()
    response_path = tmp_path / "fake-response.json"
    response_path.write_text(
        json.dumps({"hypotheses": [proposal(observation, evidence)]}), encoding="utf-8"
    )

    generated = CliRunner().invoke(
        cli,
        [
            "hypotheses",
            "generate",
            "--session",
            str(research.id),
            "--fake-response",
            str(response_path),
        ],
    )
    assert generated.exit_code == 0, generated.output
    summary = json.loads(generated.output)
    assert summary["accepted"] == 1
    assert summary["rejected"] == 0

    listed = CliRunner().invoke(
        cli, ["hypotheses", "list", "--session", str(research.id)]
    )
    assert listed.exit_code == 0, listed.output
    rows = json.loads(listed.output)
    assert len(rows) == 1
    assert rows[0]["status"] == "NEW"

    shown = CliRunner().invoke(cli, ["hypotheses", "show", rows[0]["id"]])
    assert shown.exit_code == 0, shown.output
    detail = json.loads(shown.output)
    assert detail["llm_metadata"]["prompt_version"] == "hypothesis-v1"
    assert "bob-token" not in shown.output
    get_settings.cache_clear()


def test_hypothesis_generate_reports_typed_provider_failure_without_traceback(
    tmp_path, monkeypatch
) -> None:
    from app.config import get_settings

    database_url = f"sqlite:///{tmp_path / 'hypothesis-cli-failure.db'}"
    monkeypatch.setenv("AEGIS_DATABASE_URL", database_url)
    get_settings.cache_clear()


def test_experiment_generate_show_and_policy_check_commands(tmp_path, monkeypatch) -> None:
    from app.config import get_settings

    database_url = f"sqlite:///{tmp_path / 'experiment-cli.db'}"
    monkeypatch.setenv("AEGIS_DATABASE_URL", database_url)
    monkeypatch.setenv("AEGIS_LLM_PROVIDER", "fake")
    get_settings.cache_clear()
    database = Database(database_url)
    database.create_schema()
    research, observation, evidence = store_dataset(database)
    hypothesis = add_hypothesis(database, research, observation, evidence)
    database.dispose()
    response_path = tmp_path / "experiment-response.json"
    response_path.write_text(json.dumps(experiment_proposal()), encoding="utf-8")

    generated = CliRunner().invoke(
        cli,
        [
            "experiments",
            "generate",
            "--hypothesis",
            str(hypothesis.id),
            "--fake-response",
            str(response_path),
        ],
    )
    assert generated.exit_code == 0, generated.output
    summary = json.loads(generated.output)
    assert summary["status"] == "VALIDATED"
    assert summary["candidate"]["identity"] == "bob"

    shown = CliRunner().invoke(cli, ["experiments", "show", summary["experiment_id"]])
    assert shown.exit_code == 0, shown.output
    assert "bob-token" not in shown.output
    assert json.loads(shown.output)["experiment"]["status"] == "VALIDATED"

    checked = CliRunner().invoke(cli, ["experiments", "check", summary["experiment_id"]])
    assert checked.exit_code == 0, checked.output
    decision = json.loads(checked.output)
    assert decision["allowed"] is True
    assert decision["candidate"]["reason_code"] == "WITHIN_SCOPE"
    get_settings.cache_clear()


def test_experiment_generate_reports_typed_provider_failure(tmp_path, monkeypatch) -> None:
    from app.config import get_settings

    database_url = f"sqlite:///{tmp_path / 'experiment-cli-failure.db'}"
    monkeypatch.setenv("AEGIS_DATABASE_URL", database_url)
    get_settings.cache_clear()
    database = Database(database_url)
    database.create_schema()
    research, observation, evidence = store_dataset(database)
    hypothesis = add_hypothesis(database, research, observation, evidence)
    database.dispose()
    provider = FakeLLMProvider(
        [LLMProviderError(LLMProviderErrorCode.TIMEOUT, "provider timed out")]
    )
    monkeypatch.setattr("app.cli.main.create_llm_provider", lambda *args, **kwargs: provider)

    result = CliRunner().invoke(
        cli, ["experiments", "generate", "--hypothesis", str(hypothesis.id)]
    )
    assert result.exit_code == 1
    assert json.loads(result.output)["error"]["code"] == "TIMEOUT"
    assert "Traceback" not in result.output
    get_settings.cache_clear()
    database = Database(database_url)
    database.create_schema()
    research, _, _ = store_dataset(database)
    database.dispose()
    provider = FakeLLMProvider(
        [LLMProviderError(LLMProviderErrorCode.TIMEOUT, "provider timed out")]
    )
    monkeypatch.setattr("app.cli.main.create_llm_provider", lambda *args, **kwargs: provider)

    result = CliRunner().invoke(
        cli, ["hypotheses", "generate", "--session", str(research.id)]
    )

    assert result.exit_code == 1
    assert json.loads(result.output) == {
        "error": {"code": "TIMEOUT", "message": "provider timed out"},
        "ok": False,
    }
    assert "Traceback" not in result.output
    get_settings.cache_clear()
