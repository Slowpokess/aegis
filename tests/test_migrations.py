from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

from app.config import get_settings


def test_initial_migration_upgrade_and_downgrade(tmp_path, monkeypatch) -> None:
    database_url = f"sqlite:///{tmp_path / 'migration.db'}"
    monkeypatch.setenv("AEGIS_DATABASE_URL", database_url)
    get_settings.cache_clear()
    config = Config("alembic.ini")

    command.upgrade(config, "0001_phase0")
    engine = create_engine(database_url)
    assert "research_sessions" not in inspect(engine).get_table_names()
    phase0_evidence = {column["name"]: column for column in inspect(engine).get_columns("evidence")}
    assert phase0_evidence["experiment_id"]["nullable"] is False

    command.upgrade(config, "head")
    expected_tables = {
        "alembic_version",
        "assets",
        "capabilities",
        "evidence",
        "experiments",
        "experiment_executions",
        "findings",
        "hypotheses",
        "identities",
        "llm_runs",
        "observations",
        "policy_decisions",
        "research_sessions",
        "verification_results",
        "benchmark_runs",
        "scenario_runs",
        "scenario_evaluations",
        "system_assets",
        "system_services",
        "system_endpoints",
        "system_identities",
        "system_roles",
        "system_permissions",
        "system_capabilities",
        "system_data_objects",
        "system_trust_boundaries",
        "system_relationships",
        "system_model_builds",
        "system_model_observations",
        "attack_graph_snapshots",
        "candidate_signals",
        "discovery_plans",
        "tool_runs",
        "tool_policy_decisions",
        "tool_artifacts",
        "research_steps",
        "research_intents",
        "knowledge_snapshots",
        "evidence_gaps",
        "research_questions",
        "strategy_runs",
        "research_budgets",
        "controller_steps",
        "research_actions",
        "research_action_results",
        "research_projects",
        "research_policies",
        "action_approvals",
        "research_events",
        "report_metadata",
        "web_resources",
        "web_resource_provenance",
        "web_parameters",
        "http_request_templates",
        "web_template_candidates",
        "web_candidate_provenance",
        "web_surface_snapshots",
    }
    assert set(inspect(engine).get_table_names()) == expected_tables
    phase2_evidence = {column["name"]: column for column in inspect(engine).get_columns("evidence")}
    assert phase2_evidence["experiment_id"]["nullable"] is True
    assert {"research_session_id", "request_id", "executor"} <= set(phase2_evidence)
    assert "experiment_role" in phase2_evidence
    observation_columns = {column["name"] for column in inspect(engine).get_columns("observations")}
    assert "tool_artifact_id" in observation_columns
    hypothesis_columns = {column["name"] for column in inspect(engine).get_columns("hypotheses")}
    assert {"research_session_id", "llm_run_id"} <= hypothesis_columns
    experiment_columns = {column["name"] for column in inspect(engine).get_columns("experiments")}
    assert {"research_session_id", "llm_run_id", "status"} <= experiment_columns
    command.check(config)

    command.downgrade(config, "base")
    assert set(inspect(engine).get_table_names()) == {"alembic_version"}
    engine.dispose()
    get_settings.cache_clear()


def test_phase11_rows_survive_phase12_upgrade(tmp_path, monkeypatch) -> None:
    database_url = f"sqlite:///{tmp_path / 'phase11-to-phase12.db'}"
    monkeypatch.setenv("AEGIS_DATABASE_URL", database_url)
    get_settings.cache_clear()
    config = Config("alembic.ini")
    command.upgrade(config, "0011_research_strategy")
    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO assets (id, payload) VALUES ('asset-p11', '{}')"))
        connection.execute(
            text(
                "INSERT INTO research_sessions (id, payload, asset_id, status) "
                "VALUES ('session-p11', '{}', 'asset-p11', 'RUNNING')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO knowledge_snapshots "
                "(id, payload, research_session_id, system_model_hash, sha256, created_at) "
                f"VALUES ('knowledge-p11', '{{}}', 'session-p11', '{'a' * 64}', "
                f"'{'b' * 64}', '2026-08-24T00:00:00Z')"
            )
        )
    command.upgrade(config, "head")
    with engine.connect() as connection:
        assert (
            connection.execute(
                text("SELECT sha256 FROM knowledge_snapshots WHERE id='knowledge-p11'")
            ).scalar_one()
            == "b" * 64
        )
        assert {
            "research_budgets",
            "controller_steps",
            "research_actions",
            "research_action_results",
        } <= set(inspect(engine).get_table_names())
    command.check(config)
    engine.dispose()
    get_settings.cache_clear()


def test_phase12_rows_survive_phase13_upgrade(tmp_path, monkeypatch) -> None:
    database_url = f"sqlite:///{tmp_path / 'phase12-to-phase13.db'}"
    monkeypatch.setenv("AEGIS_DATABASE_URL", database_url)
    get_settings.cache_clear()
    config = Config("alembic.ini")
    command.upgrade(config, "0012_closed_loop_controller")
    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO assets (id, payload) VALUES ('asset-p12', '{}')"))
        connection.execute(
            text(
                "INSERT INTO research_sessions (id, payload, asset_id, status) "
                "VALUES ('session-p12', '{}', 'asset-p12', 'RUNNING')"
            )
        )
    command.upgrade(config, "head")
    with engine.connect() as connection:
        assert (
            connection.execute(
                text("SELECT status FROM research_sessions WHERE id='session-p12'")
            ).scalar_one()
            == "RUNNING"
        )
        assert {
            "research_projects",
            "research_policies",
            "action_approvals",
            "research_events",
            "report_metadata",
        } <= set(inspect(engine).get_table_names())
    command.check(config)
    engine.dispose()
    get_settings.cache_clear()


def test_phase13_rows_survive_web_surface_upgrade(tmp_path, monkeypatch) -> None:
    database_url = f"sqlite:///{tmp_path / 'phase13-to-web-surface.db'}"
    monkeypatch.setenv("AEGIS_DATABASE_URL", database_url)
    get_settings.cache_clear()
    config = Config("alembic.ini")
    command.upgrade(config, "0013_operator_reporting")
    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO assets (id, payload) VALUES ('asset-p14', '{}')"))
        connection.execute(
            text(
                "INSERT INTO research_sessions (id, payload, asset_id, status) "
                "VALUES ('session-p14', '{}', 'asset-p14', 'RUNNING')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO hypotheses (id, payload, status, research_session_id) "
                "VALUES ('hyp-p14', '{}', 'SUPPORTED', 'session-p14')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO findings "
                "(id, payload, hypothesis_id, verification_status, research_session_id) "
                "VALUES ('finding-p14', '{}', 'hyp-p14', 'VERIFIED', 'session-p14')"
            )
        )
    command.upgrade(config, "head")
    with engine.connect() as connection:
        assert (
            connection.execute(
                text("SELECT COUNT(*) FROM findings WHERE id='finding-p14'")
            ).scalar_one()
            == 1
        )
        assert {
            "web_resources",
            "web_parameters",
            "http_request_templates",
            "web_surface_snapshots",
        } <= set(inspect(engine).get_table_names())
    command.check(config)
    engine.dispose()
    get_settings.cache_clear()


def test_phase15_2_rows_survive_active_web_upgrade(tmp_path, monkeypatch) -> None:
    database_url = f"sqlite:///{tmp_path / 'phase15-2-to-active-web.db'}"
    monkeypatch.setenv("AEGIS_DATABASE_URL", database_url)
    get_settings.cache_clear()
    config = Config("alembic.ini")
    command.upgrade(config, "0014_web_surface")
    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO assets (id, payload) VALUES ('asset-p15', '{}')"))
        connection.execute(
            text(
                "INSERT INTO research_sessions (id, payload, asset_id, status) "
                "VALUES ('session-p15', '{}', 'asset-p15', 'RUNNING')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO web_resources "
                "(id, payload, research_session_id, canonical_key, method, path, "
                "resource_type, system_endpoint_id) VALUES "
                "('resource-p15', '{}', 'session-p15', "
                "'GET:http://127.0.0.1:8001/admin', 'GET', '/admin', 'PAGE', NULL)"
            )
        )
    command.upgrade(config, "head")
    with engine.connect() as connection:
        assert connection.execute(
            text("SELECT COUNT(*) FROM web_resources WHERE id='resource-p15'")
        ).scalar_one() == 1
        assert "web_candidate_provenance" in inspect(engine).get_table_names()
    command.check(config)
    command.downgrade(config, "0014_web_surface")
    assert "web_candidate_provenance" not in inspect(engine).get_table_names()
    assert "web_resources" in inspect(engine).get_table_names()
    engine.dispose()
    get_settings.cache_clear()


def test_phase4_rows_survive_phase5_upgrade(tmp_path, monkeypatch) -> None:
    database_url = f"sqlite:///{tmp_path / 'phase4-to-phase5.db'}"
    monkeypatch.setenv("AEGIS_DATABASE_URL", database_url)
    get_settings.cache_clear()
    config = Config("alembic.ini")
    command.upgrade(config, "0004_phase4")
    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO assets (id, payload) VALUES ('asset-p4', '{}')"))
        connection.execute(
            text(
                "INSERT INTO research_sessions (id, payload, asset_id, status) "
                "VALUES ('session-p4', '{}', 'asset-p4', 'RUNNING')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO hypotheses (id, payload, status, research_session_id) "
                "VALUES ('hyp-p4', '{}', 'TESTING', 'session-p4')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO experiments "
                "(id, payload, hypothesis_id, research_session_id, status) "
                "VALUES ('exp-p4', '{}', 'hyp-p4', 'session-p4', 'EXECUTED')"
            )
        )
    command.upgrade(config, "head")
    with engine.connect() as connection:
        assert (
            connection.execute(
                text("SELECT status FROM experiments WHERE id='exp-p4'")
            ).scalar_one()
            == "EXECUTED"
        )
        assert "verification_results" in inspect(engine).get_table_names()
        finding_columns = {item["name"] for item in inspect(engine).get_columns("findings")}
        assert {"research_session_id", "experiment_id"} <= finding_columns
    command.check(config)
    engine.dispose()
    get_settings.cache_clear()


def test_phase6_rows_survive_phase7_upgrade(tmp_path, monkeypatch) -> None:
    database_url = f"sqlite:///{tmp_path / 'phase6-to-phase7.db'}"
    monkeypatch.setenv("AEGIS_DATABASE_URL", database_url)
    get_settings.cache_clear()
    config = Config("alembic.ini")
    command.upgrade(config, "0006_phase6")
    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO assets (id, payload) VALUES ('asset-p6', '{}')"))
        connection.execute(
            text(
                "INSERT INTO research_sessions (id, payload, asset_id, status) "
                "VALUES ('session-p6', '{}', 'asset-p6', 'RUNNING')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO benchmark_runs "
                "(id, payload, mode, status, provider, model, started_at) "
                "VALUES ('benchmark-p6', '{}', 'DETERMINISTIC', 'COMPLETED', "
                "'fake', 'fake-v1', '2026-08-22T00:00:00Z')"
            )
        )
    command.upgrade(config, "head")
    with engine.connect() as connection:
        assert (
            connection.execute(
                text("SELECT status FROM benchmark_runs WHERE id='benchmark-p6'")
            ).scalar_one()
            == "COMPLETED"
        )
        assert {
            "system_assets",
            "system_services",
            "system_endpoints",
            "system_relationships",
            "system_model_builds",
        } <= set(inspect(engine).get_table_names())
    command.check(config)
    engine.dispose()
    get_settings.cache_clear()


def test_phase7_rows_survive_phase8_upgrade(tmp_path, monkeypatch) -> None:
    database_url = f"sqlite:///{tmp_path / 'phase7-to-phase8.db'}"
    monkeypatch.setenv("AEGIS_DATABASE_URL", database_url)
    get_settings.cache_clear()
    config = Config("alembic.ini")
    command.upgrade(config, "0007_phase7")
    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO assets (id, payload) VALUES ('asset-p7', '{}')"))
        connection.execute(
            text(
                "INSERT INTO research_sessions (id, payload, asset_id, status) "
                "VALUES ('session-p7', '{}', 'asset-p7', 'RUNNING')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO system_model_builds "
                "(id, payload, research_session_id, status, started_at) "
                "VALUES ('build-p7', '{}', 'session-p7', 'COMPLETED', "
                "'2026-08-22T00:00:00Z')"
            )
        )
    command.upgrade(config, "head")
    with engine.connect() as connection:
        assert (
            connection.execute(
                text("SELECT status FROM system_model_builds WHERE id='build-p7'")
            ).scalar_one()
            == "COMPLETED"
        )
        assert {"attack_graph_snapshots", "candidate_signals"} <= set(
            inspect(engine).get_table_names()
        )
    command.check(config)
    engine.dispose()
    get_settings.cache_clear()


def test_phase8_rows_survive_phase9_upgrade(tmp_path, monkeypatch) -> None:
    database_url = f"sqlite:///{tmp_path / 'phase8-to-phase9.db'}"
    monkeypatch.setenv("AEGIS_DATABASE_URL", database_url)
    get_settings.cache_clear()
    config = Config("alembic.ini")
    command.upgrade(config, "0008_phase8")
    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO assets (id, payload) VALUES ('asset-p8', '{}')"))
        connection.execute(
            text(
                "INSERT INTO research_sessions (id, payload, asset_id, status) "
                "VALUES ('session-p8', '{}', 'asset-p8', 'RUNNING')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO attack_graph_snapshots "
                "(id, payload, research_session_id, graph_hash, system_model_hash, "
                "status, created_at) VALUES ('graph-p8', '{}', 'session-p8', "
                f"'{('a' * 64)}', '{('b' * 64)}', 'CURRENT', '2026-08-22T00:00:00Z')"
            )
        )
    command.upgrade(config, "head")
    with engine.connect() as connection:
        assert (
            connection.execute(
                text("SELECT status FROM attack_graph_snapshots WHERE id='graph-p8'")
            ).scalar_one()
            == "CURRENT"
        )
        assert {
            "discovery_plans",
            "tool_runs",
            "tool_policy_decisions",
            "tool_artifacts",
        } <= set(inspect(engine).get_table_names())
    command.check(config)
    engine.dispose()
    get_settings.cache_clear()


def test_phase5_rows_survive_phase6_upgrade(tmp_path, monkeypatch) -> None:
    database_url = f"sqlite:///{tmp_path / 'phase5-to-phase6.db'}"
    monkeypatch.setenv("AEGIS_DATABASE_URL", database_url)
    get_settings.cache_clear()
    config = Config("alembic.ini")
    command.upgrade(config, "0005_phase5")
    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO assets (id, payload) VALUES ('asset-p5', '{}')"))
        connection.execute(
            text(
                "INSERT INTO research_sessions (id, payload, asset_id, status) "
                "VALUES ('session-p5', '{}', 'asset-p5', 'RUNNING')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO hypotheses (id, payload, status, research_session_id) "
                "VALUES ('hyp-p5', '{}', 'SUPPORTED', 'session-p5')"
            )
        )
    command.upgrade(config, "head")
    with engine.connect() as connection:
        assert (
            connection.execute(text("SELECT status FROM hypotheses WHERE id='hyp-p5'")).scalar_one()
            == "SUPPORTED"
        )
        assert {"benchmark_runs", "scenario_runs", "scenario_evaluations"} <= set(
            inspect(engine).get_table_names()
        )
    command.check(config)
    engine.dispose()
    get_settings.cache_clear()


def test_phase0_rows_survive_phase2_upgrade(tmp_path, monkeypatch) -> None:
    database_url = f"sqlite:///{tmp_path / 'upgrade.db'}"
    monkeypatch.setenv("AEGIS_DATABASE_URL", database_url)
    get_settings.cache_clear()
    config = Config("alembic.ini")
    command.upgrade(config, "0001_phase0")
    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(
            text("INSERT INTO assets (id, payload) VALUES (:id, :payload)"),
            {"id": "asset-legacy", "payload": '{"legacy": true}'},
        )
        connection.execute(
            text("INSERT INTO hypotheses (id, payload, status) VALUES (:id, :payload, :status)"),
            {"id": "hypothesis-legacy", "payload": '{"legacy": true}', "status": "NEW"},
        )
        connection.execute(
            text(
                "INSERT INTO experiments (id, payload, hypothesis_id) "
                "VALUES (:id, :payload, :hypothesis_id)"
            ),
            {
                "id": "experiment-legacy",
                "payload": '{"legacy": true}',
                "hypothesis_id": "hypothesis-legacy",
            },
        )
        connection.execute(
            text(
                "INSERT INTO evidence (id, payload, experiment_id, integrity_hash) "
                "VALUES (:id, :payload, :experiment_id, :integrity_hash)"
            ),
            {
                "id": "evidence-legacy",
                "payload": '{"legacy": true}',
                "experiment_id": "experiment-legacy",
                "integrity_hash": "a" * 64,
            },
        )
    command.upgrade(config, "head")
    with engine.connect() as connection:
        preserved = connection.execute(
            text("SELECT experiment_id, integrity_hash FROM evidence WHERE id='evidence-legacy'")
        ).one()
    assert preserved.experiment_id == "experiment-legacy"
    assert preserved.integrity_hash == "a" * 64
    engine.dispose()
    get_settings.cache_clear()


def test_phase2_database_upgrades_to_phase3_without_changing_evidence(
    tmp_path, monkeypatch
) -> None:
    database_url = f"sqlite:///{tmp_path / 'phase2-to-phase3.db'}"
    monkeypatch.setenv("AEGIS_DATABASE_URL", database_url)
    get_settings.cache_clear()
    config = Config("alembic.ini")
    command.upgrade(config, "0002_phase2")
    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO assets (id, payload) VALUES ('asset-p2', '{}')"))
        connection.execute(
            text(
                "INSERT INTO research_sessions (id, payload, asset_id, status) "
                "VALUES ('session-p2', '{}', 'asset-p2', 'RUNNING')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO evidence "
                "(id, payload, experiment_id, integrity_hash, research_session_id, request_id) "
                "VALUES ('evidence-p2', '{}', NULL, :hash, 'session-p2', 'REQ-P2')"
            ),
            {"hash": "b" * 64},
        )
    command.upgrade(config, "head")
    with engine.connect() as connection:
        row = connection.execute(
            text(
                "SELECT integrity_hash, research_session_id, request_id "
                "FROM evidence WHERE id='evidence-p2'"
            )
        ).one()
    assert row.integrity_hash == "b" * 64
    assert row.research_session_id == "session-p2"
    assert row.request_id == "REQ-P2"
    command.check(config)
    engine.dispose()
    get_settings.cache_clear()


def test_phase3_rows_survive_phase4_upgrade(tmp_path, monkeypatch) -> None:
    database_url = f"sqlite:///{tmp_path / 'phase3-to-phase4.db'}"
    monkeypatch.setenv("AEGIS_DATABASE_URL", database_url)
    get_settings.cache_clear()
    config = Config("alembic.ini")
    command.upgrade(config, "0003_phase3")
    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO assets (id, payload) VALUES ('asset-p3', '{}')"))
        connection.execute(
            text(
                "INSERT INTO research_sessions (id, payload, asset_id, status) "
                "VALUES ('session-p3', '{}', 'asset-p3', 'RUNNING')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO llm_runs "
                "(id, payload, research_session_id, provider, model, prompt_version, status) "
                "VALUES ('run-p3', '{}', 'session-p3', 'fake', 'fake-v1', "
                "'hypothesis-v1', 'COMPLETED')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO hypotheses "
                "(id, payload, status, research_session_id, llm_run_id) "
                "VALUES ('hyp-p3', '{}', 'NEW', 'session-p3', 'run-p3')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO experiments (id, payload, hypothesis_id) "
                "VALUES ('exp-p3', '{}', 'hyp-p3')"
            )
        )
    command.upgrade(config, "head")
    with engine.connect() as connection:
        assert (
            connection.execute(text("SELECT purpose FROM llm_runs WHERE id='run-p3'")).scalar_one()
            == "HYPOTHESIS_GENERATION"
        )
        row = connection.execute(
            text("SELECT status, hypothesis_id FROM experiments WHERE id='exp-p3'")
        ).one()
    assert row.status == "DRAFT"
    assert row.hypothesis_id == "hyp-p3"
    command.check(config)
    engine.dispose()
    get_settings.cache_clear()


def test_phase9_rows_survive_phase10_upgrade(tmp_path, monkeypatch) -> None:
    database_url = f"sqlite:///{tmp_path / 'phase9-to-phase10.db'}"
    monkeypatch.setenv("AEGIS_DATABASE_URL", database_url)
    get_settings.cache_clear()
    config = Config("alembic.ini")
    command.upgrade(config, "0009_phase9")
    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO assets (id, payload) VALUES ('asset-p9', '{}')"))
        connection.execute(
            text(
                "INSERT INTO research_sessions (id, payload, asset_id, status) "
                "VALUES ('session-p9', '{}', 'asset-p9', 'RUNNING')"
            )
        )
    command.upgrade(config, "head")
    assert {"research_steps", "research_intents"} <= set(inspect(engine).get_table_names())
    with engine.connect() as connection:
        assert (
            connection.execute(
                text("SELECT status FROM research_sessions WHERE id='session-p9'")
            ).scalar_one()
            == "RUNNING"
        )
    command.check(config)
    engine.dispose()
    get_settings.cache_clear()


def test_phase10_rows_survive_phase11_upgrade(tmp_path, monkeypatch) -> None:
    database_url = f"sqlite:///{tmp_path / 'phase10-to-phase11.db'}"
    monkeypatch.setenv("AEGIS_DATABASE_URL", database_url)
    get_settings.cache_clear()
    config = Config("alembic.ini")
    command.upgrade(config, "0010_research_planner")
    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO assets (id, payload) VALUES ('asset-p10', '{}')"))
        connection.execute(
            text(
                "INSERT INTO research_sessions (id, payload, asset_id, status) "
                "VALUES ('session-p10', '{}', 'asset-p10', 'RUNNING')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO research_steps "
                "(id, payload, research_session_id, step_number, context_hash, status, started_at) "
                "VALUES ('step-p10', '{}', 'session-p10', 1, :hash, 'COMPLETED', "
                "'2026-08-23T00:00:00Z')"
            ),
            {"hash": "c" * 64},
        )
    command.upgrade(config, "head")
    with engine.connect() as connection:
        assert (
            connection.execute(
                text("SELECT status FROM research_steps WHERE id='step-p10'")
            ).scalar_one()
            == "COMPLETED"
        )
    assert {
        "knowledge_snapshots",
        "evidence_gaps",
        "research_questions",
        "strategy_runs",
    } <= set(inspect(engine).get_table_names())
    command.check(config)
    engine.dispose()
    get_settings.cache_clear()
