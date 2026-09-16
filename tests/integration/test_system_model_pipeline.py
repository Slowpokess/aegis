import json
from pathlib import Path

import pytest

from typer.testing import CliRunner

from app.cli.main import cli
from app.collectors.pipeline import ObservationPipeline
from app.domain.assets import Asset, AssetKind
from app.domain.common import Provenance
from app.domain.research import ResearchSession, ResearchTarget, TargetScope
from app.domain.observations import Observation, ObservationSource
from app.execution.identity import LaboratoryIdentityResolver
from app.execution.rust_executor import RustExecutorClient
from app.config import get_settings
from app.storage.database import Database
from app.storage.repositories import RepositorySet
from app.system_model.builder import SystemModelBuilder
from app.system_model.queries import SystemModelQueryService


def _executor_binary() -> Path:
    binary = Path("native/rust/target/debug/aegis-executor")
    if not binary.is_file():
        raise RuntimeError("build Rust executor before running integration tests")
    return binary


def _session(database: Database, port: int) -> ResearchSession:
    provenance = Provenance(source_type="configuration", source_reference="system model test")
    asset = Asset(name="model-lab", kind=AssetKind.API, provenance=provenance)
    target = ResearchTarget(
        asset_id=asset.id,
        name="controlled-lab",
        base_url=f"http://127.0.0.1:{port}",
        provenance=provenance,
    )
    research_session = ResearchSession(
        name="system-model",
        target=target,
        scope=TargetScope(
            hosts=("127.0.0.1",),
            ports=(port,),
            schemes=("http",),
            provenance=provenance,
        ),
        provenance=provenance,
    )
    with database.session_factory.begin() as session:
        repositories = RepositorySet(session)
        repositories.assets.add(asset)
        repositories.research_sessions.add(research_session)
    return research_session


async def _observe(
    pipeline: ObservationPipeline,
    session_id,
    identity: str,
    path: str,
) -> None:
    resolved = LaboratoryIdentityResolver().resolve(identity)
    await pipeline.observe(
        research_session_id=session_id,
        path=path,
        headers=resolved.headers,
        identity_name=resolved.name,
        identity_roles=list(resolved.roles),
    )


@pytest.mark.asyncio
async def test_http_observations_build_idempotent_incremental_rebuildable_model(
    database: Database, live_lab: int, tmp_path, monkeypatch
) -> None:
    research_session = _session(database, live_lab)
    pipeline = ObservationPipeline(database, RustExecutorClient(_executor_binary()))
    for identity, path in (
        ("anonymous", "/health"),
        ("alice", "/api/profile"),
        ("bob", "/api/orders"),
        ("bob", "/api/orders/101"),
        ("alice", "/api/admin/stats"),
        ("admin", "/api/admin/stats"),
        ("anonymous", "/api/portal"),
    ):
        await _observe(pipeline, research_session.id, identity, path)

    builder = SystemModelBuilder(database)
    first = builder.build(research_session.id)
    query = SystemModelQueryService(database)
    summary = query.summary(research_session.id)
    assert first.observations_processed == 7
    assert summary["assets"] == 2
    assert summary["services"] == 1
    assert summary["endpoints"] == 6  # admin stats is deduplicated across identities
    assert summary["identities"] == 4
    assert summary["roles"] == 3
    assert summary["data_objects"] == 3
    assert summary["capabilities"] == 5
    assert first.model_sha256 == summary["model_sha256"]

    access = query.endpoint_access(research_session.id, "/api/admin/stats")
    assert {(item["identity"], item["relationship"]) for item in access} == {
        ("alice", "CANNOT_ACCESS"),
        ("admin", "CAN_ACCESS"),
    }
    assert all(item["observation_ids"] and item["evidence_ids"] for item in access)
    assert query.owners(research_session.id, "order:101")[0]["identity"] == "alice"

    exported = query.export(research_session.id)
    encoded = json.dumps(exported, sort_keys=True)
    for secret in (
        "alice-token",
        "bob-token",
        "admin-token",
        "Authorization",
        "Cookie",
    ):
        assert secret not in encoded
    assert all(item["observation_ids"] for item in exported["relationships"])
    assert all(item["evidence_ids"] for item in exported["relationships"])

    second = builder.build(research_session.id)
    assert second.observations_processed == 0
    assert second.entities_created == 0
    assert second.relationships_created == 0
    assert second.model_sha256 == first.model_sha256
    assert query.summary(research_session.id)["relationships"] == summary["relationships"]

    await _observe(pipeline, research_session.id, "alice", "/api/orders/202")
    incremental = builder.build(research_session.id)
    assert incremental.observations_processed == 1
    assert incremental.model_sha256 != first.model_sha256
    incremental_summary = query.summary(research_session.id)
    assert incremental_summary["endpoints"] == 7
    assert incremental_summary["data_objects"] == 3

    rebuilt = builder.build(research_session.id, rebuild=True)
    assert rebuilt.observations_processed == 8
    assert rebuilt.model_sha256 == incremental.model_sha256
    assert query.summary(research_session.id)["endpoints"] == 7
    unsupported = Observation(
        asset_id=research_session.target.asset_id,
        research_session_id=research_session.id,
        source=ObservationSource.TOOL,
        raw_data={"source_type": "nmap", "synthetic": True},
        provenance=Provenance(source_type="nmap", source_reference="future-adapter-test"),
    )
    with database.session_factory.begin() as session:
        RepositorySet(session).observations.add(unsupported)
    skipped = builder.build(research_session.id)
    assert skipped.unsupported_observations == 1
    assert skipped.observations_processed == 0
    assert skipped.model_sha256 == rebuilt.model_sha256
    assert builder.build(research_session.id).unsupported_observations == 0

    monkeypatch.setenv("AEGIS_DATABASE_URL", str(database.engine.url))
    get_settings.cache_clear()
    runner = CliRunner()
    built_cli = runner.invoke(
        cli, ["model", "build", "--session", str(research_session.id)]
    )
    assert built_cli.exit_code == 0, built_cli.output
    assert json.loads(built_cli.output)["observations_processed"] == 0
    for command in ("show", "assets", "endpoints", "identities", "relationships"):
        result = runner.invoke(
            cli, ["model", command, "--session", str(research_session.id)]
        )
        assert result.exit_code == 0, result.output
        json.loads(result.output)
    export_path = tmp_path / "system-model.json"
    exported_cli = runner.invoke(
        cli,
        [
            "model",
            "export",
            "--session",
            str(research_session.id),
            "--format",
            "json",
            "--output",
            str(export_path),
        ],
    )
    assert exported_cli.exit_code == 0, exported_cli.output
    assert json.loads(export_path.read_text())["model_sha256"] == rebuilt.model_sha256
    get_settings.cache_clear()


def test_system_model_source_does_not_reference_ground_truth() -> None:
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in Path("app/system_model").rglob("*.py")
    )
    assert "lab.ground_truth" not in source
    assert "lab/scenarios" not in source
    assert "evals" not in source
    assert "FactClassification.INFERRED" not in source
