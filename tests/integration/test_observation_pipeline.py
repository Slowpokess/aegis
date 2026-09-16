import base64
from pathlib import Path

import pytest


from app.collectors.pipeline import ObservationPipeline
from app.domain.assets import Asset, AssetKind
from app.domain.common import Provenance, TrustClassification
from app.domain.research import ResearchSession, ResearchTarget, TargetScope
from app.execution.protocol import canonical_evidence_sha256
from app.execution.rust_executor import RustExecutorClient
from app.storage.database import Database
from app.storage.repositories import RepositorySet


def executor_binary() -> Path:
    binary = Path("native/rust/target/debug/aegis-executor")
    if not binary.is_file():
        raise RuntimeError("build Rust executor before running integration tests")
    return binary


@pytest.mark.asyncio
async def test_python_rust_lab_evidence_observation_sqlite_path(
    database: Database, live_lab: int
) -> None:
    provenance = Provenance(source_type="configuration", source_reference="integration test")
    asset = Asset(name="live-lab", kind=AssetKind.API, provenance=provenance)
    scope = TargetScope(
        hosts=("127.0.0.1",),
        ports=(live_lab,),
        schemes=("http",),
        provenance=provenance,
    )
    target = ResearchTarget(
        asset_id=asset.id,
        name="live-lab",
        base_url=f"http://127.0.0.1:{live_lab}",
        provenance=provenance,
    )
    research_session = ResearchSession(
        name="integration",
        target=target,
        scope=scope,
        provenance=provenance,
    )
    with database.session_factory.begin() as session:
        repositories = RepositorySet(session)
        repositories.assets.add(asset)
        repositories.research_sessions.add(research_session)

    pipeline = ObservationPipeline(database, RustExecutorClient(executor_binary()))
    captured = await pipeline.observe(
        research_session_id=research_session.id,
        path="/api/profile",
        headers={"Authorization": "Bearer alice-token"},
    )

    body = base64.b64decode(captured.evidence.response.body_base64 or "")
    recomputed_hash = canonical_evidence_sha256(
        method=captured.evidence.request.method,
        url=captured.evidence.request.url,
        request_headers=captured.evidence.request.headers,
        status_code=captured.evidence.response.status_code,
        response_headers=captured.evidence.response.headers,
        body=body,
    )
    assert recomputed_hash == captured.evidence.integrity_hash
    assert captured.evidence.response.status_code == 200
    assert captured.evidence.research_session_id == research_session.id
    assert captured.evidence.request_id == captured.observation.request_id
    assert captured.observation.evidence_id == captured.evidence.id
    assert captured.observation.research_session_id == research_session.id
    assert captured.observation.trust is TrustClassification.UNTRUSTED
    assert captured.observation.normalized_data_trust is TrustClassification.TRUSTED
    assert captured.observation.normalized_data["is_json"] is True
    assert captured.observation.provenance.metadata["evidence_id"] == str(captured.evidence.id)

    with database.session_factory() as session:
        repositories = RepositorySet(session)
        assert repositories.evidence.list_by_session(research_session.id) == [captured.evidence]
        assert repositories.observations.list_by_session(research_session.id) == [
            captured.observation
        ]


def test_research_package_does_not_reference_ground_truth() -> None:
    source = "\n".join(path.read_text(encoding="utf-8") for path in Path("app").rglob("*.py"))
    assert "lab.ground_truth" not in source
    assert "lab/scenarios" not in source
