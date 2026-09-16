from uuid import uuid4

import pytest

from app.domain.common import Provenance
from app.domain.research import ResearchSession, ResearchSessionStatus, ResearchTarget, TargetScope
from app.domain.assets import Asset, AssetKind
from app.storage.database import Database
from app.storage.repositories import RepositorySet


def provenance() -> Provenance:
    return Provenance(source_type="configuration", source_reference="test")


def make_session() -> ResearchSession:
    scope = TargetScope(
        hosts=("127.0.0.1",), ports=(8001,), schemes=("http",), provenance=provenance()
    )
    target = ResearchTarget(
        asset_id=uuid4(),
        name="lab",
        base_url="http://127.0.0.1:8001",
        provenance=provenance(),
    )
    return ResearchSession(name="phase2", target=target, scope=scope, provenance=provenance())


def test_scope_uses_parsed_scheme_host_and_port() -> None:
    scope = make_session().scope
    scope.validate_url("http://127.0.0.1:8001/api/profile")

    for outside in (
        "https://127.0.0.1:8001/api/profile",
        "http://127.0.0.1:9000/api/profile",
        "http://127.0.0.1.evil.invalid:8001/api/profile",
        "http://127.0.0.1:8001@evil.invalid/api/profile",
        "http://127.0.0.1:8001/api/profile#fragment",
    ):
        with pytest.raises(ValueError, match="scope"):
            scope.validate_url(outside)


def test_session_start_preserves_immutable_scope() -> None:
    created = make_session()
    running = created.start()

    assert created.status is ResearchSessionStatus.CREATED
    assert running.status is ResearchSessionStatus.RUNNING
    assert running.started_at is not None
    assert running.scope == created.scope


def test_repository_rejects_scope_expansion_after_start(database: Database) -> None:
    created = make_session()
    asset = Asset(
        id=created.target.asset_id,
        name="lab",
        kind=AssetKind.API,
        provenance=provenance(),
    )
    with database.session_factory.begin() as db_session:
        repositories = RepositorySet(db_session)
        repositories.assets.add(asset)
        repositories.research_sessions.add(created)
        repositories.research_sessions.update(created.start())

    expanded = created.start().model_copy(
        update={
            "scope": TargetScope(
                hosts=("127.0.0.1", "example.invalid"),
                ports=(8001,),
                schemes=("http",),
                provenance=provenance(),
            )
        }
    )
    with pytest.raises(ValueError, match="scope cannot change"):
        with database.session_factory.begin() as db_session:
            RepositorySet(db_session).research_sessions.update(expanded)
