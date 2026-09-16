from uuid import uuid4

import pytest

from app.domain.common import FactClassification, Provenance
from app.domain.assets import Asset, AssetKind
from app.domain.research import ResearchSession, ResearchTarget, TargetScope
from app.domain.system_model import (
    RelationshipType,
    SystemAsset,
    SystemAssetType,
    SystemEntityType,
    SystemRelationship,
)
from app.storage.database import Database
from app.storage.repositories import RepositorySet
from app.system_model.mapper import HTTPObservationMapper


def test_observed_model_fact_requires_complete_lineage() -> None:
    with pytest.raises(ValueError, match="lineage"):
        SystemAsset(
            research_session_id=uuid4(),
            canonical_identifier="host:127.0.0.1",
            source_type="http",
            classification=FactClassification.OBSERVED,
            confidence=1.0,
            asset_type=SystemAssetType.HOST,
            name="127.0.0.1",
            provenance=Provenance(source_type="http", source_reference="test"),
        )


def test_inferred_model_fact_cannot_claim_observed_confidence() -> None:
    with pytest.raises(ValueError, match="below 1.0"):
        SystemAsset(
            research_session_id=uuid4(),
            canonical_identifier="host:inferred",
            source_type="manual",
            classification=FactClassification.INFERRED,
            confidence=1.0,
            asset_type=SystemAssetType.HOST,
            name="inferred",
            provenance=Provenance(source_type="manual", source_reference="test"),
        )


def test_http_mapper_does_not_claim_support_for_non_http_source() -> None:
    class Unsupported:
        source = "TOOL"

    assert HTTPObservationMapper().supports(Unsupported()) is False  # type: ignore[arg-type]


def test_relationship_repository_rejects_cross_session_entities(database: Database) -> None:
    provenance = Provenance(source_type="test", source_reference="cross-session")
    sessions = []
    legacy_assets = []
    for index in (1, 2):
        legacy = Asset(name=f"legacy-{index}", kind=AssetKind.API, provenance=provenance)
        target = ResearchTarget(
            asset_id=legacy.id,
            name=f"target-{index}",
            base_url=f"http://127.0.0.1:{8000 + index}",
            provenance=provenance,
        )
        sessions.append(
            ResearchSession(
                name=f"session-{index}",
                target=target,
                scope=TargetScope(
                    hosts=("127.0.0.1",),
                    ports=(8000 + index,),
                    schemes=("http",),
                    provenance=provenance,
                ),
                provenance=provenance,
            )
        )
        legacy_assets.append(legacy)
    observation_ids = [uuid4(), uuid4()]
    evidence_ids = [uuid4(), uuid4()]
    system_assets = [
        SystemAsset(
            research_session_id=session.id,
            canonical_identifier=f"host:127.0.0.1:{index}",
            source_type="http",
            observation_ids=[observation_ids[index - 1]],
            evidence_ids=[evidence_ids[index - 1]],
            classification=FactClassification.OBSERVED,
            confidence=1.0,
            asset_type=SystemAssetType.HOST,
            name=f"host-{index}",
            provenance=provenance,
        )
        for index, session in enumerate(sessions, 1)
    ]
    with database.session_factory.begin() as session:
        repositories = RepositorySet(session)
        for legacy, research, system_asset in zip(
            legacy_assets, sessions, system_assets, strict=True
        ):
            repositories.assets.add(legacy)
            repositories.research_sessions.add(research)
            repositories.system_assets.add(system_asset)
        relationship = SystemRelationship(
            research_session_id=sessions[0].id,
            canonical_identifier="relationship:cross-session",
            source_type="http",
            observation_ids=[observation_ids[0]],
            evidence_ids=[evidence_ids[0]],
            classification=FactClassification.OBSERVED,
            confidence=1.0,
            source_entity_type=SystemEntityType.ASSET,
            source_entity_id=system_assets[0].id,
            relationship_type=RelationshipType.HOSTS,
            target_entity_type=SystemEntityType.ASSET,
            target_entity_id=system_assets[1].id,
            provenance=provenance,
        )
        with pytest.raises(ValueError, match="cross research sessions"):
            repositories.system_relationships.add(relationship)
