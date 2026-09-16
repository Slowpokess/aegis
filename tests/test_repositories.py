from hashlib import sha256

from sqlalchemy.exc import IntegrityError

from app.domain.assets import Asset, AssetKind
from app.domain.common import Provenance
from app.domain.evidence import Evidence, HTTPRequestRecord, HTTPResponseRecord
from app.domain.experiments import Experiment, ExperimentAction
from app.domain.hypotheses import Hypothesis
from app.domain.observations import Observation, ObservationSource
from app.storage.database import Database
from app.storage.repositories import RepositorySet


def test_repository_round_trip_preserves_typed_domain_models(database: Database) -> None:
    asset = Asset(
        name="local-api",
        kind=AssetKind.API,
        provenance=Provenance(source_type="manual", source_reference="test fixture"),
    )
    observation = Observation(
        asset_id=asset.id,
        source=ObservationSource.HTTP,
        raw_data={"status_code": 200},
        provenance=Provenance(source_type="http", source_reference="GET /health"),
    )
    hypothesis = Hypothesis(
        provenance=Provenance(
            source_type="reasoning",
            source_reference="test fixture",
            classification="INFERRED",
        ),
        title="Response is reachable",
        description="The local health endpoint may be reachable.",
        observation_ids=[observation.id],
        confidence=0.5,
    )
    experiment = Experiment(
        provenance=Provenance(
            source_type="experiment-design",
            source_reference="test fixture",
            classification="INFERRED",
        ),
        hypothesis_id=hypothesis.id,
        variable="request method",
        action=ExperimentAction(kind="http", parameters={"method": "GET"}),
        expected_if_true="A deterministic response is returned.",
        expected_if_false="No response is returned.",
    )
    evidence = Evidence(
        experiment_id=experiment.id,
        request=HTTPRequestRecord(method="GET", url="http://127.0.0.1/health"),
        response=HTTPResponseRecord(status_code=200, body="ok", elapsed_ms=1.0),
        provenance=Provenance(source_type="http", source_reference="GET /health"),
        integrity_hash=sha256(b"request-response").hexdigest(),
    )

    with database.session_factory.begin() as session:
        repositories = RepositorySet(session)
        repositories.assets.add(asset)
        repositories.observations.add(observation)
        repositories.hypotheses.add(hypothesis)
        repositories.experiments.add(experiment)
        repositories.evidence.add(evidence)

    with database.session_factory() as session:
        repositories = RepositorySet(session)
        assert repositories.assets.get(asset.id) == asset
        assert repositories.observations.list() == [observation]
        assert repositories.evidence.get(evidence.id) == evidence


def test_sqlite_foreign_keys_are_enforced(database: Database) -> None:
    orphan = Observation(
        asset_id=Asset(
            name="not-stored",
            kind=AssetKind.API,
            provenance=Provenance(source_type="manual", source_reference="test fixture"),
        ).id,
        source=ObservationSource.MANUAL,
        raw_data={"note": "orphan"},
        provenance=Provenance(source_type="manual", source_reference="test"),
    )

    try:
        with database.session_factory.begin() as session:
            RepositorySet(session).observations.add(orphan)
    except IntegrityError:
        pass
    else:
        raise AssertionError("SQLite accepted an observation for an unknown asset")


def test_repeated_evidence_hash_is_allowed_for_reproducibility(database: Database) -> None:
    observation_id = Asset(
        name="reference-only",
        kind=AssetKind.API,
        provenance=Provenance(source_type="manual", source_reference="test fixture"),
    ).id
    hypothesis = Hypothesis(
        provenance=Provenance(
            source_type="reasoning",
            source_reference="test fixture",
            classification="INFERRED",
        ),
        title="Repeatable response",
        description="The same experiment result may be captured more than once.",
        observation_ids=[observation_id],
        confidence=0.5,
    )
    experiment = Experiment(
        provenance=Provenance(
            source_type="experiment-design",
            source_reference="test fixture",
            classification="INFERRED",
        ),
        hypothesis_id=hypothesis.id,
        variable="repetition",
        action=ExperimentAction(kind="http", parameters={"method": "GET"}),
        expected_if_true="The response repeats.",
        expected_if_false="The response changes.",
    )
    evidence_fields = {
        "experiment_id": experiment.id,
        "request": HTTPRequestRecord(method="GET", url="http://127.0.0.1/health"),
        "response": HTTPResponseRecord(status_code=200, body="ok", elapsed_ms=1.0),
        "provenance": Provenance(source_type="http", source_reference="GET /health"),
        "integrity_hash": sha256(b"same-content").hexdigest(),
    }

    with database.session_factory.begin() as session:
        repositories = RepositorySet(session)
        repositories.hypotheses.add(hypothesis)
        repositories.experiments.add(experiment)
        repositories.evidence.add(Evidence(**evidence_fields))
        repositories.evidence.add(Evidence(**evidence_fields))

    with database.session_factory() as session:
        assert len(RepositorySet(session).evidence.list()) == 2
