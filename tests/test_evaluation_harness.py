from pathlib import Path

from app.config import Settings
from app.domain.evaluation import BenchmarkMode
from evals.ground_truth import ground_truth_sha256
from evals.harness import harness_sha256, load_harness
from evals.runner import canonical_sha256, current_git_commit, sanitized_configuration
from lab.ground_truth import load_ground_truth


def test_ground_truth_and_neutral_harness_load_and_hash_deterministically() -> None:
    truth = load_ground_truth()
    harness = load_harness()
    assert len(truth) == len(harness.scenarios) == 8
    assert {item.id for item in truth} == {item.scenario_id for item in harness.scenarios}
    assert ground_truth_sha256(truth) == ground_truth_sha256(tuple(reversed(truth)))
    assert len(ground_truth_sha256(truth)) == 64
    assert harness_sha256(harness) == harness_sha256(load_harness())
    assert harness.version == "harness-v1"


def test_configuration_snapshot_is_canonical_and_secret_free() -> None:
    settings = Settings(anthropic_api_key="do-not-export")
    snapshot = sanitized_configuration(settings, BenchmarkMode.DETERMINISTIC)
    serialized = str(snapshot)
    assert "do-not-export" not in serialized
    assert "api_key" not in serialized.lower()
    assert canonical_sha256(snapshot) == canonical_sha256(dict(reversed(snapshot.items())))
    assert current_git_commit() is None


def test_production_research_layers_do_not_depend_on_eval_or_ground_truth() -> None:
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for root in (
            Path("app/reasoning"),
            Path("app/execution"),
            Path("app/verification"),
            Path("app/collectors"),
        )
        for path in root.rglob("*.py")
    )
    assert "import evals" not in source
    assert "from evals" not in source
    assert "lab.ground_truth" not in source
    assert "lab/scenarios" not in source


def test_app_package_does_not_import_evaluation_package() -> None:
    source = "\n".join(
        path.read_text(encoding="utf-8") for path in Path("app").rglob("*.py")
    )
    assert "import evals" not in source
    assert "from evals" not in source
