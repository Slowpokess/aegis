import hashlib
import json
from pathlib import Path

from lab.ground_truth import GroundTruthScenario, load_ground_truth


def ground_truth_sha256(scenarios: tuple[GroundTruthScenario, ...] | None = None) -> str:
    loaded = scenarios if scenarios is not None else load_ground_truth()
    payload = [
        item.model_dump(mode="json", by_alias=True)
        for item in sorted(loaded, key=lambda scenario: scenario.id)
    ]
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def ground_truth_source_paths() -> tuple[Path, ...]:
    return tuple(sorted(Path("lab/scenarios").glob("LAB-*.yaml")))
