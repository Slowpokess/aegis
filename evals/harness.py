import hashlib
import json
from pathlib import Path

import yaml

from evals.schemas import HarnessDataset, ScenarioHarness

DEFAULT_HARNESS = Path(__file__).with_name("inputs") / "deterministic-v1.yaml"


def load_harness(path: Path = DEFAULT_HARNESS) -> HarnessDataset:
    with path.open(encoding="utf-8") as stream:
        return HarnessDataset.model_validate(yaml.safe_load(stream))


def harness_sha256(dataset: HarnessDataset) -> str:
    canonical = json.dumps(dataset.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def harness_by_id(dataset: HarnessDataset) -> dict[str, ScenarioHarness]:
    return {item.scenario_id: item for item in dataset.scenarios}
