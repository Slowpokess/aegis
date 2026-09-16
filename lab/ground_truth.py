from enum import StrEnum
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

SCENARIO_DIRECTORY = Path(__file__).with_name("scenarios")


class ExpectedVerdict(StrEnum):
    SUPPORTED = "SUPPORTED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class GroundTruthScenario(BaseModel):
    """Developer/eval-only schema. The target application never imports this module."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^LAB-[0-9]{3}$")
    title: str = Field(min_length=1)
    vulnerability: bool | None
    vulnerability_class: str = Field(alias="class", min_length=1)
    actors: list[str] = Field(min_length=1)
    preconditions: list[str] = Field(min_length=1)
    required_evidence: list[str] = Field(min_length=1)
    required_control: list[str]
    expected_verdict: ExpectedVerdict

    @model_validator(mode="after")
    def verdict_matches_vulnerability(self) -> "GroundTruthScenario":
        expected = {
            True: ExpectedVerdict.SUPPORTED,
            False: ExpectedVerdict.REJECTED,
            None: ExpectedVerdict.INCONCLUSIVE,
        }[self.vulnerability]
        if self.expected_verdict is not expected:
            raise ValueError("expected_verdict is inconsistent with vulnerability ground truth")
        return self


def load_ground_truth(
    scenario_directory: Path = SCENARIO_DIRECTORY,
) -> tuple[GroundTruthScenario, ...]:
    scenarios: list[GroundTruthScenario] = []
    for path in sorted(scenario_directory.glob("LAB-*.yaml")):
        with path.open(encoding="utf-8") as scenario_file:
            raw = yaml.safe_load(scenario_file)
        scenarios.append(GroundTruthScenario.model_validate(raw))

    ids = [scenario.id for scenario in scenarios]
    if len(ids) != len(set(ids)):
        raise ValueError("scenario IDs must be unique")
    return tuple(scenarios)
