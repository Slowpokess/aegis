from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.domain.experiments import HTTPExperimentAction, RiskLevel
from app.domain.verification import VerificationSpec


class HarnessExecutionMode(StrEnum):
    FULL = "FULL"
    INCOMPLETE = "INCOMPLETE"


class SeedRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    identity: str
    path: str = Field(pattern=r"^/[^#]*$")


class ScenarioHarness(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    scenario_id: str = Field(pattern=r"^LAB-[0-9]{3}$")
    seed_requests: list[SeedRequest] = Field(min_length=1)
    hypothesis_title: str
    hypothesis_description: str
    changed_variable: str
    candidate: HTTPExperimentAction
    control: HTTPExperimentAction
    expected_if_true: str
    expected_if_false: str
    verification_spec: VerificationSpec
    risk: RiskLevel = RiskLevel.LOW
    execution_mode: HarnessExecutionMode = HarnessExecutionMode.FULL

    @model_validator(mode="after")
    def actions_are_seeded(self) -> "ScenarioHarness":
        seeded = {(item.identity, item.path) for item in self.seed_requests}
        actions = (self.candidate, self.control) if self.execution_mode is HarnessExecutionMode.FULL else (self.candidate,)
        for action in actions:
            if (action.identity, action.path) not in seeded:
                raise ValueError("executable actions must be neutral seeded requests")
        return self


class HarnessDataset(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: str = Field(pattern=r"^harness-v[0-9]+$")
    scenarios: list[ScenarioHarness] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_scenarios(self) -> "HarnessDataset":
        ids = [item.scenario_id for item in self.scenarios]
        if len(ids) != len(set(ids)):
            raise ValueError("harness scenario IDs must be unique")
        return self
