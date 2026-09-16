from pydantic import BaseModel, ConfigDict, Field

from app.domain.common import Identifier


class ReasoningModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class MissingInformationCandidate(ReasoningModel):
    description: str = Field(min_length=1, max_length=2000)
    related_observation_ids: list[Identifier]


class HypothesisCandidate(ReasoningModel):
    title: str = Field(min_length=1, max_length=300)
    description: str = Field(min_length=1, max_length=5000)
    observation_ids: list[Identifier] = Field(min_length=1)
    evidence_ids: list[Identifier] = Field(min_length=1)
    assumptions: list[str]
    missing_information: list[MissingInformationCandidate]
    confidence: float = Field(ge=0.0, le=1.0)


class HypothesisBatch(ReasoningModel):
    hypotheses: list[HypothesisCandidate]
