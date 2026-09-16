from pydantic import Field

from app.domain.experiments import HTTPExperimentAction, RiskLevel
from app.reasoning.schemas import ReasoningModel
from app.domain.verification import VerificationSpec


class ExperimentProposal(ReasoningModel):
    description: str = Field(min_length=1, max_length=5000)
    changed_variable: str = Field(min_length=1, max_length=500)
    constants: list[str]
    preconditions: list[str]
    candidate: HTTPExperimentAction
    control: HTTPExperimentAction
    expected_if_true: str = Field(min_length=1, max_length=2000)
    expected_if_false: str = Field(min_length=1, max_length=2000)
    risk: RiskLevel
    verification_spec: VerificationSpec | None = None
