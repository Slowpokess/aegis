from enum import StrEnum

from pydantic import Field, model_validator

from app.domain.common import DomainModel, EntityModel, Identifier


class HypothesisStatus(StrEnum):
    NEW = "NEW"
    TESTING = "TESTING"
    SUPPORTED = "SUPPORTED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class MissingInformation(DomainModel):
    description: str = Field(min_length=1, max_length=2000)
    related_observation_ids: list[Identifier] = Field(default_factory=list)
    gap_type: str | None = Field(default=None, max_length=100)
    subject_entity_id: Identifier | None = None
    target_entity_id: Identifier | None = None
    resource_entity_id: Identifier | None = None
    expected_fact: str | None = Field(default=None, max_length=500)


class Hypothesis(EntityModel):
    research_session_id: Identifier | None = None
    title: str = Field(min_length=1, max_length=300)
    description: str = Field(min_length=1, max_length=5000)
    observation_ids: list[Identifier] = Field(min_length=1)
    evidence_ids: list[Identifier] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    missing_information: list[MissingInformation | str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    status: HypothesisStatus = HypothesisStatus.NEW
    llm_run_id: Identifier | None = None

    @model_validator(mode="after")
    def require_verification_for_supported(self) -> "Hypothesis":
        if self.status is HypothesisStatus.SUPPORTED and not self.evidence_ids:
            raise ValueError("SUPPORTED hypotheses require evidence_ids")
        return self
