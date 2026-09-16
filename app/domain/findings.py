from enum import StrEnum

from pydantic import Field, model_validator

from datetime import datetime

from app.domain.common import EntityModel, Identifier, utc_now
from app.domain.verification import VerificationConfidence


class VerificationStatus(StrEnum):
    SUPPORTED = "SUPPORTED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class Finding(EntityModel):
    research_session_id: Identifier | None = None
    hypothesis_id: Identifier
    experiment_id: Identifier | None = None
    verification_result_id: Identifier | None = None
    verification_result_ids: list[Identifier] = Field(default_factory=list)
    execution_ids: list[Identifier] = Field(default_factory=list)
    title: str | None = Field(default=None, max_length=300)
    claim: str = Field(min_length=1, max_length=5000)
    evidence_ids: list[Identifier] = Field(min_length=1)
    observation_ids: list[Identifier] = Field(default_factory=list)
    reproduction: list[str] = Field(min_length=1)
    control_evidence_ids: list[Identifier] = Field(default_factory=list)
    impact: str = Field(min_length=1, max_length=3000)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    hypothesis_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    verification_confidence: VerificationConfidence = VerificationConfidence.LOW
    verification_status: VerificationStatus
    limitations: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def supported_requires_control(self) -> "Finding":
        if (
            self.verification_status is VerificationStatus.SUPPORTED
            and not self.control_evidence_ids
        ):
            raise ValueError("SUPPORTED findings require control evidence")
        return self
