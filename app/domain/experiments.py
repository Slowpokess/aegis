from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import Field, model_validator

from app.domain.common import DomainModel, EntityModel, Identifier, JsonObject, utc_now
from app.domain.verification import VerificationSpec


class RiskLevel(StrEnum):
    PASSIVE = "PASSIVE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class ExperimentStatus(StrEnum):
    DRAFT = "DRAFT"
    VALIDATED = "VALIDATED"
    POLICY_APPROVED = "POLICY_APPROVED"
    POLICY_REJECTED = "POLICY_REJECTED"
    EXECUTING = "EXECUTING"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"


class ExperimentRole(StrEnum):
    CANDIDATE = "CANDIDATE"
    CONTROL = "CONTROL"


class ExperimentAction(DomainModel):
    """Legacy Phase 0 action payload retained for migration compatibility."""

    kind: str = Field(min_length=1, max_length=100)
    parameters: JsonObject


class HTTPExperimentAction(DomainModel):
    type: Literal["http"] = "http"
    method: str = Field(min_length=1, max_length=20)
    path: str = Field(min_length=1, max_length=2048)
    identity: str = Field(min_length=1, max_length=100)
    headers: dict[str, str] = Field(default_factory=dict)
    follow_redirects: bool = False
    timeout_ms: int = Field(default=5000, ge=1, le=60_000)
    max_response_bytes: int = Field(default=100_000, ge=1, le=10_000_000)


class Experiment(EntityModel):
    research_session_id: Identifier | None = None
    hypothesis_id: Identifier
    description: str | None = Field(default=None, max_length=5000)
    changed_variable: str = Field(min_length=1, max_length=500)
    constants: list[str] | JsonObject = Field(default_factory=list)
    preconditions: list[str] = Field(default_factory=list)
    candidate: HTTPExperimentAction | None = None
    control: HTTPExperimentAction | None = None
    expected_if_true: str = Field(min_length=1, max_length=2000)
    expected_if_false: str = Field(min_length=1, max_length=2000)
    required_observation_ids: list[Identifier] = Field(default_factory=list)
    risk: RiskLevel = RiskLevel.LOW
    status: ExperimentStatus = ExperimentStatus.DRAFT
    created_at: datetime = Field(default_factory=utc_now)
    llm_run_id: Identifier | None = None
    validation_errors: list[JsonObject] = Field(default_factory=list)
    verification_spec: VerificationSpec | None = None

    # Legacy Phase 0 fields remain readable but are not used by the Phase 4 runner.
    action: ExperimentAction | None = None
    control_experiment_id: Identifier | None = None
    is_control: bool = False

    @model_validator(mode="before")
    @classmethod
    def migrate_legacy_variable(cls, value: Any) -> Any:
        if isinstance(value, dict) and "changed_variable" not in value and "variable" in value:
            value = dict(value)
            value["changed_variable"] = value.pop("variable")
        return value

    @model_validator(mode="after")
    def validate_lifecycle(self) -> "Experiment":
        if self.control_experiment_id == self.id:
            raise ValueError("an experiment cannot be its own control")
        if self.status is not ExperimentStatus.DRAFT and (
            self.candidate is None or self.control is None or self.research_session_id is None
        ):
            raise ValueError(
                "non-DRAFT Phase 4 experiments require session, candidate, and control"
            )
        return self


class ExperimentExecutionStatus(StrEnum):
    CREATED = "CREATED"
    POLICY_REJECTED = "POLICY_REJECTED"
    EXECUTING = "EXECUTING"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"


class ExperimentExecution(EntityModel):
    experiment_id: Identifier
    research_session_id: Identifier
    status: ExperimentExecutionStatus = ExperimentExecutionStatus.CREATED
    started_at: datetime = Field(default_factory=utc_now)
    finished_at: datetime | None = None
    candidate_policy_decision_id: Identifier | None = None
    control_policy_decision_id: Identifier | None = None
    candidate_evidence_id: Identifier | None = None
    candidate_observation_id: Identifier | None = None
    control_evidence_id: Identifier | None = None
    control_observation_id: Identifier | None = None
    error_code: str | None = Field(default=None, max_length=100)

    @model_validator(mode="after")
    def validate_completion(self) -> "ExperimentExecution":
        if (
            self.status
            in {
                ExperimentExecutionStatus.POLICY_REJECTED,
                ExperimentExecutionStatus.EXECUTED,
                ExperimentExecutionStatus.FAILED,
            }
            and self.finished_at is None
        ):
            raise ValueError("finished experiment execution requires finished_at")
        if self.status is ExperimentExecutionStatus.EXECUTED and (
            self.candidate_evidence_id is None
            or self.candidate_observation_id is None
            or self.control_evidence_id is None
            or self.control_observation_id is None
        ):
            raise ValueError("EXECUTED experiment requires candidate and control lineage")
        return self
