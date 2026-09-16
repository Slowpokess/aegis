from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import Field, model_validator

from app.domain.common import DomainModel, EntityModel, Identifier, utc_now

VERIFIER_VERSION = "verification-v1"


class VerificationVerdict(StrEnum):
    SUPPORTED = "SUPPORTED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class VerificationConfidence(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ComparisonType(StrEnum):
    STATUS_CODE = "STATUS_CODE"
    HEADER_PRESENCE = "HEADER_PRESENCE"
    HEADER_VALUE = "HEADER_VALUE"
    REDIRECT = "REDIRECT"
    CONTENT_TYPE = "CONTENT_TYPE"
    BODY_LENGTH = "BODY_LENGTH"
    BODY_HASH = "BODY_HASH"
    JSON_VALIDITY = "JSON_VALIDITY"
    JSON_FIELD_PRESENCE = "JSON_FIELD_PRESENCE"
    JSON_FIELD_VALUE = "JSON_FIELD_VALUE"
    NORMALIZED_JSON = "NORMALIZED_JSON"


class ComparisonOperator(StrEnum):
    EQUAL = "EQUAL"
    NOT_EQUAL = "NOT_EQUAL"
    PRESENT = "PRESENT"
    ABSENT = "ABSENT"
    GREATER_THAN = "GREATER_THAN"
    LESS_THAN = "LESS_THAN"


class ComparisonSpec(DomainModel):
    type: ComparisonType
    operator: ComparisonOperator
    field: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.-]+$")
    required: bool = True
    impact: bool = False

    @model_validator(mode="after")
    def validate_field_and_operator(self) -> "ComparisonSpec":
        field_types = {
            ComparisonType.HEADER_PRESENCE,
            ComparisonType.HEADER_VALUE,
            ComparisonType.JSON_FIELD_PRESENCE,
            ComparisonType.JSON_FIELD_VALUE,
        }
        if self.type in field_types and self.field is None:
            raise ValueError(f"{self.type.value} requires field")
        if self.type not in field_types and self.field is not None:
            raise ValueError(f"{self.type.value} does not accept field")
        if self.operator in {
            ComparisonOperator.PRESENT,
            ComparisonOperator.ABSENT,
        } and self.type not in {
            ComparisonType.HEADER_PRESENCE,
            ComparisonType.JSON_FIELD_PRESENCE,
        }:
            raise ValueError("PRESENT/ABSENT operators require a presence comparator")
        if self.operator in {
            ComparisonOperator.GREATER_THAN,
            ComparisonOperator.LESS_THAN,
        } and self.type not in {
            ComparisonType.STATUS_CODE,
            ComparisonType.BODY_LENGTH,
        }:
            raise ValueError("ordered operators require a numeric comparator")
        return self


class VerificationSpec(DomainModel):
    rule_id: str = Field(min_length=1, max_length=100, pattern=r"^[a-z0-9_-]+$")
    rule_version: str = Field(min_length=1, max_length=50, pattern=r"^v[0-9]+$")
    comparisons: list[ComparisonSpec] = Field(min_length=1, max_length=20)

    @property
    def has_required_impact(self) -> bool:
        return any(item.required and item.impact for item in self.comparisons)


class ComparisonResult(DomainModel):
    comparator: ComparisonType
    operator: ComparisonOperator
    field: str | None = None
    candidate: Any = None
    control: Any = None
    complete: bool
    matched: bool | None
    required: bool
    impact: bool
    reason: str


class VerificationResult(EntityModel):
    research_session_id: Identifier
    hypothesis_id: Identifier
    experiment_id: Identifier
    execution_id: Identifier
    candidate_evidence_id: Identifier | None = None
    control_evidence_id: Identifier | None = None
    candidate_observation_id: Identifier | None = None
    control_observation_id: Identifier | None = None
    verdict: VerificationVerdict
    verifier_version: str = VERIFIER_VERSION
    rule_id: str
    rule_version: str
    comparisons: list[ComparisonResult] = Field(default_factory=list)
    reason: str = Field(min_length=1, max_length=3000)
    evidence_integrity_valid: bool
    verification_confidence: VerificationConfidence
    created_at: datetime = Field(default_factory=utc_now)
