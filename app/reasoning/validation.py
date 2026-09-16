import re
from enum import StrEnum
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.domain.evidence import Evidence
from app.domain.hypotheses import Hypothesis
from app.domain.observations import Observation
from app.reasoning.schemas import HypothesisBatch, HypothesisCandidate

_EXPLICIT_PATH = re.compile(r"(?<![A-Za-z0-9])(/api/[A-Za-z0-9_{}./-]+|/health|/login)")


class HypothesisRejectionCode(StrEnum):
    MAX_HYPOTHESES_EXCEEDED = "MAX_HYPOTHESES_EXCEEDED"
    DUPLICATE_HYPOTHESIS = "DUPLICATE_HYPOTHESIS"
    INVALID_OBSERVATION_REFERENCE = "INVALID_OBSERVATION_REFERENCE"
    INVALID_EVIDENCE_REFERENCE = "INVALID_EVIDENCE_REFERENCE"
    CROSS_SESSION_REFERENCE = "CROSS_SESSION_REFERENCE"
    OBSERVATION_EVIDENCE_MISMATCH = "OBSERVATION_EVIDENCE_MISMATCH"
    INVALID_MISSING_INFORMATION_REFERENCE = "INVALID_MISSING_INFORMATION_REFERENCE"
    UNSUPPORTED_CONTEXT_REFERENCE = "UNSUPPORTED_CONTEXT_REFERENCE"


class ValidationModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class HypothesisRejection(ValidationModel):
    index: int
    code: HypothesisRejectionCode
    message: str


class HypothesisValidationResult(ValidationModel):
    accepted: list[HypothesisCandidate]
    rejected: list[HypothesisRejection]


class HypothesisValidator:
    def validate(
        self,
        *,
        batch: HypothesisBatch,
        research_session_id: UUID,
        observations: list[Observation],
        evidence: list[Evidence],
        existing_hypotheses: list[Hypothesis],
        max_hypotheses: int,
    ) -> HypothesisValidationResult:
        observation_by_id = {item.id: item for item in observations}
        evidence_by_id = {item.id: item for item in evidence}
        duplicate_keys = {
            self._duplicate_key(item.title, item.observation_ids) for item in existing_hypotheses
        }
        accepted: list[HypothesisCandidate] = []
        rejected: list[HypothesisRejection] = []
        for index, candidate in enumerate(batch.hypotheses):
            rejection = self._validate_candidate(
                index=index,
                candidate=candidate,
                research_session_id=research_session_id,
                observation_by_id=observation_by_id,
                evidence_by_id=evidence_by_id,
            )
            key = self._duplicate_key(candidate.title, candidate.observation_ids)
            if rejection is None and key in duplicate_keys:
                rejection = HypothesisRejection(
                    index=index,
                    code=HypothesisRejectionCode.DUPLICATE_HYPOTHESIS,
                    message="normalized title and observation references duplicate an existing result",
                )
            if rejection is None and len(accepted) >= max_hypotheses:
                rejection = HypothesisRejection(
                    index=index,
                    code=HypothesisRejectionCode.MAX_HYPOTHESES_EXCEEDED,
                    message="hypothesis exceeds the deterministic per-run limit",
                )
            if rejection is None:
                duplicate_keys.add(key)
                accepted.append(candidate)
            else:
                rejected.append(rejection)
        return HypothesisValidationResult(accepted=accepted, rejected=rejected)

    def _validate_candidate(
        self,
        *,
        index: int,
        candidate: HypothesisCandidate,
        research_session_id: UUID,
        observation_by_id: dict[UUID, Observation],
        evidence_by_id: dict[UUID, Evidence],
    ) -> HypothesisRejection | None:
        if len(set(candidate.observation_ids)) != len(candidate.observation_ids):
            return self._reject(
                index,
                HypothesisRejectionCode.INVALID_OBSERVATION_REFERENCE,
                "observation references contain duplicates",
            )
        if len(set(candidate.evidence_ids)) != len(candidate.evidence_ids):
            return self._reject(
                index,
                HypothesisRejectionCode.INVALID_EVIDENCE_REFERENCE,
                "evidence references contain duplicates",
            )
        cited_observations: list[Observation] = []
        for observation_id in candidate.observation_ids:
            observation = observation_by_id.get(observation_id)
            if observation is None:
                return self._reject(
                    index,
                    HypothesisRejectionCode.INVALID_OBSERVATION_REFERENCE,
                    f"observation does not exist in the supplied context: {observation_id}",
                )
            if observation.research_session_id != research_session_id:
                return self._reject(
                    index,
                    HypothesisRejectionCode.CROSS_SESSION_REFERENCE,
                    f"observation belongs to another research session: {observation_id}",
                )
            cited_observations.append(observation)
        for evidence_id in candidate.evidence_ids:
            item = evidence_by_id.get(evidence_id)
            if item is None:
                return self._reject(
                    index,
                    HypothesisRejectionCode.INVALID_EVIDENCE_REFERENCE,
                    f"evidence does not exist in the supplied session: {evidence_id}",
                )
            if item.research_session_id != research_session_id:
                return self._reject(
                    index,
                    HypothesisRejectionCode.CROSS_SESSION_REFERENCE,
                    f"evidence belongs to another research session: {evidence_id}",
                )
        linked_evidence_ids = {item.evidence_id for item in cited_observations}
        if None in linked_evidence_ids or linked_evidence_ids != set(candidate.evidence_ids):
            return self._reject(
                index,
                HypothesisRejectionCode.OBSERVATION_EVIDENCE_MISMATCH,
                "observation and evidence references do not describe the same provenance links",
            )
        for missing in candidate.missing_information:
            if not set(missing.related_observation_ids) <= set(candidate.observation_ids):
                return self._reject(
                    index,
                    HypothesisRejectionCode.INVALID_MISSING_INFORMATION_REFERENCE,
                    "missing information cites an observation outside the hypothesis",
                )
        cited_paths = {
            urlsplit(evidence_by_id[evidence_id].request.url).path
            for evidence_id in candidate.evidence_ids
        }
        explicit_paths = set(_EXPLICIT_PATH.findall(f"{candidate.title}\n{candidate.description}"))
        if not explicit_paths <= cited_paths:
            return self._reject(
                index,
                HypothesisRejectionCode.UNSUPPORTED_CONTEXT_REFERENCE,
                "hypothesis contains an endpoint not present in its cited observations",
            )
        return None

    @staticmethod
    def _reject(
        index: int, code: HypothesisRejectionCode, message: str
    ) -> HypothesisRejection:
        return HypothesisRejection(index=index, code=code, message=message)

    @staticmethod
    def _duplicate_key(title: str, observation_ids: list[UUID]) -> tuple[str, tuple[str, ...]]:
        normalized_title = " ".join(re.findall(r"\w+", title.casefold()))
        return normalized_title, tuple(sorted(str(item) for item in observation_ids))
