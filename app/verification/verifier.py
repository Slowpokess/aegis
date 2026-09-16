from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.domain.common import FactClassification, Provenance
from app.domain.evidence import Evidence
from app.domain.experiments import Experiment, ExperimentExecution, ExperimentExecutionStatus, ExperimentRole
from app.domain.findings import Finding, VerificationStatus
from app.domain.hypotheses import Hypothesis, HypothesisStatus
from app.domain.verification import (
    ComparisonResult,
    VerificationConfidence,
    VerificationResult,
    VerificationVerdict,
)
from app.execution.protocol import canonical_evidence_sha256
from app.logging_config import verification_log
from app.storage.database import Database
from app.storage.repositories import RepositorySet
from app.verification.comparisons import EvidenceComparator, captured_body


class VerificationEngineResult(BaseModel):
    model_config = ConfigDict(frozen=True)
    verification: VerificationResult
    finding: Finding | None


class AggregateVerification(BaseModel):
    model_config = ConfigDict(frozen=True)
    experiment_id: UUID
    verdict: VerificationVerdict
    verification_result_ids: list[UUID]
    reproduction_count: int
    minimum_runs: int
    finding: Finding | None


class VerificationEngine:
    def __init__(
        self,
        database: Database,
        *,
        min_verification_runs: int = 1,
        comparator: EvidenceComparator | None = None,
    ) -> None:
        if min_verification_runs < 1:
            raise ValueError("min_verification_runs must be positive")
        self.database = database
        self.min_verification_runs = min_verification_runs
        self.comparator = comparator or EvidenceComparator()

    def verify_execution(self, execution_id: UUID) -> VerificationEngineResult:
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            execution = repositories.experiment_executions.get(execution_id)
            if execution is None:
                raise ValueError("experiment execution does not exist")
            experiment = repositories.experiments.get(execution.experiment_id)
            if experiment is None:
                raise ValueError("experiment does not exist")
            hypothesis = repositories.hypotheses.get(experiment.hypothesis_id)
            if hypothesis is None:
                raise ValueError("hypothesis does not exist")
            verification = self._verify(repositories, execution, experiment, hypothesis)
        with self.database.session_factory.begin() as session:
            RepositorySet(session).verification_results.add(verification)
        aggregate = self.aggregate_experiment(experiment.id)
        verification_log.info(
            "verification execution_id=%s result_id=%s verdict=%s rule=%s/%s",
            execution.id,
            verification.id,
            verification.verdict.value,
            verification.rule_id,
            verification.rule_version,
        )
        return VerificationEngineResult(verification=verification, finding=aggregate.finding)

    def verify_experiment(self, experiment_id: UUID) -> AggregateVerification:
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            experiment = repositories.experiments.get(experiment_id)
            if experiment is None:
                raise ValueError("experiment does not exist")
            executions = repositories.experiment_executions.list_by_experiment(experiment_id)
            verified_execution_ids = {
                item.execution_id
                for item in repositories.verification_results.list_by_experiment(experiment_id)
            }
        for execution in executions:
            if execution.id not in verified_execution_ids:
                self.verify_execution(execution.id)
        return self.aggregate_experiment(experiment_id)

    def aggregate_experiment(self, experiment_id: UUID) -> AggregateVerification:
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            experiment = repositories.experiments.get(experiment_id)
            if experiment is None:
                raise ValueError("experiment does not exist")
            hypothesis = repositories.hypotheses.get(experiment.hypothesis_id)
            if hypothesis is None:
                raise ValueError("hypothesis does not exist")
            all_results = repositories.verification_results.list_by_experiment(experiment_id)
            latest_by_execution: dict[UUID, VerificationResult] = {}
            for result in all_results:
                latest_by_execution[result.execution_id] = result
            results = list(latest_by_execution.values())
            verdict = self._aggregate_verdict(results)
            finding = self._upsert_finding(
                repositories, experiment, hypothesis, results, verdict
            )
            target_status = HypothesisStatus(verdict.value)
            if hypothesis.status is not target_status:
                repositories.hypotheses.update(
                    hypothesis.model_copy(update={"status": target_status})
                )
        return AggregateVerification(
            experiment_id=experiment_id,
            verdict=verdict,
            verification_result_ids=[item.id for item in results],
            reproduction_count=len(results),
            minimum_runs=self.min_verification_runs,
            finding=finding,
        )

    def _aggregate_verdict(self, results: list[VerificationResult]) -> VerificationVerdict:
        if len(results) < self.min_verification_runs:
            return VerificationVerdict.INCONCLUSIVE
        verdicts = {item.verdict for item in results}
        if verdicts == {VerificationVerdict.SUPPORTED}:
            return VerificationVerdict.SUPPORTED
        if verdicts == {VerificationVerdict.REJECTED}:
            return VerificationVerdict.REJECTED
        return VerificationVerdict.INCONCLUSIVE

    def _verify(
        self,
        repositories: RepositorySet,
        execution: ExperimentExecution,
        experiment: Experiment,
        hypothesis: Hypothesis,
    ) -> VerificationResult:
        rule_id = experiment.verification_spec.rule_id if experiment.verification_spec else "missing-verification-spec"
        rule_version = experiment.verification_spec.rule_version if experiment.verification_spec else "v1"
        base = {
            "research_session_id": execution.research_session_id,
            "hypothesis_id": hypothesis.id,
            "experiment_id": experiment.id,
            "execution_id": execution.id,
            "candidate_evidence_id": execution.candidate_evidence_id,
            "control_evidence_id": execution.control_evidence_id,
            "candidate_observation_id": execution.candidate_observation_id,
            "control_observation_id": execution.control_observation_id,
            "rule_id": rule_id,
            "rule_version": rule_version,
            "provenance": Provenance(
                source_type="deterministic-verification",
                source_reference=str(execution.id),
                collector="aegis-verification-engine",
                classification=FactClassification.INFERRED,
            ),
        }
        lineage = self._load_lineage(repositories, execution, experiment)
        if isinstance(lineage, str):
            return VerificationResult(
                **base,
                verdict=VerificationVerdict.INCONCLUSIVE,
                comparisons=[],
                reason=lineage,
                evidence_integrity_valid=False,
                verification_confidence=VerificationConfidence.LOW,
            )
        candidate, control = lineage
        integrity_reason = self._integrity_error(candidate, control)
        if integrity_reason is not None:
            return VerificationResult(
                **base,
                verdict=VerificationVerdict.INCONCLUSIVE,
                comparisons=[],
                reason=integrity_reason,
                evidence_integrity_valid=False,
                verification_confidence=VerificationConfidence.LOW,
            )
        if experiment.verification_spec is None:
            return VerificationResult(
                **base,
                verdict=VerificationVerdict.INCONCLUSIVE,
                comparisons=[],
                reason="experiment has no typed verification specification",
                evidence_integrity_valid=True,
                verification_confidence=VerificationConfidence.LOW,
            )
        comparisons = [
            self.comparator.compare(item, candidate, control)
            for item in experiment.verification_spec.comparisons
        ]
        verdict, reason, confidence = self._comparison_verdict(
            comparisons, experiment.verification_spec.has_required_impact
        )
        return VerificationResult(
            **base,
            verdict=verdict,
            comparisons=comparisons,
            reason=reason,
            evidence_integrity_valid=True,
            verification_confidence=confidence,
        )

    def _load_lineage(
        self,
        repositories: RepositorySet,
        execution: ExperimentExecution,
        experiment: Experiment,
    ) -> tuple[Evidence, Evidence] | str:
        if execution.status is not ExperimentExecutionStatus.EXECUTED:
            return "experiment execution is incomplete or policy-rejected"
        if execution.research_session_id != experiment.research_session_id:
            return "execution and experiment research sessions do not match"
        identifiers = (
            execution.candidate_evidence_id,
            execution.control_evidence_id,
            execution.candidate_observation_id,
            execution.control_observation_id,
        )
        if any(identifier is None for identifier in identifiers):
            return "candidate/control evidence or observation lineage is missing"
        candidate = repositories.evidence.get(execution.candidate_evidence_id)  # type: ignore[arg-type]
        control = repositories.evidence.get(execution.control_evidence_id)  # type: ignore[arg-type]
        candidate_observation = repositories.observations.get(execution.candidate_observation_id)  # type: ignore[arg-type]
        control_observation = repositories.observations.get(execution.control_observation_id)  # type: ignore[arg-type]
        if any(item is None for item in (candidate, control, candidate_observation, control_observation)):
            return "referenced evidence or observation does not exist"
        if candidate.experiment_role is not ExperimentRole.CANDIDATE or control.experiment_role is not ExperimentRole.CONTROL:  # type: ignore[union-attr]
            return "candidate/control evidence roles are invalid"
        for evidence in (candidate, control):
            if evidence.experiment_id != experiment.id or evidence.research_session_id != execution.research_session_id:  # type: ignore[union-attr]
                return "evidence belongs to another experiment or research session"
        if candidate_observation.evidence_id != candidate.id or control_observation.evidence_id != control.id:  # type: ignore[union-attr]
            return "observation does not reference the expected evidence"
        if candidate_observation.research_session_id != execution.research_session_id or control_observation.research_session_id != execution.research_session_id:  # type: ignore[union-attr]
            return "observation belongs to another research session"
        return candidate, control  # type: ignore[return-value]

    @staticmethod
    def _integrity_error(candidate: Evidence, control: Evidence) -> str | None:
        for role, evidence in (("candidate", candidate), ("control", control)):
            try:
                body = captured_body(evidence)
            except (ValueError, TypeError):
                return f"{role} body encoding is invalid"
            actual = canonical_evidence_sha256(
                method=evidence.request.method,
                url=evidence.request.url,
                request_headers=evidence.request.headers,
                status_code=evidence.response.status_code,
                response_headers=evidence.response.headers,
                body=body,
            )
            if actual != evidence.integrity_hash:
                return f"{role} evidence SHA-256 does not match captured data"
        return None

    @staticmethod
    def _comparison_verdict(
        comparisons: list[ComparisonResult], has_impact: bool
    ) -> tuple[VerificationVerdict, str, VerificationConfidence]:
        required = [item for item in comparisons if item.required]
        if not required or any(not item.complete for item in required):
            return (
                VerificationVerdict.INCONCLUSIVE,
                "one or more required comparisons are unavailable",
                VerificationConfidence.LOW,
            )
        if not has_impact:
            return (
                VerificationVerdict.INCONCLUSIVE,
                "rule has no required observable-impact comparison",
                VerificationConfidence.LOW,
            )
        if all(item.matched for item in required):
            return (
                VerificationVerdict.SUPPORTED,
                "all required relations, including observable impact, matched",
                VerificationConfidence.HIGH,
            )
        return (
            VerificationVerdict.REJECTED,
            "complete evidence contradicted at least one required relation",
            VerificationConfidence.HIGH,
        )

    def _upsert_finding(
        self,
        repositories: RepositorySet,
        experiment: Experiment,
        hypothesis: Hypothesis,
        results: list[VerificationResult],
        verdict: VerificationVerdict,
    ) -> Finding | None:
        existing = repositories.findings.get_by_experiment(experiment.id)
        if verdict is not VerificationVerdict.SUPPORTED and existing is None:
            return None
        evidence_ids = list(
            dict.fromkeys(
                item.candidate_evidence_id
                for item in results
                if item.candidate_evidence_id is not None
            )
        )
        control_ids = list(
            dict.fromkeys(
                item.control_evidence_id
                for item in results
                if item.control_evidence_id is not None
            )
        )
        observation_ids = list(
            dict.fromkeys(
                identifier
                for item in results
                for identifier in (
                    item.candidate_observation_id,
                    item.control_observation_id,
                )
                if identifier is not None
            )
        )
        limitations = []
        if verdict is VerificationVerdict.INCONCLUSIVE:
            limitations.append("repeated executions produced mixed or incomplete verdicts")
        finding_data = {
            "research_session_id": experiment.research_session_id,
            "hypothesis_id": hypothesis.id,
            "experiment_id": experiment.id,
            "verification_result_id": results[-1].id if results else None,
            "verification_result_ids": [item.id for item in results],
            "execution_ids": [item.execution_id for item in results],
            "title": hypothesis.title,
            "claim": (
                f"Deterministic evidence supports hypothesis: {hypothesis.title}"
                if verdict is VerificationVerdict.SUPPORTED
                else f"Previously supported hypothesis is now disputed: {hypothesis.title}"
            ),
            "evidence_ids": evidence_ids or (existing.evidence_ids if existing else []),
            "observation_ids": observation_ids,
            "reproduction": self._reproduction(experiment, results),
            "control_evidence_ids": control_ids or (
                existing.control_evidence_ids if existing else []
            ),
            "impact": "Declared observable-impact comparison matched candidate and control evidence.",
            "confidence": None,
            "hypothesis_confidence": hypothesis.confidence,
            "verification_confidence": (
                VerificationConfidence.HIGH
                if verdict is VerificationVerdict.SUPPORTED
                else VerificationConfidence.LOW
            ),
            "verification_status": VerificationStatus(verdict.value),
            "limitations": limitations,
            "provenance": Provenance(
                source_type="deterministic-verification",
                source_reference=str(experiment.id),
                collector="aegis-verification-engine",
                classification=FactClassification.INFERRED,
            ),
        }
        if existing is None:
            finding = Finding(**finding_data)
            repositories.findings.add(finding)
            return finding
        finding = Finding.model_validate(
            {
                **existing.model_dump(mode="python"),
                **finding_data,
                "id": existing.id,
                "created_at": existing.created_at,
            }
        )
        repositories.findings.update(finding)
        return finding

    @staticmethod
    def _reproduction(
        experiment: Experiment, results: list[VerificationResult]
    ) -> list[str]:
        steps = [f"Run experiment {experiment.id} under its persisted policy."]
        if experiment.control is not None:
            steps.append(
                f"Control: {experiment.control.identity} {experiment.control.method} "
                f"{experiment.control.path}"
            )
        if experiment.candidate is not None:
            steps.append(
                f"Candidate: {experiment.candidate.identity} {experiment.candidate.method} "
                f"{experiment.candidate.path}"
            )
        steps.append(
            "Verify executions: " + ", ".join(str(item.execution_id) for item in results)
        )
        return steps
