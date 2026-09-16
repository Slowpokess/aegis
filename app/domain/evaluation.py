from datetime import datetime
from enum import StrEnum

from pydantic import Field, model_validator

from app.domain.common import DomainModel, EntityModel, Identifier, JsonObject, utc_now
from app.domain.verification import VerificationVerdict

EVALUATOR_VERSION = "evaluation-v1"


class BenchmarkMode(StrEnum):
    DETERMINISTIC = "DETERMINISTIC"
    LIVE_LLM = "LIVE_LLM"


class BenchmarkStatus(StrEnum):
    CREATED = "CREATED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"


class ScenarioRunStatus(StrEnum):
    CREATED = "CREATED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED_PROVIDER = "FAILED_PROVIDER"
    FAILED_PIPELINE = "FAILED_PIPELINE"


class EvaluationClassification(StrEnum):
    TP = "TP"
    FP = "FP"
    TN = "TN"
    FN = "FN"
    CORRECT_INCONCLUSIVE = "CORRECT_INCONCLUSIVE"
    UNEXPECTED_INCONCLUSIVE = "UNEXPECTED_INCONCLUSIVE"
    NOT_SCORED = "NOT_SCORED"


class FailureStage(StrEnum):
    NONE = "NONE"
    OBSERVATION = "OBSERVATION"
    HYPOTHESIS = "HYPOTHESIS"
    EXPERIMENT = "EXPERIMENT"
    POLICY = "POLICY"
    EXECUTION = "EXECUTION"
    VERIFICATION = "VERIFICATION"
    PROVIDER = "PROVIDER"


class PipelineMetrics(DomainModel):
    observations: int = Field(default=0, ge=0)
    evidence_records: int = Field(default=0, ge=0)
    hypotheses_generated: int = Field(default=0, ge=0)
    hypotheses_accepted: int = Field(default=0, ge=0)
    hypotheses_rejected: int = Field(default=0, ge=0)
    experiments_generated: int = Field(default=0, ge=0)
    experiments_validated: int = Field(default=0, ge=0)
    experiments_rejected: int = Field(default=0, ge=0)
    policy_approvals: int = Field(default=0, ge=0)
    policy_rejections: int = Field(default=0, ge=0)
    experiment_executions: int = Field(default=0, ge=0)
    verification_runs: int = Field(default=0, ge=0)
    findings: int = Field(default=0, ge=0)
    http_requests: int = Field(default=0, ge=0)
    llm_runs: int = Field(default=0, ge=0)
    llm_input_tokens: int | None = Field(default=None, ge=0)
    llm_output_tokens: int | None = Field(default=None, ge=0)
    llm_total_tokens: int | None = Field(default=None, ge=0)
    llm_latency_ms: int | None = Field(default=None, ge=0)
    runtime_ms: int = Field(default=0, ge=0)


class BenchmarkMetrics(PipelineMetrics):
    scenario_count: int = Field(default=0, ge=0)
    completed: int = Field(default=0, ge=0)
    failed: int = Field(default=0, ge=0)
    tp: int = Field(default=0, ge=0)
    fp: int = Field(default=0, ge=0)
    tn: int = Field(default=0, ge=0)
    fn: int = Field(default=0, ge=0)
    correct_inconclusive: int = Field(default=0, ge=0)
    unexpected_inconclusive: int = Field(default=0, ge=0)
    inconclusive_count: int = Field(default=0, ge=0)
    precision: float | None = Field(default=None, ge=0, le=1)
    recall: float | None = Field(default=None, ge=0, le=1)
    f1: float | None = Field(default=None, ge=0, le=1)
    accuracy: float | None = Field(default=None, ge=0, le=1)
    false_positive_rate: float | None = Field(default=None, ge=0, le=1)
    false_negative_rate: float | None = Field(default=None, ge=0, le=1)
    inconclusive_rate: float | None = Field(default=None, ge=0, le=1)
    correct_inconclusive_rate: float | None = Field(default=None, ge=0, le=1)
    requests_per_finding: float | None = Field(default=None, ge=0)
    requests_per_tp: float | None = Field(default=None, ge=0)
    tokens_per_hypothesis: float | None = Field(default=None, ge=0)
    tokens_per_finding: float | None = Field(default=None, ge=0)
    undefined_reasons: dict[str, str] = Field(default_factory=dict)


class BenchmarkRun(EntityModel):
    name: str = Field(min_length=1, max_length=300)
    mode: BenchmarkMode
    status: BenchmarkStatus = BenchmarkStatus.CREATED
    started_at: datetime = Field(default_factory=utc_now)
    finished_at: datetime | None = None
    provider: str
    model: str
    hypothesis_prompt_version: str
    experiment_prompt_version: str
    verifier_version: str
    evaluator_version: str = EVALUATOR_VERSION
    executor_version: str | None = None
    policy_protocol_version: int = 1
    git_commit: str | None = None
    scenario_count: int = Field(default=0, ge=0)
    configuration_snapshot: JsonObject
    configuration_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    ground_truth_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    harness_version: str
    harness_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    metrics: BenchmarkMetrics | None = None
    estimated_cost: float | None = Field(default=None, ge=0)
    error: str | None = Field(default=None, max_length=3000)

    @model_validator(mode="after")
    def finished_status_has_timestamp(self) -> "BenchmarkRun":
        if (
            self.status
            in {
                BenchmarkStatus.COMPLETED,
                BenchmarkStatus.FAILED,
                BenchmarkStatus.PARTIAL,
            }
            and self.finished_at is None
        ):
            raise ValueError("finished benchmark requires finished_at")
        return self


class ScenarioRun(EntityModel):
    benchmark_run_id: Identifier
    scenario_id: str = Field(pattern=r"^LAB-[0-9]{3}$")
    research_session_id: Identifier
    status: ScenarioRunStatus = ScenarioRunStatus.CREATED
    started_at: datetime = Field(default_factory=utc_now)
    finished_at: datetime | None = None
    failure_stage: FailureStage = FailureStage.NONE
    error_code: str | None = Field(default=None, max_length=100)
    error: str | None = Field(default=None, max_length=3000)


class ScenarioEvaluation(EntityModel):
    benchmark_run_id: Identifier
    scenario_run_id: Identifier
    scenario_id: str = Field(pattern=r"^LAB-[0-9]{3}$")
    research_session_id: Identifier
    expected_vulnerability: bool | None
    expected_verdict: VerificationVerdict
    expected_class: str
    actual_hypothesis_ids: list[Identifier] = Field(default_factory=list)
    actual_experiment_ids: list[Identifier] = Field(default_factory=list)
    actual_verification_ids: list[Identifier] = Field(default_factory=list)
    actual_finding_ids: list[Identifier] = Field(default_factory=list)
    selected_actual_verdict: VerificationVerdict | None = None
    classification: EvaluationClassification
    failure_stage: FailureStage = FailureStage.NONE
    matched_finding_id: Identifier | None = None
    metrics: PipelineMetrics
    duration_ms: int = Field(ge=0)
    created_at: datetime = Field(default_factory=utc_now)
