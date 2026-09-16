import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from time import monotonic
from uuid import UUID

from app.collectors.pipeline import ObservationPipeline
from app.config import Settings
from app.domain.assets import Asset, AssetKind
from app.domain.common import FactClassification, Provenance, utc_now
from app.domain.evaluation import (
    BenchmarkMode,
    BenchmarkRun,
    BenchmarkStatus,
    FailureStage,
    PipelineMetrics,
    ScenarioRun,
    ScenarioRunStatus,
)
from app.domain.experiments import (
    ExperimentExecution,
    ExperimentExecutionStatus,
    ExperimentStatus,
)
from app.domain.research import ResearchSession, ResearchSessionStatus, ResearchTarget, TargetScope
from app.domain.verification import VERIFIER_VERSION, VerificationVerdict
from app.execution.experiments import ExperimentRunner
from app.execution.identity import LaboratoryIdentityResolver
from app.execution.rust_executor import RustExecutorClient
from app.execution.rust_policy import RustPolicyClient
from app.llm.providers.fake import FakeLLMProvider
from app.llm.base import LLMProviderError
from app.reasoning.experiments import ExperimentEngine
from app.reasoning.hypotheses import HypothesisEngine
from app.reasoning.prompts import EXPERIMENT_PROMPT_VERSION, PROMPT_VERSION
from app.storage.database import Database
from app.storage.repositories import RepositorySet
from app.verification.verifier import VerificationEngine
from evals.evaluator import evaluate_scenario
from evals.ground_truth import ground_truth_sha256
from evals.harness import harness_by_id, harness_sha256, load_harness
from evals.metrics import aggregate_metrics
from evals.schemas import HarnessExecutionMode, ScenarioHarness
from lab.ground_truth import load_ground_truth


@dataclass(frozen=True)
class ScenarioActual:
    scenario_run: ScenarioRun
    verdict: VerificationVerdict | None
    hypothesis_ids: list[UUID]
    experiment_ids: list[UUID]
    verification_ids: list[UUID]
    finding_ids: list[UUID]
    metrics: PipelineMetrics
    duration_ms: int


def sanitized_configuration(settings: Settings, mode: BenchmarkMode) -> dict[str, object]:
    return {
        "mode": mode.value,
        "provider": "fake" if mode is BenchmarkMode.DETERMINISTIC else settings.llm_provider,
        "model": "deterministic-fixture-v1" if mode is BenchmarkMode.DETERMINISTIC else settings.llm_model,
        "context_limits": {
            "max_observations": settings.llm_context_max_observations,
            "max_body_characters": settings.llm_context_max_body_characters,
            "max_total_characters": settings.llm_context_max_total_characters,
        },
        "max_hypotheses": settings.max_hypotheses_per_run,
        "llm_timeout_seconds": settings.llm_timeout_seconds,
        "policy": {
            "max_requests_per_minute": settings.policy_max_requests_per_minute,
            "max_response_bytes": settings.policy_max_response_bytes,
            "max_timeout_ms": settings.policy_max_timeout_ms,
            "follow_redirects": False,
        },
        "verification_minimum_runs": settings.min_verification_runs,
        "hypothesis_prompt_version": PROMPT_VERSION,
        "experiment_prompt_version": EXPERIMENT_PROMPT_VERSION,
        "target": {
            "host": settings.eval_target_host,
            "port": settings.eval_target_port,
            "scheme": settings.eval_target_scheme,
        },
    }


def canonical_sha256(value: object) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def current_git_commit() -> str | None:
    try:
        root = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
        ).stdout.strip()
        if not root or Path(root).resolve() != Path.cwd().resolve():
            return None
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
            cwd=root,
        ).stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


class ScenarioRunner:
    def __init__(self, database: Database, settings: Settings) -> None:
        self.database = database
        self.settings = settings
        self.pipeline = ObservationPipeline(
            database, RustExecutorClient(settings.executor_path)
        )
        self.experiment_runner = ExperimentRunner(
            database,
            RustPolicyClient(
                settings.policy_path, settings.policy_process_timeout_seconds
            ),
            self.pipeline,
            settings,
        )
        self.verifier = VerificationEngine(
            database, min_verification_runs=settings.min_verification_runs
        )
        self.identities = LaboratoryIdentityResolver()

    async def run(self, benchmark_run_id: UUID, harness: ScenarioHarness) -> ScenarioActual:
        started = monotonic()
        research = self._create_research_session(harness.scenario_id)
        scenario_run = ScenarioRun(
            benchmark_run_id=benchmark_run_id,
            scenario_id=harness.scenario_id,
            research_session_id=research.id,
            status=ScenarioRunStatus.RUNNING,
            provenance=self._provenance(harness.scenario_id),
        )
        with self.database.session_factory.begin() as session:
            RepositorySet(session).scenario_runs.add(scenario_run)
        observations = []
        for request in harness.seed_requests:
            identity = self.identities.resolve(request.identity)
            observations.append(
                await self.pipeline.observe(
                    research_session_id=research.id,
                    path=request.path,
                    headers=identity.headers,
                    identity_name=identity.name,
                    identity_roles=list(identity.roles),
                    follow_redirects=False,
                )
            )
        hypothesis_response = {
            "hypotheses": [
                {
                    "title": harness.hypothesis_title,
                    "description": harness.hypothesis_description,
                    "observation_ids": [str(item.observation.id) for item in observations],
                    "evidence_ids": [str(item.evidence.id) for item in observations],
                    "assumptions": ["Candidate and control refer to the declared seeded inputs."],
                    "missing_information": [],
                    "confidence": 0.5,
                }
            ]
        }
        hypothesis_result = await HypothesisEngine(
            self.database,
            FakeLLMProvider([hypothesis_response], model="deterministic-hypothesis-fixture-v1"),
        ).generate(research.id)
        hypothesis = hypothesis_result.hypotheses[0]
        experiment_response = {
            "description": "Deterministic candidate/control pipeline benchmark fixture",
            "changed_variable": harness.changed_variable,
            "constants": ["controlled laboratory", "read-only HTTP"],
            "preconditions": ["seed requests completed"],
            "candidate": harness.candidate.model_dump(mode="json"),
            "control": harness.control.model_dump(mode="json"),
            "expected_if_true": harness.expected_if_true,
            "expected_if_false": harness.expected_if_false,
            "risk": harness.risk.value,
            "verification_spec": harness.verification_spec.model_dump(mode="json"),
        }
        experiment_result = await ExperimentEngine(
            self.database,
            FakeLLMProvider([experiment_response], model="deterministic-experiment-fixture-v1"),
        ).generate(hypothesis.id)
        experiment = experiment_result.experiment
        if experiment.status is not ExperimentStatus.VALIDATED:
            raise RuntimeError("deterministic harness produced an invalid experiment")
        if harness.execution_mode is HarnessExecutionMode.INCOMPLETE:
            execution = ExperimentExecution(
                experiment_id=experiment.id,
                research_session_id=research.id,
                status=ExperimentExecutionStatus.FAILED,
                finished_at=utc_now(),
                error_code="HARNESS_REQUIRED_CONTROL_MISSING",
                provenance=self._provenance(harness.scenario_id),
            )
            with self.database.session_factory.begin() as session:
                RepositorySet(session).experiment_executions.add(execution)
        else:
            execution = (await self.experiment_runner.run(experiment.id)).execution
        verification = self.verifier.verify_execution(execution.id)
        aggregate = self.verifier.aggregate_experiment(experiment.id)
        scenario_run = scenario_run.model_copy(
            update={"status": ScenarioRunStatus.COMPLETED, "finished_at": utc_now()}
        )
        research = research.model_copy(
            update={
                "status": ResearchSessionStatus.COMPLETED,
                "finished_at": utc_now(),
            }
        )
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            repositories.scenario_runs.update(scenario_run)
            repositories.research_sessions.update(research)
        duration_ms = round((monotonic() - started) * 1000)
        metrics = self._collect_metrics(research.id, duration_ms)
        finding_ids = [aggregate.finding.id] if aggregate.finding else []
        return ScenarioActual(
            scenario_run=scenario_run,
            verdict=aggregate.verdict,
            hypothesis_ids=[hypothesis.id],
            experiment_ids=[experiment.id],
            verification_ids=[verification.verification.id],
            finding_ids=finding_ids,
            metrics=metrics,
            duration_ms=duration_ms,
        )

    def failed_actual(
        self, benchmark_run_id: UUID, scenario_id: str, error: Exception
    ) -> ScenarioActual:
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            scenario_run = repositories.scenario_runs.get_by_benchmark_scenario(
                benchmark_run_id, scenario_id
            )
            if scenario_run is None:
                raise error
            provider_failure = isinstance(error, LLMProviderError)
            scenario_run = scenario_run.model_copy(
                update={
                    "status": (
                        ScenarioRunStatus.FAILED_PROVIDER
                        if provider_failure
                        else ScenarioRunStatus.FAILED_PIPELINE
                    ),
                    "finished_at": utc_now(),
                    "failure_stage": (
                        FailureStage.PROVIDER
                        if provider_failure
                        else FailureStage.EXECUTION
                    ),
                    "error_code": (
                        error.code.value if provider_failure else type(error).__name__
                    ),
                    "error": str(error),
                }
            )
            repositories.scenario_runs.update(scenario_run)
            research = repositories.research_sessions.get(
                scenario_run.research_session_id
            )
            if research is not None:
                repositories.research_sessions.update(
                    research.model_copy(
                        update={
                            "status": ResearchSessionStatus.FAILED,
                            "finished_at": utc_now(),
                        }
                    )
                )
        metrics = self._collect_metrics(scenario_run.research_session_id, 0)
        return ScenarioActual(
            scenario_run=scenario_run,
            verdict=None,
            hypothesis_ids=[],
            experiment_ids=[],
            verification_ids=[],
            finding_ids=[],
            metrics=metrics,
            duration_ms=0,
        )

    def _create_research_session(self, scenario_id: str) -> ResearchSession:
        provenance = self._provenance(scenario_id)
        asset = Asset(name=f"eval-{scenario_id}", kind=AssetKind.API, provenance=provenance)
        base_url = (
            f"{self.settings.eval_target_scheme}://{self.settings.eval_target_host}:"
            f"{self.settings.eval_target_port}"
        )
        research = ResearchSession(
            name=f"eval-{scenario_id}",
            target=ResearchTarget(
                asset_id=asset.id,
                name=f"eval-{scenario_id}",
                base_url=base_url,
                provenance=provenance,
            ),
            scope=TargetScope(
                hosts=(self.settings.eval_target_host,),
                ports=(self.settings.eval_target_port,),
                schemes=(self.settings.eval_target_scheme,),
                provenance=provenance,
            ),
            provenance=provenance,
        ).start()
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            repositories.assets.add(asset)
            repositories.research_sessions.add(research)
        return research

    def _collect_metrics(self, research_session_id: UUID, duration_ms: int) -> PipelineMetrics:
        with self.database.session_factory() as session:
            repositories = RepositorySet(session)
            observations = repositories.observations.list_by_session(research_session_id)
            evidence = repositories.evidence.list_by_session(research_session_id)
            experiments = repositories.experiments.list_by_session(research_session_id)
            llm_runs = repositories.llm_runs.list_by_session(research_session_id)
            executions = [
                item
                for item in repositories.experiment_executions.list()
                if item.research_session_id == research_session_id
            ]
            decisions = [
                item
                for item in repositories.policy_decisions.list()
                if item.research_session_id == research_session_id
            ]
            verifications = [
                item
                for item in repositories.verification_results.list()
                if item.research_session_id == research_session_id
            ]
            findings = repositories.findings.list_by_session(research_session_id)
        token_fields = ("input_tokens", "output_tokens", "total_tokens", "latency_ms")
        token_totals: dict[str, int | None] = {}
        for field in token_fields:
            values = [getattr(item, field) for item in llm_runs]
            token_totals[field] = (
                sum(value for value in values if value is not None)
                if values and all(value is not None for value in values)
                else None
            )
        return PipelineMetrics(
            observations=len(observations),
            evidence_records=len(evidence),
            hypotheses_generated=sum(item.generated_count for item in llm_runs if item.purpose.value == "HYPOTHESIS_GENERATION"),
            hypotheses_accepted=sum(item.accepted_count for item in llm_runs if item.purpose.value == "HYPOTHESIS_GENERATION"),
            hypotheses_rejected=sum(item.rejected_count for item in llm_runs if item.purpose.value == "HYPOTHESIS_GENERATION"),
            experiments_generated=len(experiments),
            experiments_validated=sum(item.status is not ExperimentStatus.DRAFT for item in experiments),
            experiments_rejected=sum(item.status is ExperimentStatus.DRAFT for item in experiments),
            policy_approvals=sum(item.allowed for item in decisions),
            policy_rejections=sum(not item.allowed for item in decisions),
            experiment_executions=len(executions),
            verification_runs=len(verifications),
            findings=len(findings),
            http_requests=len(evidence),
            llm_runs=len(llm_runs),
            llm_input_tokens=token_totals["input_tokens"],
            llm_output_tokens=token_totals["output_tokens"],
            llm_total_tokens=token_totals["total_tokens"],
            llm_latency_ms=token_totals["latency_ms"],
            runtime_ms=duration_ms,
        )

    @staticmethod
    def _provenance(scenario_id: str) -> Provenance:
        return Provenance(
            source_type="evaluation-harness",
            source_reference=scenario_id,
            collector="aegis-scenario-runner",
            classification=FactClassification.OBSERVED,
        )


class BenchmarkRunner:
    def __init__(self, database: Database, settings: Settings) -> None:
        self.database = database
        self.settings = settings

    async def run(
        self,
        *,
        mode: BenchmarkMode,
        scenario_ids: list[str] | None = None,
        name: str = "phase6-benchmark",
    ) -> BenchmarkRun:
        if mode is BenchmarkMode.LIVE_LLM:
            raise ValueError("LIVE_LLM benchmark requires a separately configured model harness")
        dataset = load_harness()
        harnesses = harness_by_id(dataset)
        selected = scenario_ids or sorted(harnesses)
        unknown = sorted(set(selected) - set(harnesses))
        if unknown:
            raise ValueError(f"unknown harness scenarios: {', '.join(unknown)}")
        snapshot = sanitized_configuration(self.settings, mode)
        run = BenchmarkRun(
            name=name,
            mode=mode,
            status=BenchmarkStatus.RUNNING,
            provider="fake",
            model="deterministic-fixture-v1",
            hypothesis_prompt_version=PROMPT_VERSION,
            experiment_prompt_version=EXPERIMENT_PROMPT_VERSION,
            verifier_version=VERIFIER_VERSION,
            git_commit=current_git_commit(),
            scenario_count=len(selected),
            configuration_snapshot=snapshot,
            configuration_sha256=canonical_sha256(snapshot),
            harness_version=dataset.version,
            harness_sha256=harness_sha256(dataset),
            provenance=Provenance(
                source_type="evaluation",
                source_reference=name,
                collector="aegis-benchmark-runner",
                classification=FactClassification.OBSERVED,
            ),
        )
        with self.database.session_factory.begin() as session:
            RepositorySet(session).benchmark_runs.add(run)
        started = monotonic()
        scenario_runner = ScenarioRunner(self.database, self.settings)
        actuals: list[ScenarioActual] = []
        for scenario_id in selected:
            try:
                actuals.append(await scenario_runner.run(run.id, harnesses[scenario_id]))
            except Exception as error:
                actuals.append(scenario_runner.failed_actual(run.id, scenario_id, error))

        # Ground truth enters only after every selected research workflow has completed.
        truths = {item.id: item for item in load_ground_truth()}
        evaluations = []
        for actual in actuals:
            truth = truths[actual.scenario_run.scenario_id]
            evaluation = evaluate_scenario(
                truth=truth,
                scenario_run=actual.scenario_run,
                actual_verdict=actual.verdict,
                hypothesis_ids=actual.hypothesis_ids,
                experiment_ids=actual.experiment_ids,
                verification_ids=actual.verification_ids,
                finding_ids=actual.finding_ids,
                metrics=actual.metrics,
                duration_ms=actual.duration_ms,
            )
            with self.database.session_factory.begin() as session:
                RepositorySet(session).scenario_evaluations.add(evaluation)
            evaluations.append(evaluation)
        runtime_ms = round((monotonic() - started) * 1000)
        metrics = aggregate_metrics(evaluations, benchmark_runtime_ms=runtime_ms)
        executor_version = self._executor_version(evaluations)
        has_failures = any(
            item.scenario_run.status is not ScenarioRunStatus.COMPLETED
            for item in actuals
        )
        run = run.model_copy(
            update={
                "status": BenchmarkStatus.PARTIAL if has_failures else BenchmarkStatus.COMPLETED,
                "finished_at": utc_now(),
                "ground_truth_sha256": ground_truth_sha256(tuple(truths.values())),
                "metrics": metrics,
                "executor_version": executor_version,
            }
        )
        with self.database.session_factory.begin() as session:
            RepositorySet(session).benchmark_runs.update(run)
        return run

    def _executor_version(self, evaluations: list) -> str | None:
        session_ids = {item.research_session_id for item in evaluations}
        with self.database.session_factory() as session:
            evidence = RepositorySet(session).evidence.list()
        versions = sorted(
            {
                item.executor_version
                for item in evidence
                if item.research_session_id in session_ids and item.executor_version is not None
            }
        )
        return versions[0] if len(versions) == 1 else None
