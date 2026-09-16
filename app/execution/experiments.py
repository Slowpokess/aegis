from datetime import timedelta
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict

from app.collectors.pipeline import ObservationPipeline, ObservationResult
from app.config import Settings
from app.domain.common import FactClassification, Provenance, utc_now
from app.domain.experiments import (
    Experiment,
    ExperimentExecution,
    ExperimentExecutionStatus,
    ExperimentRole,
    ExperimentStatus,
    HTTPExperimentAction,
)
from app.domain.hypotheses import HypothesisStatus
from app.domain.policy import PolicyDecisionAudit, PolicyReasonCode
from app.execution.identity import LaboratoryIdentityResolver
from app.execution.policy_protocol import (
    PolicyAction,
    PolicyConfig,
    PolicyReasonCode as ProtocolReasonCode,
    PolicyRequest,
    PolicyResponse,
)
from app.execution.protocol import HttpMethod
from app.execution.rust_policy import PolicyClientError, RustPolicyClient
from app.logging_config import experiment_log
from app.storage.database import Database
from app.storage.repositories import RepositorySet


class ExperimentCheckResult(BaseModel):
    model_config = ConfigDict(frozen=True)
    candidate: PolicyDecisionAudit
    control: PolicyDecisionAudit

    @property
    def allowed(self) -> bool:
        return self.candidate.allowed and self.control.allowed


class ExperimentRunResult(BaseModel):
    model_config = ConfigDict(frozen=True)
    execution: ExperimentExecution
    candidate: ObservationResult | None = None
    control: ObservationResult | None = None


class ExperimentRunner:
    def __init__(
        self,
        database: Database,
        policy_client: RustPolicyClient,
        observation_pipeline: ObservationPipeline,
        settings: Settings,
        identity_resolver: LaboratoryIdentityResolver | None = None,
    ) -> None:
        self.database = database
        self.policy_client = policy_client
        self.observation_pipeline = observation_pipeline
        self.settings = settings
        self.identity_resolver = identity_resolver or LaboratoryIdentityResolver()

    def _load(self, experiment_id: UUID) -> tuple[Experiment, object]:
        with self.database.session_factory() as session:
            repositories = RepositorySet(session)
            experiment = repositories.experiments.get(experiment_id)
            if experiment is None or experiment.research_session_id is None:
                raise ValueError("experiment does not exist or lacks session lineage")
            research_session = repositories.research_sessions.get(experiment.research_session_id)
        if research_session is None:
            raise ValueError("research session does not exist")
        if experiment.status is ExperimentStatus.DRAFT:
            raise ValueError("DRAFT experiment cannot be policy checked or executed")
        return experiment, research_session

    def _policy(self, research_session: object) -> PolicyConfig:
        scope = research_session.scope  # type: ignore[attr-defined]
        return PolicyConfig(
            allowed_hosts=list(scope.hosts),
            allowed_ports=list(scope.ports),
            allowed_schemes=list(scope.schemes),
            allowed_methods=["GET", "HEAD", "OPTIONS"],
            max_requests_per_minute=self.settings.policy_max_requests_per_minute,
            max_response_bytes=self.settings.policy_max_response_bytes,
            max_timeout_ms=self.settings.policy_max_timeout_ms,
            follow_redirects=False,
        )

    @staticmethod
    def _policy_action(action: HTTPExperimentAction, base_url: str) -> PolicyAction:
        return PolicyAction(
            method=action.method.upper(),
            url=f"{base_url.rstrip('/')}{action.path}",
            headers=action.headers,
            timeout_ms=action.timeout_ms,
            max_response_bytes=action.max_response_bytes,
            follow_redirects=action.follow_redirects,
        )

    async def check(
        self, experiment_id: UUID, *, execution_id: UUID | None = None
    ) -> ExperimentCheckResult:
        experiment, research_session = self._load(experiment_id)
        if experiment.candidate is None or experiment.control is None:
            raise ValueError("validated experiment requires candidate and control")
        policy = self._policy(research_session)
        control = await self._decide(
            experiment,
            ExperimentRole.CONTROL,
            experiment.control,
            research_session.target.base_url,  # type: ignore[attr-defined]
            policy,
            execution_id,
        )
        candidate = await self._decide(
            experiment,
            ExperimentRole.CANDIDATE,
            experiment.candidate,
            research_session.target.base_url,  # type: ignore[attr-defined]
            policy,
            execution_id,
        )
        status = ExperimentStatus.POLICY_APPROVED if candidate.allowed and control.allowed else ExperimentStatus.POLICY_REJECTED
        updated = Experiment.model_validate(
            {**experiment.model_dump(mode="python"), "status": status}
        )
        with self.database.session_factory.begin() as session:
            RepositorySet(session).experiments.update(updated)
        return ExperimentCheckResult(candidate=candidate, control=control)

    async def _decide(
        self,
        experiment: Experiment,
        role: ExperimentRole,
        action: HTTPExperimentAction,
        base_url: str,
        policy: PolicyConfig,
        execution_id: UUID | None,
    ) -> PolicyDecisionAudit:
        decision_id = f"DEC-{uuid4()}"
        response = await self.policy_client.evaluate(
            PolicyRequest(
                decision_id=decision_id,
                policy=policy,
                action=self._policy_action(action, base_url),
            )
        )
        return self._persist_decision(experiment, role, execution_id, response)

    def _persist_decision(
        self,
        experiment: Experiment,
        role: ExperimentRole,
        execution_id: UUID | None,
        response: PolicyResponse,
    ) -> PolicyDecisionAudit:
        if response.policy_sha256 is None:
            raise PolicyClientError("policy did not return a policy hash; action denied")
        audit = PolicyDecisionAudit(
            decision_id=response.decision_id or "missing",
            research_session_id=experiment.research_session_id,  # type: ignore[arg-type]
            experiment_id=experiment.id,
            experiment_execution_id=execution_id,
            action_role=role,
            allowed=response.allowed,
            reason_code=PolicyReasonCode(response.reason_code.value),
            message=response.message,
            policy_sha256=response.policy_sha256,
            policy_engine=response.policy_engine,
            policy_engine_version=response.policy_engine_version,
            provenance=Provenance(
                source_type="policy",
                source_reference=response.decision_id or "missing",
                collector=response.policy_engine,
                classification=FactClassification.OBSERVED,
            ),
        )
        with self.database.session_factory.begin() as session:
            RepositorySet(session).policy_decisions.add(audit)
        return audit

    def _rate_allowed(self, research_session_id: UUID) -> bool:
        cutoff = utc_now() - timedelta(minutes=1)
        with self.database.session_factory() as session:
            executions = RepositorySet(session).experiment_executions.list()
        recent_requests = sum(
            2
            for item in executions
            if item.research_session_id == research_session_id
            and item.started_at >= cutoff
            and item.status in {
                ExperimentExecutionStatus.EXECUTING,
                ExperimentExecutionStatus.EXECUTED,
                ExperimentExecutionStatus.FAILED,
            }
        )
        return recent_requests + 2 <= self.settings.policy_max_requests_per_minute

    async def run(self, experiment_id: UUID) -> ExperimentRunResult:
        experiment, research_session = self._load(experiment_id)
        execution = ExperimentExecution(
            experiment_id=experiment.id,
            research_session_id=experiment.research_session_id,  # type: ignore[arg-type]
            provenance=Provenance(
                source_type="experiment-execution",
                source_reference=str(experiment.id),
                collector="aegis-experiment-runner",
                classification=FactClassification.OBSERVED,
            ),
        )
        with self.database.session_factory.begin() as session:
            RepositorySet(session).experiment_executions.add(execution)
        if not self._rate_allowed(execution.research_session_id):
            denied = self._rate_denial(experiment, execution.id)
            execution = ExperimentExecution.model_validate(
                {
                    **execution.model_dump(mode="python"),
                    "status": ExperimentExecutionStatus.POLICY_REJECTED,
                    "finished_at": utc_now(),
                    "candidate_policy_decision_id": denied.id,
                    "control_policy_decision_id": denied.id,
                    "error_code": PolicyReasonCode.RATE_LIMIT_EXCEEDED.value,
                }
            )
            self._update_execution(execution)
            return ExperimentRunResult(execution=execution)
        try:
            checked = await self.check(experiment_id, execution_id=execution.id)
        except PolicyClientError:
            failed = ExperimentExecution.model_validate(
                {
                    **execution.model_dump(mode="python"),
                    "status": ExperimentExecutionStatus.FAILED,
                    "finished_at": utc_now(),
                    "error_code": "POLICY_UNAVAILABLE",
                }
            )
            self._update_execution(failed)
            raise
        execution_data = {
            **execution.model_dump(mode="python"),
            "candidate_policy_decision_id": checked.candidate.id,
            "control_policy_decision_id": checked.control.id,
        }
        if not checked.allowed:
            rejected = ExperimentExecution.model_validate(
                {
                    **execution_data,
                    "status": ExperimentExecutionStatus.POLICY_REJECTED,
                    "finished_at": utc_now(),
                    "error_code": "POLICY_REJECTED",
                }
            )
            self._update_execution(rejected)
            return ExperimentRunResult(execution=rejected)
        executing = ExperimentExecution.model_validate(
            {**execution_data, "status": ExperimentExecutionStatus.EXECUTING}
        )
        self._update_execution(executing)
        updated_experiment = Experiment.model_validate(
            {**experiment.model_dump(mode="python"), "status": ExperimentStatus.EXECUTING}
        )
        with self.database.session_factory.begin() as session:
            RepositorySet(session).experiments.update(updated_experiment)
        try:
            control = await self._execute_action(updated_experiment, ExperimentRole.CONTROL)
            candidate = await self._execute_action(updated_experiment, ExperimentRole.CANDIDATE)
        except Exception:
            failed = ExperimentExecution.model_validate(
                {
                    **executing.model_dump(mode="python"),
                    "status": ExperimentExecutionStatus.FAILED,
                    "finished_at": utc_now(),
                    "error_code": "EXECUTION_FAILED",
                }
            )
            self._update_execution(failed)
            raise
        completed = ExperimentExecution.model_validate(
            {
                **executing.model_dump(mode="python"),
                "status": ExperimentExecutionStatus.EXECUTED,
                "finished_at": utc_now(),
                "candidate_evidence_id": candidate.evidence.id,
                "candidate_observation_id": candidate.observation.id,
                "control_evidence_id": control.evidence.id,
                "control_observation_id": control.observation.id,
            }
        )
        self._update_execution(completed)
        final_experiment = Experiment.model_validate(
            {**updated_experiment.model_dump(mode="python"), "status": ExperimentStatus.EXECUTED}
        )
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            repositories.experiments.update(final_experiment)
            hypothesis = repositories.hypotheses.get(experiment.hypothesis_id)
            if hypothesis is not None and hypothesis.status is HypothesisStatus.NEW:
                repositories.hypotheses.update(
                    hypothesis.model_copy(update={"status": HypothesisStatus.TESTING})
                )
        experiment_log.info("experiment executed experiment_id=%s execution_id=%s", experiment.id, completed.id)
        return ExperimentRunResult(execution=completed, candidate=candidate, control=control)

    def _rate_denial(self, experiment: Experiment, execution_id: UUID) -> PolicyDecisionAudit:
        policy = PolicyConfig(
            allowed_hosts=[], allowed_ports=[], allowed_schemes=[], allowed_methods=[]
        )
        response = PolicyResponse(
            protocol_version=1,
            decision_id=f"DEC-{uuid4()}",
            allowed=False,
            reason_code=ProtocolReasonCode.RATE_LIMIT_EXCEEDED,
            message="session request rate would exceed configured limit",
            policy_sha256=policy.canonical_sha256(),
            policy_engine="aegis-python-rate-limiter",
            policy_engine_version="1",
        )
        return self._persist_decision(experiment, ExperimentRole.CANDIDATE, execution_id, response)

    async def _execute_action(
        self, experiment: Experiment, role: ExperimentRole
    ) -> ObservationResult:
        action = experiment.control if role is ExperimentRole.CONTROL else experiment.candidate
        if action is None:
            raise ValueError("experiment action is missing")
        identity = self.identity_resolver.resolve(action.identity)
        headers = {**action.headers, **identity.headers}
        return await self.observation_pipeline.observe(
            research_session_id=experiment.research_session_id,  # type: ignore[arg-type]
            path=action.path,
            method=HttpMethod(action.method.upper()),
            headers=headers,
            timeout_ms=action.timeout_ms,
            max_response_bytes=action.max_response_bytes,
            follow_redirects=action.follow_redirects,
            identity_name=identity.name,
            identity_roles=list(identity.roles),
            experiment_id=experiment.id,
            experiment_role=role,
        )

    def _update_execution(self, execution: ExperimentExecution) -> None:
        with self.database.session_factory.begin() as session:
            RepositorySet(session).experiment_executions.update(execution)
