import asyncio
from collections import Counter
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from app.collectors.pipeline import ObservationPipeline
from app.discovery.adapters import DNSAdapter, NmapAdapter, TLSAdapter
from app.discovery.errors import ToolExecutionError
from app.discovery.policy import ToolPolicy
from app.discovery.registry import ToolRegistry
from app.domain.common import FactClassification, Provenance, TrustClassification, utc_now
from app.domain.discovery import (
    ArtifactType,
    DISCOVERY_VERSION,
    DiscoveryPlan,
    DiscoveryPlanStatus,
    DiscoveryProfile,
    NmapServiceRecord,
    ParserStatus,
    PlanItemRequirement,
    TLSResult,
    TargetType,
    ToolArtifact,
    ToolCapability,
    ToolErrorCode,
    ToolRequest,
    ToolRun,
    ToolRunStatus,
    ToolTarget,
    tool_run_config_sha256,
)
from app.domain.observations import Observation, ObservationSource
from app.execution.protocol import HttpMethod
from app.logging_config import artifact_log, discovery_log, tool_execution_log
from app.storage.database import Database
from app.storage.repositories import RepositorySet


class DiscoveryEngine:
    def __init__(
        self,
        database: Database,
        registry: ToolRegistry,
        observation_pipeline: ObservationPipeline,
        *,
        artifact_max_bytes: int = 1_000_000,
        max_concurrency: int = 2,
        max_runs_per_plan: int = 8,
        dns_adapter: DNSAdapter | None = None,
        tls_adapter: TLSAdapter | None = None,
        nmap_adapter_factory: Any | None = None,
    ) -> None:
        self.database = database
        self.registry = registry
        self.observation_pipeline = observation_pipeline
        self.artifact_max_bytes = artifact_max_bytes
        self.max_concurrency = max_concurrency
        self.max_runs_per_plan = max_runs_per_plan
        self.dns_adapter = dns_adapter or DNSAdapter()
        self.tls_adapter = tls_adapter or TLSAdapter()
        self.nmap_adapter_factory = nmap_adapter_factory or (
            lambda descriptor: NmapAdapter(
                descriptor, artifact_max_bytes=self.artifact_max_bytes
            )
        )
        self.policy = ToolPolicy(registry)

    def create_plan(
        self, research_session_id: UUID, profile: DiscoveryProfile
    ) -> DiscoveryPlan:
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            research = repositories.research_sessions.get(research_session_id)
            if research is None:
                raise ValueError("research session does not exist")
            parsed = urlsplit(research.target.base_url)
            host = parsed.hostname
            if host is None:
                raise ValueError("research target has no hostname")
            target = ToolTarget.from_scope(
                host, research.scope.ports, parsed.scheme
            )
            requests: list[ToolRequest] = []
            capabilities: list[ToolCapability] = []
            if target.target_type is TargetType.HOSTNAME:
                requests.append(
                    ToolRequest(
                        tool="dns",
                        profile="lookup",
                        target=target,
                        timeout_seconds=5,
                        requirement=PlanItemRequirement.REQUIRED,
                    )
                )
                capabilities.append(ToolCapability.DNS_LOOKUP)
            requests.append(
                ToolRequest(
                    tool="http",
                    profile="metadata",
                    target=target,
                    timeout_seconds=5,
                    requirement=PlanItemRequirement.REQUIRED,
                )
            )
            capabilities.append(ToolCapability.HTTP_REQUEST)
            if parsed.scheme == "https":
                requests.append(
                    ToolRequest(
                        tool="tls",
                        profile="inspect",
                        target=target,
                        timeout_seconds=10,
                        requirement=PlanItemRequirement.REQUIRED,
                    )
                )
                capabilities.append(ToolCapability.TLS_INSPECTION)
            if profile is DiscoveryProfile.STANDARD:
                requests.append(
                    ToolRequest(
                        tool="nmap",
                        profile="service_discovery",
                        target=target,
                        timeout_seconds=30,
                        requirement=PlanItemRequirement.OPTIONAL,
                    )
                )
                capabilities.extend(
                    [ToolCapability.PORT_DISCOVERY, ToolCapability.SERVICE_DISCOVERY]
                )
            plan = DiscoveryPlan(
                research_session_id=research_session_id,
                profile=profile,
                requested_capabilities=tuple(dict.fromkeys(capabilities)),
                planned_tool_runs=tuple(requests),
                provenance=Provenance(
                    source_type="discovery_plan",
                    source_reference=str(research_session_id),
                    collector=DISCOVERY_VERSION,
                    classification=FactClassification.OBSERVED,
                ),
            )
            repositories.discovery_plans.add(plan)
        discovery_log.info(
            "plan created plan_id=%s session_id=%s profile=%s tools=%s",
            plan.id,
            research_session_id,
            profile.value,
            [request.tool for request in requests],
        )
        return plan

    def create_resolved_plan(
        self,
        research_session_id: UUID,
        *,
        capabilities: tuple[ToolCapability, ...],
        requests: tuple[ToolRequest, ...],
    ) -> DiscoveryPlan:
        """Persist a planner-resolved plan without weakening Phase 9 validation."""
        if not requests or len(requests) > self.max_runs_per_plan:
            raise ValueError("resolved plan request count is outside configured bounds")
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            research = repositories.research_sessions.get(research_session_id)
            if research is None:
                raise ValueError("research session does not exist")
            parsed = urlsplit(research.target.base_url)
            if parsed.hostname is None:
                raise ValueError("research target has no hostname")
            expected = ToolTarget.from_scope(
                parsed.hostname, research.scope.ports, parsed.scheme
            )
            for request in requests:
                descriptor = self.registry.get(request.tool)
                if descriptor is None or request.profile not in descriptor.supported_profiles:
                    raise ValueError("resolved tool/profile is not registered")
                if request.target != expected:
                    raise ValueError("resolved target must equal immutable session scope")
                if not set(capabilities).intersection(descriptor.capabilities):
                    raise ValueError("resolved tool does not provide requested capability")
            plan = DiscoveryPlan(
                research_session_id=research_session_id,
                profile=DiscoveryProfile.STANDARD,
                requested_capabilities=capabilities,
                planned_tool_runs=requests,
                provenance=Provenance(
                    source_type="research_planner",
                    source_reference=str(research_session_id),
                    collector=DISCOVERY_VERSION,
                    classification=FactClassification.OBSERVED,
                ),
            )
            repositories.discovery_plans.add(plan)
        discovery_log.info(
            "resolved plan created plan_id=%s session_id=%s tools=%s",
            plan.id,
            research_session_id,
            [request.tool for request in requests],
        )
        return plan

    async def run(self, discovery_plan_id: UUID) -> DiscoveryPlan:
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            plan = repositories.discovery_plans.get(discovery_plan_id)
            if plan is None:
                raise ValueError("discovery plan does not exist")
            if plan.status is not DiscoveryPlanStatus.CREATED:
                raise ValueError("discovery plan was already executed")
            research = repositories.research_sessions.get(plan.research_session_id)
            if research is None:
                raise ValueError("research session does not exist")
            running = plan.model_copy(
                update={"status": DiscoveryPlanStatus.RUNNING, "started_at": utc_now()}
            )
            repositories.discovery_plans.update(running)
        semaphore = asyncio.Semaphore(self.max_concurrency)
        tool_counts = Counter(request.tool for request in running.planned_tool_runs)

        async def bounded(request: ToolRequest) -> ToolRun:
            async with semaphore:
                return await self._run_request(
                    running,
                    research,
                    request,
                    same_tool_request_count=tool_counts[request.tool],
                )

        runs = await asyncio.gather(
            *(bounded(request) for request in running.planned_tool_runs)
        )
        failed_required = any(
            run.status is not ToolRunStatus.COMPLETED
            and request.requirement is PlanItemRequirement.REQUIRED
            for run, request in zip(runs, running.planned_tool_runs, strict=True)
        )
        failed_optional = any(
            run.status is not ToolRunStatus.COMPLETED
            and request.requirement is PlanItemRequirement.OPTIONAL
            for run, request in zip(runs, running.planned_tool_runs, strict=True)
        )
        completed_count = sum(run.status is ToolRunStatus.COMPLETED for run in runs)
        if failed_required:
            final_status = (
                DiscoveryPlanStatus.PARTIAL
                if completed_count
                else DiscoveryPlanStatus.FAILED
            )
        elif failed_optional:
            final_status = DiscoveryPlanStatus.PARTIAL
        else:
            final_status = DiscoveryPlanStatus.COMPLETED
        completed = running.model_copy(
            update={"status": final_status, "finished_at": utc_now()}
        )
        with self.database.session_factory.begin() as session:
            RepositorySet(session).discovery_plans.update(completed)
        discovery_log.info(
            "plan completed plan_id=%s status=%s completed=%d failed=%d",
            plan.id,
            final_status.value,
            completed_count,
            len(runs) - completed_count,
        )
        return completed

    async def _run_request(
        self,
        plan: DiscoveryPlan,
        research: Any,
        request: ToolRequest,
        *,
        same_tool_request_count: int = 1,
    ) -> ToolRun:
        descriptor = self.registry.get(request.tool)
        profile_version = {
            ("nmap", "common_tcp_ports"): "nmap-common-tcp-ports-v1",
            ("nmap", "service_discovery"): "nmap-service-discovery-v1",
            ("dns", "lookup"): "dns-lookup-v1",
            ("tls", "inspect"): "tls-inspection-v1",
            ("http", "metadata"): "http-metadata-v1",
        }.get((request.tool, request.profile), "unknown-profile")
        run = ToolRun(
            research_session_id=plan.research_session_id,
            discovery_plan_id=plan.id,
            tool_id=request.tool,
            tool_version=descriptor.version if descriptor else None,
            profile=request.profile,
            profile_version=profile_version,
            requested_target=request.target,
            normalized_target=request.target,
            config_sha256=(
                tool_run_config_sha256(request, descriptor)
                if descriptor
                else "0" * 64
            ),
            provenance=Provenance(
                source_type="tool_request",
                source_reference=str(plan.id),
                collector=DISCOVERY_VERSION,
                classification=FactClassification.OBSERVED,
            ),
        )
        with self.database.session_factory.begin() as session:
            RepositorySet(session).tool_runs.add(run)
            run = run.model_copy(update={"status": ToolRunStatus.VALIDATED})
            RepositorySet(session).tool_runs.update(run)
        decision = self.policy.evaluate(
            research_session=research,
            discovery_plan_id=plan.id,
            tool_run_id=run.id,
            request=request,
            plan_request_count=len(plan.planned_tool_runs),
            same_tool_request_count=same_tool_request_count,
            max_plan_requests=self.max_runs_per_plan,
            max_concurrency=self.max_concurrency,
        )
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            repositories.tool_policy_decisions.add(decision)
            policy_status = (
                ToolRunStatus.POLICY_APPROVED
                if decision.allowed
                else ToolRunStatus.POLICY_REJECTED
            )
            run = run.model_copy(
                update={"status": policy_status, "policy_decision_id": decision.id}
            )
            repositories.tool_runs.update(run)
        if not decision.allowed:
            rejected = run.model_copy(
                update={
                    "finished_at": utc_now(),
                    "error_code": _reason_error(decision.reason.value),
                    "error": decision.message,
                }
            )
            with self.database.session_factory.begin() as session:
                RepositorySet(session).tool_runs.update(rejected)
            return rejected
        run = run.model_copy(update={"status": ToolRunStatus.RUNNING})
        with self.database.session_factory.begin() as session:
            RepositorySet(session).tool_runs.update(run)
        tool_execution_log.info(
            "tool run started plan_id=%s run_id=%s tool=%s profile=%s",
            plan.id,
            run.id,
            run.tool_id,
            run.profile,
        )
        try:
            if request.tool == "http":
                observed = await self.observation_pipeline.observe(
                    research_session_id=plan.research_session_id,
                    path="/health",
                    method=HttpMethod.GET,
                    timeout_ms=int(request.timeout_seconds * 1000),
                    max_response_bytes=min(self.artifact_max_bytes, 100_000),
                    identity_name="anonymous",
                    identity_roles=["anonymous"],
                )
                completed = run.model_copy(
                    update={
                        "status": ToolRunStatus.COMPLETED,
                        "finished_at": utc_now(),
                        "observation_ids": [observed.observation.id],
                        "exit_code": 0,
                    }
                )
            else:
                completed = await self._execute_discovery_adapter(run, request, descriptor)
        except ToolExecutionError as error:
            completed = run.model_copy(
                update={
                    "status": ToolRunStatus.FAILED,
                    "finished_at": utc_now(),
                    "error_code": error.code,
                    "error": str(error),
                }
            )
        except (OSError, TimeoutError) as error:
            completed = run.model_copy(
                update={
                    "status": ToolRunStatus.FAILED,
                    "finished_at": utc_now(),
                    "error_code": ToolErrorCode.PROCESS_FAILED,
                    "error": str(error),
                }
            )
        except Exception as error:
            completed = run.model_copy(
                update={
                    "status": ToolRunStatus.FAILED,
                    "finished_at": utc_now(),
                    "error_code": ToolErrorCode.PROCESS_FAILED,
                    "error": f"unexpected adapter failure: {type(error).__name__}",
                }
            )
        with self.database.session_factory.begin() as session:
            RepositorySet(session).tool_runs.update(completed)
        return completed

    async def _execute_discovery_adapter(
        self, run: ToolRun, request: ToolRequest, descriptor: Any
    ) -> ToolRun:
        if request.tool == "nmap":
            adapter: Any = self.nmap_adapter_factory(descriptor)
        elif request.tool == "dns":
            adapter = self.dns_adapter
        elif request.tool == "tls":
            adapter = self.tls_adapter
        else:
            raise ToolExecutionError(
                ToolErrorCode.TOOL_NOT_AVAILABLE, "no adapter registered for tool"
            )
        adapter.validate_request(request)
        execution = await adapter.execute(request)
        raw = execution.raw_artifact or b""
        if len(raw) > self.artifact_max_bytes:
            raise ToolExecutionError(
                ToolErrorCode.OUTPUT_TOO_LARGE, "tool artifact exceeded configured limit"
            )
        artifact = ToolArtifact.from_bytes(
            raw=raw,
            research_session_id=run.research_session_id,
            tool_run_id=run.id,
            tool_id=run.tool_id,
            tool_version=run.tool_version,
            artifact_type=execution.artifact_type or ArtifactType.DNS_JSON,
            content_type=execution.content_type or "application/octet-stream",
            parser_version=execution.parser_version,
            provenance=Provenance(
                source_type="tool_artifact",
                source_reference=str(run.id),
                collector=run.tool_id,
                classification=FactClassification.OBSERVED,
            ),
        )
        with self.database.session_factory.begin() as session:
            RepositorySet(session).tool_artifacts.add(artifact)
        artifact_log.info(
            "artifact persisted run_id=%s artifact_id=%s sha256=%s bytes=%d",
            run.id,
            artifact.id,
            artifact.sha256,
            artifact.size_bytes,
        )
        try:
            records = (
                tuple(adapter.parser.parse(raw))
                if request.tool == "nmap"
                else execution.parsed_records
            )
            if request.tool == "nmap" and any(
                not isinstance(record, NmapServiceRecord)
                or record.port not in request.target.ports
                or (
                    request.target.target_type is TargetType.IP
                    and record.address != request.target.host
                )
                for record in records
            ):
                raise ToolExecutionError(
                    ToolErrorCode.ARTIFACT_INVALID,
                    "Nmap artifact contains facts outside the validated target",
                )
        except ToolExecutionError as error:
            failed_artifact = artifact.model_copy(
                update={
                    "parser_status": ParserStatus.FAILED,
                    "parser_error": str(error),
                }
            )
            with self.database.session_factory.begin() as session:
                repositories = RepositorySet(session)
                repositories.tool_artifacts.update(failed_artifact)
                failed_run = run.model_copy(
                    update={
                        "status": ToolRunStatus.FAILED,
                        "finished_at": utc_now(),
                        "artifact_ids": [artifact.id],
                        "normalized_argv": execution.argv,
                        "parser_version": execution.parser_version,
                        "exit_code": execution.exit_code,
                        "error_code": error.code,
                        "error": str(error),
                    }
                )
                repositories.tool_runs.update(failed_run)
            return failed_run
        completed_artifact = artifact.model_copy(
            update={"parser_status": ParserStatus.COMPLETED}
        )
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            research = repositories.research_sessions.get(run.research_session_id)
            if research is None:
                raise ValueError("research session does not exist")
            observations = [
                self._tool_observation(
                    run, completed_artifact, record, research.target.asset_id
                )
                for record in records
            ]
            repositories.tool_artifacts.update(completed_artifact)
            for observation in observations:
                repositories.observations.add(observation)
        return run.model_copy(
            update={
                "status": ToolRunStatus.COMPLETED,
                "finished_at": utc_now(),
                "exit_code": execution.exit_code,
                "artifact_ids": [artifact.id],
                "observation_ids": [item.id for item in observations],
                "normalized_argv": execution.argv,
                "parser_version": execution.parser_version,
            }
        )

    @staticmethod
    def _tool_observation(
        run: ToolRun, artifact: ToolArtifact, record: object, asset_id: UUID
    ) -> Observation:
        if isinstance(record, NmapServiceRecord):
            normalized = {
                "source_type": "nmap",
                **record.model_dump(mode="json"),
            }
        elif isinstance(record, TLSResult):
            normalized = {
                "source_type": "tls",
                **record.model_dump(mode="json"),
            }
        else:
            normalized = {
                "source_type": "dns",
                **record.model_dump(mode="json"),  # type: ignore[attr-defined]
            }
        return Observation(
            asset_id=asset_id,
            research_session_id=run.research_session_id,
            tool_artifact_id=artifact.id,
            source=ObservationSource.TOOL,
            raw_data={
                "artifact_id": str(artifact.id),
                "tool_run_id": str(run.id),
                "data": normalized,
            },
            normalized_data=normalized,
            trust=TrustClassification.UNTRUSTED,
            normalized_data_trust=TrustClassification.TRUSTED,
            provenance=Provenance(
                source_type=run.tool_id,
                source_reference=str(artifact.id),
                collector=run.parser_version or artifact.parser_version,
                classification=FactClassification.OBSERVED,
                metadata={
                    "tool_run_id": str(run.id),
                    "tool_artifact_id": str(artifact.id),
                    "artifact_sha256": artifact.sha256,
                    "data_trust": "UNTRUSTED_TOOL_DATA",
                },
            ),
        )

    def export(self, discovery_plan_id: UUID) -> dict[str, Any]:
        with self.database.session_factory() as session:
            repositories = RepositorySet(session)
            plan = repositories.discovery_plans.get(discovery_plan_id)
            if plan is None:
                raise ValueError("discovery plan does not exist")
            runs = repositories.tool_runs.list_by_plan(plan.id)
            artifacts = [
                artifact
                for run in runs
                for artifact in repositories.tool_artifacts.list_by_run(run.id)
            ]
            observations = repositories.observations.list_by_session(
                plan.research_session_id
            )
            run_observation_ids = {value for run in runs for value in run.observation_ids}
        return {
            "discovery_version": plan.discovery_version,
            "registry_version": plan.registry_version,
            "plan": plan.model_dump(mode="json"),
            "tool_runs": [run.model_dump(mode="json") for run in runs],
            "artifacts": [
                {
                    **artifact.model_dump(
                        mode="json", exclude={"content_base64"}
                    ),
                    "raw_content_included": False,
                }
                for artifact in artifacts
            ],
            "observations": [
                observation.model_dump(mode="json")
                for observation in observations
                if observation.id in run_observation_ids
            ],
            "failures": [
                {"tool_run_id": str(run.id), "code": run.error_code, "error": run.error}
                for run in runs
                if run.status is not ToolRunStatus.COMPLETED
            ],
        }
def _reason_error(reason: str) -> ToolErrorCode:
    return {
        "TOOL_NOT_AVAILABLE": ToolErrorCode.TOOL_NOT_AVAILABLE,
        "TOOL_DISABLED": ToolErrorCode.TOOL_DISABLED,
        "PROFILE_NOT_ALLOWED": ToolErrorCode.PROFILE_NOT_ALLOWED,
        "TARGET_OUT_OF_SCOPE": ToolErrorCode.TARGET_OUT_OF_SCOPE,
        "PORT_OUT_OF_SCOPE": ToolErrorCode.PORT_OUT_OF_SCOPE,
        "RATE_LIMIT_EXCEEDED": ToolErrorCode.RATE_LIMIT_EXCEEDED,
    }.get(reason, ToolErrorCode.POLICY_REJECTED)
