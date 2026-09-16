from uuid import UUID

from app.config import Settings
from app.domain.assets import Asset, AssetKind
from app.domain.common import FactClassification, Provenance, utc_now
from app.domain.controller import ControllerStatus, ResearchActionStatus, ResearchBudget
from app.domain.operator import (
    ApprovalMode,
    ApprovalStatus,
    ControllerMode,
    EventSeverity,
    ProjectStatus,
    ResearchBudgetTemplate,
    ResearchEvent,
    ResearchEventType,
    ResearchPolicy,
    ResearchPolicyProfile,
    ResearchProject,
    SessionMetrics,
    SessionOverview,
)
from app.domain.research import ResearchSession, ResearchTarget, TargetScope
from app.domain.research_strategy import GapStatus
from app.operator.policy import policy_settings
from app.storage.database import Database
from app.storage.repositories import RepositorySet


def operator_provenance(reference: str) -> Provenance:
    return Provenance(
        source_type="operator",
        source_reference=reference,
        collector="operator-api-v1",
        classification=FactClassification.OBSERVED,
    )


class ResearchEventService:
    def __init__(self, database: Database) -> None:
        self.database = database

    def emit(
        self,
        project_id: UUID,
        event_type: ResearchEventType,
        entity_type: str,
        entity_id: str,
        message: str,
        *,
        session_id: UUID | None = None,
        severity: EventSeverity = EventSeverity.INFO,
        data: dict[str, object] | None = None,
        key: str | None = None,
    ) -> ResearchEvent:
        idempotency = key or f"{event_type.value}:{entity_type}:{entity_id}"
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            existing = repositories.research_events.get_by_idempotency(idempotency)
            if existing:
                return existing
            event = ResearchEvent(
                project_id=project_id,
                research_session_id=session_id,
                sequence_number=repositories.research_events.next_sequence(project_id, session_id),
                event_type=event_type,
                entity_type=entity_type,
                entity_id=entity_id,
                severity=severity,
                message=message,
                structured_data=data or {},
                idempotency_key=idempotency,
                provenance=operator_provenance(idempotency),
            )
            repositories.research_events.add(event)
            return event

    def sync_session(self, session_id: UUID) -> list[ResearchEvent]:
        with self.database.session_factory() as session:
            repositories = RepositorySet(session)
            research = repositories.research_sessions.get(session_id)
            if research is None or research.project_id is None:
                return []
            project_id = research.project_id
            observations = repositories.observations.list_by_session(session_id)
            evidence = repositories.evidence.list_by_session(session_id)
            gaps = repositories.evidence_gaps.list_by_session(session_id)
            actions = repositories.research_actions.list_by_session(session_id)
            tool_runs = repositories.tool_runs.list_by_session(session_id)
            builds = repositories.system_model_builds.list_by_session(session_id)
            graphs = repositories.attack_graph_snapshots.list_by_session(session_id)
            hypotheses = repositories.hypotheses.list_by_session(session_id)
            experiments = repositories.experiments.list_by_session(session_id)
            verifications = repositories.verification_results.list_by_session(session_id)
            findings = repositories.findings.list_by_session(session_id)
        for item in observations:
            self.emit(
                project_id,
                ResearchEventType.OBSERVATION_CREATED,
                "Observation",
                str(item.id),
                "Observation persisted",
                session_id=session_id,
            )
        for item in evidence:
            self.emit(
                project_id,
                ResearchEventType.EVIDENCE_CREATED,
                "Evidence",
                str(item.id),
                "Evidence persisted",
                session_id=session_id,
            )
        for item in gaps:
            event_type = (
                ResearchEventType.GAP_RESOLVED
                if item.status is GapStatus.RESOLVED
                else ResearchEventType.GAP_DETECTED
            )
            self.emit(
                project_id,
                event_type,
                "EvidenceGap",
                str(item.id),
                f"Evidence gap {item.status.value.lower()}",
                session_id=session_id,
                data={"gap_type": item.gap_type.value, "status": item.status.value},
                key=f"gap:{item.id}:{item.status.value}",
            )
        for item in actions:
            event_type = (
                ResearchEventType.ACTION_REJECTED
                if item.status is ResearchActionStatus.REJECTED
                else ResearchEventType.ACTION_VALIDATED
                if item.status
                in {ResearchActionStatus.VALIDATED, ResearchActionStatus.WAITING_FOR_APPROVAL}
                else ResearchEventType.ACTION_PROPOSED
            )
            self.emit(
                project_id,
                event_type,
                "ResearchAction",
                str(item.id),
                f"Action {item.action_type.value}: {item.status.value}",
                session_id=session_id,
                data={"status": item.status.value, "validation": item.validation_reason},
                key=f"action:{item.id}:{item.status.value}",
            )
        for item in tool_runs:
            event_type = (
                ResearchEventType.TOOL_COMPLETED
                if item.status.value in {"COMPLETED", "FAILED"}
                else ResearchEventType.TOOL_STARTED
            )
            self.emit(
                project_id,
                event_type,
                "ToolRun",
                str(item.id),
                f"Tool {item.tool_id}: {item.status.value}",
                session_id=session_id,
                data={"tool": item.tool_id, "profile": item.profile, "status": item.status.value},
                key=f"tool:{item.id}:{item.status.value}",
            )
        for item in builds:
            self.emit(
                project_id,
                ResearchEventType.MODEL_REBUILT,
                "SystemModelBuild",
                str(item.id),
                "System Model rebuilt",
                session_id=session_id,
                data={"model_hash": item.model_sha256},
                key=f"model:{item.id}:{item.model_sha256}",
            )
        for item in graphs:
            self.emit(
                project_id,
                ResearchEventType.GRAPH_REBUILT,
                "AttackGraphSnapshot",
                str(item.id),
                "Attack Graph snapshot persisted",
                session_id=session_id,
                data={"graph_hash": item.graph_hash, "status": item.status.value},
                key=f"graph:{item.id}:{item.status.value}",
            )
        for item in hypotheses:
            self.emit(
                project_id,
                ResearchEventType.HYPOTHESIS_CREATED,
                "Hypothesis",
                str(item.id),
                "Hypothesis persisted",
                session_id=session_id,
            )
        for item in experiments:
            self.emit(
                project_id,
                ResearchEventType.EXPERIMENT_EXECUTED,
                "Experiment",
                str(item.id),
                f"Experiment state: {item.status.value}",
                session_id=session_id,
                key=f"experiment:{item.id}:{item.status.value}",
            )
        for item in verifications:
            self.emit(
                project_id,
                ResearchEventType.VERIFICATION_COMPLETED,
                "VerificationResult",
                str(item.id),
                f"Verification: {item.verdict.value}",
                session_id=session_id,
                data={"verdict": item.verdict.value},
            )
        for item in findings:
            self.emit(
                project_id,
                ResearchEventType.FINDING_CREATED,
                "Finding",
                str(item.id),
                "Evidence-backed Finding created",
                session_id=session_id,
                data={"verification_status": item.verification_status.value},
            )
        with self.database.session_factory() as session:
            return RepositorySet(session).research_events.list_by_session(session_id, limit=1000)


class ProjectService:
    def __init__(self, database: Database, settings: Settings) -> None:
        self.database = database
        self.settings = settings
        self.events = ResearchEventService(database)

    def create(
        self,
        name: str,
        *,
        description: str | None = None,
        profile: ResearchPolicyProfile = ResearchPolicyProfile.CONSERVATIVE,
        created_by: dict[str, object] | None = None,
    ) -> ResearchProject:
        policy = ResearchPolicy(
            profile=profile,
            settings=policy_settings(profile),
            provenance=operator_provenance(f"policy:{profile.value}"),
        )
        project = ResearchProject(
            name=name,
            description=description,
            default_provider=self.settings.llm_provider,
            default_model=self.settings.llm_model,
            model_configuration={
                "provider": self.settings.llm_provider,
                "model": self.settings.llm_model,
                "max_completion_tokens": self.settings.llm_max_output_tokens,
                **(
                    {"temperature": self.settings.nvidia_temperature, "top_p": 0.95}
                    if self.settings.llm_provider == "nvidia_nim"
                    else {}
                ),
            },
            controller_mode=(
                ControllerMode.EXPERIMENTAL
                if profile is ResearchPolicyProfile.EXPERIMENTAL
                else ControllerMode.SAFE
            ),
            research_policy_id=policy.id,
            created_by=created_by or {"type": "local_operator"},
            provenance=operator_provenance(f"project:{name}"),
        )
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            repositories.research_policies.add(policy)
            repositories.research_projects.add(project)
        self.events.emit(
            project.id,
            ResearchEventType.PROJECT_CREATED,
            "ResearchProject",
            str(project.id),
            "Research project created",
        )
        return project

    def configure(
        self,
        project_id: UUID,
        *,
        scope: TargetScope,
        identity_names: tuple[str, ...],
        profile: ResearchPolicyProfile,
        approval_mode: ApprovalMode,
        budget: ResearchBudgetTemplate,
    ) -> ResearchProject:
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            project = repositories.research_projects.get(project_id)
            if project is None:
                raise ValueError("project does not exist")
            policy = ResearchPolicy(
                profile=profile,
                settings=policy_settings(profile),
                provenance=operator_provenance(f"project-policy:{project_id}:{profile.value}"),
            )
            repositories.research_policies.add(policy)
            revision = project.scope_revision + (1 if project.scope != scope else 0)
            updated = project.model_copy(
                update={
                    "scope": scope,
                    "scope_revision": max(1, revision),
                    "identity_names": identity_names,
                    "research_policy_id": policy.id,
                    "controller_mode": ControllerMode.EXPERIMENTAL
                    if profile is ResearchPolicyProfile.EXPERIMENTAL
                    else ControllerMode.SAFE,
                    "approval_mode": approval_mode,
                    "budget": budget,
                    "status": ProjectStatus.READY,
                    "updated_at": utc_now(),
                }
            )
            repositories.research_projects.update(updated)
        self.events.emit(
            project_id,
            ResearchEventType.PROJECT_CONFIGURED,
            "ResearchProject",
            str(project_id),
            "Research project configured",
            data={
                "scope_revision": updated.scope_revision,
                "policy": profile.value,
                "approval_mode": approval_mode.value,
            },
            key=f"project-configured:{project_id}:{updated.scope_revision}:{policy.id}",
        )
        return updated

    def start(self, project_id: UUID) -> ResearchSession:
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            project = repositories.research_projects.get(project_id)
            if (
                project is None
                or project.scope is None
                or project.status is ProjectStatus.CANCELLED
            ):
                raise ValueError("project is not ready")
            host, port, scheme = (
                project.scope.hosts[0],
                project.scope.ports[0],
                project.scope.schemes[0],
            )
            asset = Asset(
                name=project.name,
                kind=AssetKind.API,
                provenance=operator_provenance(
                    f"project-asset:{project.id}:{project.scope_revision}"
                ),
            )
            research = ResearchSession(
                project_id=project.id,
                project_scope_revision=project.scope_revision,
                name=f"{project.name} session {len(repositories.research_sessions.list_by_project(project.id)) + 1}",
                target=ResearchTarget(
                    asset_id=asset.id,
                    name=project.name,
                    base_url=f"{scheme}://{host}:{port}",
                    provenance=operator_provenance(
                        f"project-target:{project.id}:{project.scope_revision}"
                    ),
                ),
                scope=project.scope,
                provenance=operator_provenance(
                    f"project-session:{project.id}:{project.scope_revision}"
                ),
            ).start()
            repositories.assets.add(asset)
            repositories.research_sessions.add(research)
            budget = ResearchBudget(
                research_session_id=research.id,
                max_steps=project.budget.max_steps,
                max_actions=project.budget.max_actions,
                max_tool_runs=project.budget.max_tool_runs,
                max_requests=project.budget.max_requests,
                max_duration_seconds=project.budget.max_duration_seconds,
                max_llm_calls=project.budget.max_llm_calls,
                allowed_capabilities=project.budget.allowed_capabilities,
                provenance=operator_provenance(f"project-budget:{project.id}:{research.id}"),
            )
            repositories.research_budgets.add(budget)
            repositories.research_projects.update(
                project.model_copy(
                    update={"status": ProjectStatus.RUNNING, "updated_at": utc_now()}
                )
            )
        self.events.emit(
            project_id,
            ResearchEventType.SESSION_STARTED,
            "ResearchSession",
            str(research.id),
            "Research session started",
            session_id=research.id,
            data={"scope_revision": research.project_scope_revision},
        )
        return research

    def overview(self, session_id: UUID) -> SessionOverview:
        with self.database.session_factory() as session:
            r = RepositorySet(session)
            research = r.research_sessions.get(session_id)
            if research is None or research.project_id is None:
                raise ValueError("project-linked session does not exist")
            project = r.research_projects.get(research.project_id)
            budget = r.research_budgets.get_by_session(session_id)
            if project is None or budget is None:
                raise ValueError("project configuration is incomplete")
            policy = r.research_policies.get(project.research_policy_id)
            if policy is None:
                raise ValueError("research policy does not exist")
            observations = r.observations.list_by_session(session_id)
            evidence = r.evidence.list_by_session(session_id)
            assets = r.system_assets.list_by_session(session_id)
            services = r.system_services.list_by_session(session_id)
            endpoints = r.system_endpoints.list_by_session(session_id)
            identities = r.system_identities.list_by_session(session_id)
            gaps = r.evidence_gaps.list_by_session(session_id)
            actions = r.research_actions.list_by_session(session_id)
            tool_runs = r.tool_runs.list_by_session(session_id)
            hypotheses = r.hypotheses.list_by_session(session_id)
            experiments = r.experiments.list_by_session(session_id)
            verifications = r.verification_results.list_by_session(session_id)
            findings = r.findings.list_by_session(session_id)
            approvals = r.action_approvals.list_by_session(session_id)
            steps = r.controller_steps.list_by_session(session_id)
            graphs = r.attack_graph_snapshots.list_by_session(session_id)
            signals = r.candidate_signals.list_by_graph(graphs[-1].id) if graphs else []
            policy_rejections = [
                item for item in tool_runs if item.status.value == "POLICY_REJECTED"
            ]
        executed = [
            item
            for item in actions
            if item.status
            in {
                ResearchActionStatus.SATISFIED,
                ResearchActionStatus.UNSATISFIED,
                ResearchActionStatus.COMPLETED,
            }
        ]
        rejected = [item for item in actions if item.status is ResearchActionStatus.REJECTED]
        resolved = [item for item in gaps if item.status is GapStatus.RESOLVED]
        repeats = len(actions) - len({item.semantic_hash for item in actions})
        metrics = SessionMetrics(
            controller_steps=len(steps),
            actions_proposed=len(actions),
            actions_executed=len(executed),
            actions_rejected=len(rejected),
            experimental_actions=sum(
                item.validation_reason == "VALIDATED_EXPERIMENTAL" for item in actions
            ),
            tool_runs=len(tool_runs),
            http_requests=sum(item.tool_id == "http" for item in tool_runs),
            evidence_records=len(evidence),
            gaps_detected=len(gaps),
            gaps_resolved=len(resolved),
            repeated_actions=max(0, repeats),
            redundant_actions_prevented=sum(
                item.validation_reason == "DUPLICATE_SATISFIED_ACTION" for item in actions
            ),
            findings=len(findings),
            inconclusive_hypotheses=sum(item.status.value == "INCONCLUSIVE" for item in hypotheses),
            policy_rejections=len(policy_rejections),
            autonomous_actions=max(
                0, len(executed) - sum(item.status is ApprovalStatus.APPROVED for item in approvals)
            ),
            operator_approved_actions=sum(
                item.status is ApprovalStatus.APPROVED for item in approvals
            ),
            operator_rejected_actions=sum(
                item.status is ApprovalStatus.REJECTED for item in approvals
            ),
            actions_per_finding=(len(executed) / len(findings) if findings else None),
            requests_per_finding=(
                sum(item.tool_id == "http" for item in tool_runs) / len(findings)
                if findings
                else None
            ),
            gaps_resolved_per_action=(len(resolved) / len(executed) if executed else None),
        )
        counts = {
            "observations": len(observations),
            "evidence": len(evidence),
            "assets": len(assets),
            "services": len(services),
            "endpoints": len(endpoints),
            "identities": len(identities),
            "candidate_signals": len(signals),
            "hypotheses": len(hypotheses),
            "experiments": len(experiments),
            "verifications": len(verifications),
            "findings": len(findings),
            "pending_approvals": sum(item.status is ApprovalStatus.PENDING for item in approvals),
        }
        budget_payload = budget.model_dump(mode="json")
        return SessionOverview(
            project_id=project.id,
            session_id=session_id,
            session_status=research.status.value,
            scope=research.scope.model_dump(mode="json"),
            controller_mode=project.controller_mode,
            research_policy=policy.profile,
            approval_mode=project.approval_mode,
            experimental_mode=project.controller_mode is ControllerMode.EXPERIMENTAL,
            budget=budget_payload,
            counts=counts,
            open_gaps=sum(
                item.status in {GapStatus.OPEN, GapStatus.PARTIALLY_RESOLVED, GapStatus.BLOCKED}
                for item in gaps
            ),
            resolved_gaps=len(resolved),
            last_action_id=actions[-1].id if actions else None,
            stop_reason=budget.stop_reason,
            metrics=metrics,
        )

    def cancel(self, project_id: UUID) -> ResearchProject:
        with self.database.session_factory.begin() as session:
            r = RepositorySet(session)
            project = r.research_projects.get(project_id)
            if project is None:
                raise ValueError("project does not exist")
            updated = project.model_copy(
                update={"status": ProjectStatus.CANCELLED, "updated_at": utc_now()}
            )
            r.research_projects.update(updated)
            for research in r.research_sessions.list_by_project(project_id):
                budget = r.research_budgets.get_by_session(research.id)
                if budget:
                    r.research_budgets.update(
                        budget.model_copy(
                            update={
                                "controller_status": ControllerStatus.CANCELLED,
                                "stop_reason": "operator cancelled project",
                                "pause_requested": True,
                                "updated_at": utc_now(),
                            }
                        )
                    )
        self.events.emit(
            project_id,
            ResearchEventType.CONTROLLER_STOPPED,
            "ResearchProject",
            str(project_id),
            "Project cancelled by operator",
            severity=EventSeverity.NOTICE,
            key=f"project-cancelled:{project_id}",
        )
        return updated
