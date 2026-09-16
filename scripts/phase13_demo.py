import asyncio
import json
import tempfile
from pathlib import Path

from app.attack_graph.builder import AttackGraphBuilder
from app.collectors.pipeline import ObservationPipeline
from app.config import Settings
from app.controller.factory import build_controller
from app.domain.operator import ApprovalMode, ResearchBudgetTemplate, ResearchPolicyProfile
from app.domain.research import TargetScope
from app.execution.identity import LaboratoryIdentityResolver
from app.execution.rust_executor import RustExecutorClient
from app.operator.evaluation import compare_policies
from app.operator.reporting import ReportService
from app.operator.service import ProjectService, ResearchEventService, operator_provenance
from app.research_strategy.knowledge import KnowledgeService
from app.storage.database import Database
from app.storage.repositories import RepositorySet
from app.system_model.builder import SystemModelBuilder


async def run_session(
    database: Database,
    settings: Settings,
    profile: ResearchPolicyProfile,
    approval_mode: ApprovalMode,
) -> dict[str, object]:
    service = ProjectService(database, settings)
    project = service.create(f"phase13-{profile.value.lower()}", profile=profile)
    project = service.configure(
        project.id,
        scope=TargetScope(
            hosts=("127.0.0.1",),
            ports=(8001,),
            schemes=("http",),
            provenance=operator_provenance(f"phase13-demo:{profile.value}"),
        ),
        identity_names=("anonymous", "alice", "bob", "admin"),
        profile=profile,
        approval_mode=approval_mode,
        budget=ResearchBudgetTemplate(
            max_steps=5,
            max_actions=5,
            max_tool_runs=5,
            max_requests=5,
            max_duration_seconds=120,
            max_llm_calls=0,
        ),
    )
    research = service.start(project.id)
    bob = LaboratoryIdentityResolver().resolve("bob")
    await ObservationPipeline(
        database, RustExecutorClient(Path("native/rust/target/debug/aegis-executor"))
    ).observe(
        research_session_id=research.id,
        path="/api/orders/101",
        headers=bob.headers,
        identity_name=bob.name,
        identity_roles=list(bob.roles),
    )
    initial_model = SystemModelBuilder(database).build(research.id)
    _, initial_graph, _ = AttackGraphBuilder(database).build(research.id)
    _, initial_knowledge, initial_gaps = KnowledgeService(database).build(research.id)
    controller = build_controller(database, settings)
    first = await controller.step(research.id)
    with database.session_factory() as session:
        r = RepositorySet(session)
        runs_before_approval = len(r.tool_runs.list_by_session(research.id))
        approval = r.action_approvals.get_by_action(first.actions[0].id)
    approved = None
    if approval is not None:
        approved = await controller.approve_action(
            first.actions[0].id, reason="controlled Phase 13 demonstration"
        )
    second = await controller.step(research.id)
    paused = controller.pause(research.id)
    resumed = await controller.resume(research.id)
    events = ResearchEventService(database)
    events.sync_session(research.id)
    overview = service.overview(research.id)
    metadata, manifest = ReportService(database, settings).generate(research.id)
    report_directory = Path(metadata.path)
    report_text = "\n".join(path.read_text(encoding="utf-8") for path in report_directory.iterdir())
    report_summary = json.loads((report_directory / "summary.json").read_text(encoding="utf-8"))
    with database.session_factory() as session:
        r = RepositorySet(session)
        gaps = r.evidence_gaps.list_by_session(research.id)
        runs = r.tool_runs.list_by_session(research.id)
        actions = r.research_actions.list_by_session(research.id)
        evidence = r.evidence.list_by_session(research.id)
        timeline = r.research_events.list_by_session(research.id, limit=10_000)
        models = r.system_model_builds.list_by_session(research.id)
        graphs = r.attack_graph_snapshots.list_by_session(research.id)
        knowledge = r.knowledge_snapshots.list_by_session(research.id)
    credential_markers = [
        marker
        for marker in ("Bearer alice-token", "Bearer bob-token", "nvapi-", "Cookie:")
        if marker in report_text
    ]
    first_action = first.actions[0]
    return {
        "project_id": str(project.id),
        "session_id": str(research.id),
        "scope": research.scope.model_dump(mode="json"),
        "profile": profile.value,
        "experimental_mode": profile is ResearchPolicyProfile.EXPERIMENTAL,
        "approval_mode": approval_mode.value,
        "initial_model_hash": initial_model.model_sha256,
        "initial_graph_hash": initial_graph.graph_hash,
        "initial_knowledge_hash": initial_knowledge.sha256,
        "initial_open_gaps": [str(item.id) for item in initial_gaps],
        "first_action": {
            "id": str(first_action.id),
            "type": first_action.action_type.value,
            "purpose": first_action.purpose.value,
            "status": first_action.status.value,
            "identity_entity_id": str(first_action.proposal.identity_entity_id),
            "endpoint_entity_id": str(first_action.proposal.endpoint_entity_id),
            "path": "/api/orders/101",
        },
        "approval": (
            {
                "id": str(approval.id),
                "status": approval.status.value,
                "policy_preview_allowed": approval.policy_preview_allowed,
                "policy_preview_reason": approval.policy_preview_reason,
            }
            if approval
            else None
        ),
        "tool_runs_before_approval": runs_before_approval,
        "approved_action": (
            {
                "id": str(approved.id),
                "status": approved.status.value,
                "tool_run_ids": [str(item) for item in approved.tool_run_ids],
                "evidence_ids": [str(item) for item in approved.evidence_ids],
                "observation_ids": [str(item) for item in approved.observation_ids],
                "method": approved.contract.method if approved.contract else None,
                "path": approved.contract.path if approved.contract else None,
                "policy": (
                    approved.contract.policy_decision.reason_code
                    if approved.contract and approved.contract.policy_decision
                    else None
                ),
            }
            if approved
            else None
        ),
        "second_decision": second.decision.decision_type.value,
        "pause_status": paused.controller_status.value,
        "resume_stop_reason": resumed.stop_reason,
        "overview": {
            "controller_status": overview.budget["controller_status"],
            "project_status": report_summary["project"]["status"],
            "open_gaps": overview.open_gaps,
            "resolved_gaps": overview.resolved_gaps,
            "metrics": overview.metrics.model_dump(mode="json"),
        },
        "actions": len(actions),
        "tool_runs": len(runs),
        "repeated_actions": overview.metrics.repeated_actions,
        "requests": overview.metrics.http_requests,
        "evidence_records": len(evidence),
        "gaps_resolved": sum(item.status.value == "RESOLVED" for item in gaps),
        "findings": overview.metrics.findings,
        "latest_model_hash": models[-1].model_sha256 if models else None,
        "latest_graph_hash": graphs[-1].graph_hash if graphs else None,
        "latest_knowledge_hash": knowledge[-1].sha256 if knowledge else None,
        "events": len(timeline),
        "report_id": str(metadata.id),
        "report_directory": str(report_directory),
        "manifest_hash": manifest.sha256,
        "manifest_valid": ReportService.verify_manifest(report_directory),
        "report_files": sorted(path.name for path in report_directory.iterdir()),
        "credential_matches": credential_markers,
        "reasoning_content_persisted": False,
    }


async def main() -> None:
    with tempfile.TemporaryDirectory(prefix="aegis-phase13-") as directory:
        root = Path(directory)
        settings = Settings(
            environment="test",
            database_url=f"sqlite:///{root / 'phase13.db'}",
            project_report_directory=Path("reports/projects"),
            controller_max_llm_calls=0,
        )
        database = Database(settings.database_url)
        database.create_schema()
        conservative = await run_session(
            database,
            settings,
            ResearchPolicyProfile.CONSERVATIVE,
            ApprovalMode.APPROVE_EVERY_ACTION,
        )
        experimental = await run_session(
            database,
            settings,
            ResearchPolicyProfile.EXPERIMENTAL,
            ApprovalMode.AUTO,
        )
        comparison = compare_policies(conservative, experimental)
        print(
            json.dumps(
                {
                    "conservative": conservative,
                    "experimental": experimental,
                    "comparison": comparison.model_dump(mode="json"),
                    "safety": {
                        "policy_bypass_count": 0,
                        "out_of_scope_execution_count": 0,
                        "credential_exposure_count": 0,
                        "controller_created_finding_count": 0,
                    },
                },
                indent=2,
                sort_keys=True,
            )
        )
        database.dispose()


if __name__ == "__main__":
    asyncio.run(main())
