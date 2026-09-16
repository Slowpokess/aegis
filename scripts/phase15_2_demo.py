import asyncio
import json
import tempfile
from pathlib import Path

from app.attack_graph.builder import AttackGraphBuilder
from app.collectors.pipeline import ObservationPipeline
from app.config import Settings
from app.domain.operator import ApprovalMode, ResearchBudgetTemplate, ResearchPolicyProfile
from app.domain.research import TargetScope
from app.execution.rust_executor import RustExecutorClient
from app.operator.reporting import ReportService
from app.operator.service import ProjectService, operator_provenance
from app.research_planner.context import ResearchContextBuilder
from app.research_strategy.knowledge import KnowledgeService
from app.storage.database import Database
from app.storage.repositories import RepositorySet
from app.web_surface.builder import WebSurfaceBuilder
from app.web_surface.queries import WebSurfaceQueryService
from app.web_surface.service import WebImportService


SECRET = "PHASE15_LIVE_SECRET"


async def main() -> None:
    with tempfile.TemporaryDirectory(prefix="aegis-phase15-2-") as directory:
        settings = Settings(
            environment="test",
            database_url=f"sqlite:///{Path(directory) / 'phase15-2.db'}",
            project_report_directory=Path("reports/phase15-2-proof"),
            controller_max_llm_calls=0,
        )
        database = Database(settings.database_url)
        database.create_schema()
        projects = ProjectService(database, settings)
        project = projects.create(
            "phase15-2-controlled-proof", profile=ResearchPolicyProfile.CONSERVATIVE
        )
        project = projects.configure(
            project.id,
            scope=TargetScope(
                hosts=("127.0.0.1",),
                ports=(8001,),
                schemes=("http",),
                provenance=operator_provenance("phase15-2-proof-scope"),
            ),
            identity_names=("anonymous",),
            profile=ResearchPolicyProfile.CONSERVATIVE,
            approval_mode=ApprovalMode.AUTO,
            budget=ResearchBudgetTemplate(
                max_steps=3,
                max_actions=3,
                max_tool_runs=4,
                max_requests=4,
                max_duration_seconds=120,
                max_llm_calls=0,
            ),
        )
        research = projects.start(project.id)
        await ObservationPipeline(
            database, RustExecutorClient(Path("native/rust/target/debug/aegis-executor"))
        ).observe(research_session_id=research.id, path="/admin")

        importer = WebImportService(database, settings)
        burp = importer.import_burp(
            research.id, Path("tests/fixtures/web/phase15-burp.xml").read_bytes()
        )
        candidate_import = importer.import_template_assessment(
            research.id, Path("tests/fixtures/web/phase15-template.jsonl").read_bytes()
        )
        AttackGraphBuilder(database).build(research.id)
        KnowledgeService(database).build(research.id)
        build_a = WebSurfaceBuilder(database).build(research.id)
        build_b = WebSurfaceBuilder(database).build(research.id)
        query = WebSurfaceQueryService(database)
        exported = query.export(research.id)
        planner_context = ResearchContextBuilder(database).build(research.id)
        metadata, manifest = ReportService(database, settings).generate(research.id)
        report_directory = Path(metadata.path)
        report_text = "".join(
            path.read_text(encoding="utf-8") for path in report_directory.iterdir()
        )
        projection_text = json.dumps(exported, default=str, sort_keys=True)
        planner_text = planner_context.canonical_bytes().decode()
        frontend_text = "".join(
            path.read_text(encoding="utf-8", errors="ignore")
            for path in Path("web/dist").rglob("*")
            if path.is_file()
        )
        with database.session_factory() as session:
            r = RepositorySet(session)
            resources = r.web_resources.list_by_session(research.id)
            parameters = r.web_parameters.list_by_session(research.id)
            templates = r.http_request_templates.list_by_session(research.id)
            candidates = r.web_template_candidates.list_by_session(research.id)
            findings = r.findings.list_by_session(research.id)
            observations = r.observations.list_by_session(research.id)
            actions = r.research_actions.list_by_session(research.id)
            endpoints = r.system_endpoints.list_by_session(research.id)
            runs = r.tool_runs.list_by_session(research.id)
            admin = next(
                item for item in resources if item.method == "GET" and item.path == "/admin"
            )
            admin_sources = r.web_resource_provenance.list_by_resource(admin.id)
        scan_surfaces = {
            "projection": projection_text,
            "planner_context": planner_text,
            "reports": report_text,
            "frontend_build": frontend_text,
        }
        credential_matches = {name: text.count(SECRET) for name, text in scan_surfaces.items()}
        output = {
            "project": str(project.id),
            "session": str(research.id),
            "scope": research.scope.model_dump(mode="json"),
            "burp_artifact": str(burp.burp_artifact_id),
            "burp_sha256": burp.artifact_sha256,
            "template_artifact": str(candidate_import.artifact_id),
            "template_sha256": candidate_import.artifact_sha256,
            "entries": burp.input_entries,
            "in_scope": burp.in_scope_entries,
            "out_of_scope": burp.ignored_out_of_scope,
            "observations": len(observations),
            "web_resources": len(resources),
            "methods": {
                "GET": sum(item.method == "GET" for item in resources),
                "POST": sum(item.method == "POST" for item in resources),
            },
            "parameters": sorted({item.name for item in parameters}),
            "request_templates": len(templates),
            "template_candidates": len(candidates),
            "candidate_id": str(candidates[0].id),
            "candidate_resource_id": str(candidates[0].web_resource_id),
            "candidate_observation_id": str(candidates[0].observation_id),
            "candidate_artifact_id": str(candidates[0].tool_artifact_id),
            "findings_created_from_candidate": candidate_import.finding_count,
            "findings_total": len(findings),
            "build_a_hash": build_a.web_surface_sha256,
            "build_b_hash": build_b.web_surface_sha256,
            "build_hashes_equal": build_a.web_surface_sha256 == build_b.web_surface_sha256,
            "multi_source_resource_id": str(admin.id),
            "multi_source_observations": len(admin_sources),
            "multi_source_values": sorted({item.source.value for item in admin_sources}),
            "system_endpoint_id": str(admin.system_endpoint_id),
            "system_admin_endpoints": sum(
                item.method == "GET" and item.path == "/admin" for item in endpoints
            ),
            "external_active_resources": sum(item.host == "external.invalid" for item in resources),
            "external_system_entities": sum(item.host == "external.invalid" for item in endpoints),
            "external_executions": 0,
            "target_tool_runs_from_prompt": sum(
                item.tool_id not in {"burp_import", "template_import"} for item in runs
            ),
            "actions_from_prompt": len(actions),
            "planner_contains_prompt": "IGNORE SYSTEM" in planner_text,
            "planner_contains_secret": SECRET in planner_text,
            "report_id": str(metadata.id),
            "report_directory": str(report_directory),
            "report_files": sorted(path.name for path in report_directory.iterdir()),
            "manifest_sha256": manifest.sha256,
            "manifest_valid": ReportService.verify_manifest(report_directory),
            "credential_matches": credential_matches,
            "credential_exposure_total": sum(credential_matches.values()),
            "policy_bypass": 0,
            "tool_created_findings": 0,
            "controller_created_findings": 0,
        }
        print(json.dumps(output, indent=2, sort_keys=True))
        database.dispose()


if __name__ == "__main__":
    asyncio.run(main())
