import hashlib
import json
from urllib.parse import urlsplit
from uuid import UUID

from app.config import Settings
from app.domain.common import FactClassification, Provenance, utc_now
from app.domain.discovery import (
    ArtifactType,
    DiscoveryPlan,
    DiscoveryPlanStatus,
    DiscoveryProfile,
    ParserStatus,
    ToolArtifact,
    ToolCapability,
    ToolErrorCode,
    ToolRequest,
    ToolRun,
    ToolRunStatus,
    ToolTarget,
)
from app.domain.web_surface import (
    BURP_PARSER_VERSION,
    TEMPLATE_ASSESSMENT_PARSER_VERSION,
    WebImportResult,
    WebTemplateImportResult,
)
from app.storage.database import Database
from app.storage.repositories import RepositorySet
from app.system_model.builder import SystemModelBuilder
from app.web_surface.builder import WebSurfaceBuilder
from app.web_surface.observations import intake_observations
from app.web_surface.parsers import BurpExportParser, TemplateAssessmentParser
from app.web_surface.pipeline import WebSurfacePipeline, canonical_resource_key


class WebImportFailure(ValueError):
    def __init__(self, message: str, *, artifact_id: UUID) -> None:
        super().__init__(message)
        self.artifact_id = artifact_id


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class WebImportService:
    """Offline artifact intake; it performs no target request or tool execution."""

    def __init__(self, database: Database, settings: Settings) -> None:
        self.database = database
        self.settings = settings

    def import_burp(
        self,
        research_session_id: UUID,
        raw: bytes,
        *,
        template_results: bytes | None = None,
    ) -> WebImportResult:
        if len(raw) > self.settings.web_import_max_bytes:
            raise ValueError("Burp import exceeds configured file-size limit")
        if (
            template_results is not None
            and len(template_results) > self.settings.web_import_max_bytes
        ):
            raise ValueError("template import exceeds configured file-size limit")
        with self.database.session_factory() as session:
            r = RepositorySet(session)
            research = r.research_sessions.get(research_session_id)
            if research is None:
                raise ValueError("research session does not exist")
            before_keys = {
                item.canonical_key for item in r.web_resources.list_by_session(research_session_id)
            }
        parsed_target = urlsplit(research.target.base_url)
        target = ToolTarget.from_scope(
            parsed_target.hostname or "", research.scope.ports, parsed_target.scheme
        )
        request = ToolRequest(
            tool="burp_import",
            profile="offline_import",
            target=target,
            timeout_seconds=1,
        )
        plan = DiscoveryPlan(
            research_session_id=research_session_id,
            profile=DiscoveryProfile.PASSIVE,
            requested_capabilities=(
                ToolCapability.WEB_PROXY_ANALYSIS,
                ToolCapability.WEB_CONTENT_DISCOVERY,
                ToolCapability.OFFLINE_ARTIFACT_ANALYSIS,
            ),
            planned_tool_runs=(request,),
            status=DiscoveryPlanStatus.RUNNING,
            started_at=utc_now(),
            provenance=Provenance(
                source_type="web_import",
                source_reference=str(research_session_id),
                collector="web-surface-v1",
            ),
        )
        config_sha256 = _sha256(
            json.dumps(
                {
                    "session_id": str(research_session_id),
                    "scope": research.scope.model_dump(mode="json"),
                    "burp_sha256": _sha256(raw),
                    "template_sha256": _sha256(template_results) if template_results else None,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        )
        run = ToolRun(
            research_session_id=research_session_id,
            discovery_plan_id=plan.id,
            tool_id="burp_import",
            tool_version="offline-v1",
            profile="offline_import",
            profile_version="burp-offline-import-v1",
            requested_target=target,
            normalized_target=target,
            status=ToolRunStatus.RUNNING,
            parser_version=BURP_PARSER_VERSION,
            config_sha256=config_sha256,
            provenance=Provenance(
                source_type="offline_tool_run",
                source_reference=str(plan.id),
                collector="web-surface-v1",
            ),
        )
        burp_artifact = ToolArtifact.from_bytes(
            raw=raw,
            research_session_id=research_session_id,
            tool_run_id=run.id,
            tool_id="burp_import",
            tool_version="offline-v1",
            artifact_type=ArtifactType.BURP_EXPORT,
            content_type="application/xml",
            parser_version=BURP_PARSER_VERSION,
            provenance=Provenance(
                source_type="operator_upload",
                source_reference=str(run.id),
                collector="web-surface-v1",
                classification=FactClassification.OBSERVED,
                metadata={"data_trust": "UNTRUSTED_TARGET_DATA"},
            ),
        )
        template_artifact = (
            ToolArtifact.from_bytes(
                raw=template_results,
                research_session_id=research_session_id,
                tool_run_id=run.id,
                tool_id="template_import",
                tool_version="offline-v1",
                artifact_type=ArtifactType.NUCLEI_JSON,
                content_type="application/x-ndjson",
                parser_version=TEMPLATE_ASSESSMENT_PARSER_VERSION,
                provenance=Provenance(
                    source_type="operator_upload",
                    source_reference=str(run.id),
                    collector="web-surface-v1",
                    classification=FactClassification.OBSERVED,
                    metadata={"data_trust": "UNTRUSTED_TOOL_DATA"},
                ),
            )
            if template_results is not None
            else None
        )
        with self.database.session_factory.begin() as session:
            r = RepositorySet(session)
            r.discovery_plans.add(plan)
            r.tool_runs.add(run)
            r.tool_artifacts.add(burp_artifact)
            if template_artifact:
                r.tool_artifacts.add(template_artifact)
        pipeline = WebSurfacePipeline(
            burp_parser=BurpExportParser(
                max_bytes=self.settings.web_import_max_bytes,
                max_request_bytes=self.settings.web_import_max_request_bytes,
                max_response_bytes=self.settings.web_import_max_response_bytes,
                max_entries=self.settings.web_import_max_entries,
            ),
            assessment_parser=TemplateAssessmentParser(
                max_bytes=self.settings.web_import_max_bytes,
                max_records=self.settings.web_import_max_template_records,
            ),
            max_links_per_response=self.settings.web_import_max_html_references,
        )
        try:
            intake = pipeline.build(
                scope=research.scope,
                burp_export=raw,
                template_results=template_results,
            )
        except ValueError as error:
            self._fail(plan, run, burp_artifact, template_artifact, str(error))
            raise WebImportFailure(str(error), artifact_id=burp_artifact.id) from error
        observations = intake_observations(
            intake,
            asset_id=research.target.asset_id,
            research_session_id=research_session_id,
            burp_artifact_id=burp_artifact.id,
            burp_artifact_sha256=burp_artifact.sha256,
            template_artifact_id=template_artifact.id if template_artifact else None,
            template_artifact_sha256=template_artifact.sha256 if template_artifact else None,
        )
        artifact_ids = [burp_artifact.id]
        if template_artifact:
            artifact_ids.append(template_artifact.id)
        with self.database.session_factory.begin() as session:
            r = RepositorySet(session)
            r.tool_artifacts.update(
                burp_artifact.model_copy(update={"parser_status": ParserStatus.COMPLETED})
            )
            if template_artifact:
                r.tool_artifacts.update(
                    template_artifact.model_copy(update={"parser_status": ParserStatus.COMPLETED})
                )
            for observation in observations:
                r.observations.add(observation)
            r.tool_runs.update(
                run.model_copy(
                    update={
                        "status": ToolRunStatus.COMPLETED,
                        "finished_at": utc_now(),
                        "exit_code": 0,
                        "artifact_ids": artifact_ids,
                        "observation_ids": [item.id for item in observations],
                    }
                )
            )
            r.discovery_plans.update(
                plan.model_copy(
                    update={
                        "status": DiscoveryPlanStatus.COMPLETED,
                        "finished_at": utc_now(),
                    }
                )
            )
        SystemModelBuilder(self.database).build(research_session_id)
        snapshot = WebSurfaceBuilder(self.database).build(research_session_id)
        touched_keys = {canonical_resource_key(item.method, item.url) for item in intake.content}
        return WebImportResult(
            research_session_id=research_session_id,
            discovery_plan_id=plan.id,
            tool_run_id=run.id,
            burp_artifact_id=burp_artifact.id,
            template_artifact_id=template_artifact.id if template_artifact else None,
            artifact_sha256=burp_artifact.sha256,
            input_entries=(
                len(intake.traffic) + len(intake.assessments) + intake.ignored_out_of_scope
            ),
            parsed_entries=len(intake.traffic) + len(intake.assessments),
            in_scope_entries=len(intake.traffic) + len(intake.assessments),
            ignored_out_of_scope=intake.ignored_out_of_scope,
            redacted_sensitive_fields=intake.redacted_sensitive_fields,
            observation_ids=tuple(item.id for item in observations),
            resources_created=len(touched_keys - before_keys),
            resources_updated=len(touched_keys & before_keys),
            resource_count=snapshot.resource_count,
            parameter_count=snapshot.parameter_count,
            request_template_count=snapshot.request_template_count,
            candidate_count=snapshot.candidate_count,
            web_surface_sha256=snapshot.web_surface_sha256,
        )

    def import_template_assessment(
        self, research_session_id: UUID, raw: bytes
    ) -> WebTemplateImportResult:
        """Import passive JSONL assertions; this does not execute a template tool."""
        if len(raw) > self.settings.web_import_max_bytes:
            raise ValueError("template import exceeds configured file-size limit")
        with self.database.session_factory() as session:
            r = RepositorySet(session)
            research = r.research_sessions.get(research_session_id)
            if research is None:
                raise ValueError("research session does not exist")
            before_keys = {
                item.canonical_key for item in r.web_resources.list_by_session(research_session_id)
            }
            findings_before = len(r.findings.list_by_session(research_session_id))
        parsed_target = urlsplit(research.target.base_url)
        target = ToolTarget.from_scope(
            parsed_target.hostname or "", research.scope.ports, parsed_target.scheme
        )
        tool_request = ToolRequest(
            tool="template_import",
            profile="offline_import",
            target=target,
            timeout_seconds=1,
        )
        plan = DiscoveryPlan(
            research_session_id=research_session_id,
            profile=DiscoveryProfile.PASSIVE,
            requested_capabilities=(ToolCapability.OFFLINE_ARTIFACT_ANALYSIS,),
            planned_tool_runs=(tool_request,),
            status=DiscoveryPlanStatus.RUNNING,
            started_at=utc_now(),
            provenance=Provenance(
                source_type="web_template_import",
                source_reference=str(research_session_id),
                collector="web-surface-v1",
            ),
        )
        run = ToolRun(
            research_session_id=research_session_id,
            discovery_plan_id=plan.id,
            tool_id="template_import",
            tool_version="offline-v1",
            profile="offline_import",
            profile_version="template-offline-import-v1",
            requested_target=target,
            normalized_target=target,
            status=ToolRunStatus.RUNNING,
            parser_version=TEMPLATE_ASSESSMENT_PARSER_VERSION,
            config_sha256=_sha256(raw),
            provenance=Provenance(
                source_type="offline_tool_run",
                source_reference=str(plan.id),
                collector="web-surface-v1",
            ),
        )
        artifact = ToolArtifact.from_bytes(
            raw=raw,
            research_session_id=research_session_id,
            tool_run_id=run.id,
            tool_id="template_import",
            tool_version="offline-v1",
            artifact_type=ArtifactType.NUCLEI_JSON,
            content_type="application/x-ndjson",
            parser_version=TEMPLATE_ASSESSMENT_PARSER_VERSION,
            provenance=Provenance(
                source_type="operator_upload",
                source_reference=str(run.id),
                collector="web-surface-v1",
                classification=FactClassification.OBSERVED,
                metadata={"data_trust": "UNTRUSTED_TOOL_DATA"},
            ),
        )
        with self.database.session_factory.begin() as session:
            r = RepositorySet(session)
            r.discovery_plans.add(plan)
            r.tool_runs.add(run)
            r.tool_artifacts.add(artifact)
        pipeline = WebSurfacePipeline(
            assessment_parser=TemplateAssessmentParser(
                max_bytes=self.settings.web_import_max_bytes,
                max_records=self.settings.web_import_max_template_records,
            )
        )
        try:
            intake = pipeline.build(
                scope=research.scope,
                burp_export=b"<items/>",
                template_results=raw,
            )
        except ValueError as error:
            self._fail(plan, run, artifact, None, str(error))
            raise WebImportFailure(str(error), artifact_id=artifact.id) from error
        observations = intake_observations(
            intake,
            asset_id=research.target.asset_id,
            research_session_id=research_session_id,
            burp_artifact_id=artifact.id,
            burp_artifact_sha256=artifact.sha256,
            template_artifact_id=artifact.id,
            template_artifact_sha256=artifact.sha256,
        )
        with self.database.session_factory.begin() as session:
            r = RepositorySet(session)
            r.tool_artifacts.update(
                artifact.model_copy(update={"parser_status": ParserStatus.COMPLETED})
            )
            for observation in observations:
                r.observations.add(observation)
            r.tool_runs.update(
                run.model_copy(
                    update={
                        "status": ToolRunStatus.COMPLETED,
                        "finished_at": utc_now(),
                        "exit_code": 0,
                        "artifact_ids": [artifact.id],
                        "observation_ids": [item.id for item in observations],
                    }
                )
            )
            r.discovery_plans.update(
                plan.model_copy(
                    update={
                        "status": DiscoveryPlanStatus.COMPLETED,
                        "finished_at": utc_now(),
                    }
                )
            )
        SystemModelBuilder(self.database).build(research_session_id)
        snapshot = WebSurfaceBuilder(self.database).build(research_session_id)
        touched_keys = {
            canonical_resource_key("GET", item.matched_url) for item in intake.assessments
        }
        with self.database.session_factory() as session:
            findings_after = len(
                RepositorySet(session).findings.list_by_session(research_session_id)
            )
        return WebTemplateImportResult(
            research_session_id=research_session_id,
            discovery_plan_id=plan.id,
            tool_run_id=run.id,
            artifact_id=artifact.id,
            artifact_sha256=artifact.sha256,
            input_entries=intake.input_entries,
            in_scope_entries=len(intake.assessments),
            ignored_out_of_scope=intake.ignored_out_of_scope,
            observation_ids=tuple(item.id for item in observations),
            resources_created=len(touched_keys - before_keys),
            candidate_count=snapshot.candidate_count,
            finding_count=findings_after - findings_before,
            web_surface_sha256=snapshot.web_surface_sha256,
        )

    def _fail(
        self,
        plan: DiscoveryPlan,
        run: ToolRun,
        burp_artifact: ToolArtifact,
        template_artifact: ToolArtifact | None,
        error: str,
    ) -> None:
        with self.database.session_factory.begin() as session:
            r = RepositorySet(session)
            r.tool_artifacts.update(
                burp_artifact.model_copy(
                    update={"parser_status": ParserStatus.FAILED, "parser_error": error}
                )
            )
            if template_artifact:
                r.tool_artifacts.update(
                    template_artifact.model_copy(
                        update={"parser_status": ParserStatus.FAILED, "parser_error": error}
                    )
                )
            r.tool_runs.update(
                run.model_copy(
                    update={
                        "status": ToolRunStatus.FAILED,
                        "finished_at": utc_now(),
                        "artifact_ids": [
                            burp_artifact.id,
                            *([template_artifact.id] if template_artifact else []),
                        ],
                        "error_code": ToolErrorCode.PARSER_FAILED,
                        "error": error,
                    }
                )
            )
            r.discovery_plans.update(
                plan.model_copy(
                    update={
                        "status": DiscoveryPlanStatus.FAILED,
                        "finished_at": utc_now(),
                        "error": error,
                    }
                )
            )
