import hashlib
import json
from html import escape
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from app import __version__
from app.config import Settings
from app.domain.attack_graph import GraphSnapshotStatus
from app.domain.operator import (
    FileManifestEntry,
    FindingReport,
    ReportManifest,
    ReportMetadata,
    ReportStatus,
    ResearchEventType,
    canonical_hash,
)
from app.operator.service import ResearchEventService, operator_provenance
from app.storage.database import Database
from app.storage.repositories import RepositorySet
from app.system_model.serialization import export_model
from app.web_surface.queries import WebSurfaceQueryService


_SECRET_KEYS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "api_key",
    "apikey",
    "token",
    "access_token",
    "refresh_token",
    "nvidia_api_key",
}


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if str(key).lower() in _SECRET_KEYS else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        lowered = value.lower()
        if lowered.startswith("bearer ") or lowered.startswith("nvapi-"):
            return "[REDACTED]"
    return value


class ReportService:
    def __init__(self, database: Database, settings: Settings) -> None:
        self.database = database
        self.settings = settings
        self.events = ResearchEventService(database)

    def build_core(self, session_id: UUID) -> dict[str, Any]:
        self.events.sync_session(session_id)
        with self.database.session_factory() as session:
            r = RepositorySet(session)
            research = r.research_sessions.get(session_id)
            if research is None or research.project_id is None:
                raise ValueError("report requires a project-linked session")
            project = r.research_projects.get(research.project_id)
            if project is None:
                raise ValueError("report project does not exist")
            policy = r.research_policies.get(project.research_policy_id)
            budget = r.research_budgets.get_by_session(session_id)
            observations = r.observations.list_by_session(session_id)
            evidence = r.evidence.list_by_session(session_id)
            hypotheses = r.hypotheses.list_by_session(session_id)
            experiments = r.experiments.list_by_session(session_id)
            verifications = r.verification_results.list_by_session(session_id)
            findings = r.findings.list_by_session(session_id)
            gaps = r.evidence_gaps.list_by_session(session_id)
            actions = r.research_actions.list_by_session(session_id)
            runs = r.tool_runs.list_by_session(session_id)
            events = r.research_events.list_by_session(session_id, limit=10_000)
            model = export_model(r, session_id)
            graphs = r.attack_graph_snapshots.list_by_session(session_id)
            knowledge = r.knowledge_snapshots.list_by_session(session_id)
            current_graph = next(
                (item for item in reversed(graphs) if item.status is GraphSnapshotStatus.CURRENT),
                None,
            )
            signals_by_id = {
                item.id: item
                for graph in graphs
                for item in r.candidate_signals.list_by_graph(graph.id)
            }
            signals = list(signals_by_id.values())
            web_provenance = r.web_resource_provenance.list_by_session(session_id)
            web_observation_ids = {str(item.observation_id) for item in web_provenance}
            web_evidence_ids = {
                str(item.evidence_id) for item in web_provenance if item.evidence_id
            }
        verification_by_id = {item.id: item for item in verifications}
        hypothesis_by_id = {item.id: item for item in hypotheses}
        services_by_id = {str(item["id"]): item for item in model["services"]}
        endpoints_by_id = {str(item["id"]): item for item in model["endpoints"]}
        finding_reports = []
        for finding in findings:
            verification = (
                verification_by_id.get(finding.verification_result_id)
                if finding.verification_result_id
                else None
            )
            hypothesis = hypothesis_by_id.get(finding.hypothesis_id)
            lineage_evidence = set(finding.evidence_ids)
            lineage_observations = set(finding.observation_ids)
            if hypothesis:
                lineage_evidence.update(hypothesis.evidence_ids)
                lineage_observations.update(hypothesis.observation_ids)
            related_signals = [
                signal
                for signal in signals
                if lineage_evidence.intersection(signal.evidence_ids)
                or lineage_observations.intersection(signal.observation_ids)
            ]
            endpoint_ids = {
                signal.endpoint_entity_id
                for signal in related_signals
                if signal.endpoint_entity_id is not None
            }
            resource_ids = {
                signal.resource_entity_id
                for signal in related_signals
                if signal.resource_entity_id is not None
            }
            identity_ids = {
                entity_id
                for signal in related_signals
                for entity_id in (signal.subject_entity_id, signal.target_entity_id)
            }
            service_ids = {
                str(endpoints_by_id[str(endpoint_id)]["service_id"])
                for endpoint_id in endpoint_ids
                if str(endpoint_id) in endpoints_by_id
            }
            asset_ids = {
                UUID(str(services_by_id[service_id]["asset_id"]))
                for service_id in service_ids
                if service_id in services_by_id
            }
            finding_reports.append(
                FindingReport(
                    finding_id=finding.id,
                    title=finding.title,
                    claim=finding.claim,
                    verification_status=finding.verification_status.value,
                    verification_confidence=finding.verification_confidence.value,
                    affected_asset_ids=tuple(sorted(asset_ids, key=str)),
                    affected_endpoint_ids=tuple(sorted(endpoint_ids, key=str)),
                    affected_resource_ids=tuple(sorted(resource_ids, key=str)),
                    involved_identity_ids=tuple(sorted(identity_ids, key=str)),
                    hypothesis_id=finding.hypothesis_id,
                    experiment_id=finding.experiment_id,
                    verification_result_ids=tuple(finding.verification_result_ids),
                    verification_rule=(
                        f"{verification.rule_id}/{verification.rule_version}"
                        if verification
                        else None
                    ),
                    evidence_ids=tuple(finding.evidence_ids),
                    observation_ids=tuple(finding.observation_ids),
                    reproduction_summary=tuple(finding.reproduction),
                    impact=finding.impact,
                    limitations=tuple(finding.limitations),
                    observed_facts=tuple(
                        {"observation_id": str(item)} for item in finding.observation_ids
                    ),
                    deterministic_verification=(
                        verification.model_dump(mode="json")
                        if verification
                        else {"status": "UNKNOWN"}
                    ),
                    inferred_interpretation={
                        "hypothesis_id": str(finding.hypothesis_id),
                        "classification": "INFERRED_INTERPRETATION",
                    },
                    created_at=finding.created_at,
                    updated_at=finding.created_at,
                ).model_dump(mode="json")
            )
        evidence_index = [
            {
                "id": str(item.id),
                "integrity_hash": item.integrity_hash,
                "observation_ids": [
                    str(observation.id)
                    for observation in observations
                    if observation.evidence_id == item.id
                ],
                "method": item.request.method,
                "path": urlsplit(item.request.url).path,
                "status_code": item.response.status_code,
                "body_bytes": item.response.body_bytes,
                "truncated": item.response.truncated,
            }
            for item in evidence
        ]
        web_surface = WebSurfaceQueryService(self.database).export(session_id)
        report = {
            "report_version": "aegis-report-v1",
            "project": {
                "id": str(project.id),
                "name": project.name,
                "description": project.description,
                "status": project.status.value,
                "model_configuration": project.model_configuration,
            },
            "session": {
                "id": str(research.id),
                "status": research.status.value,
                "scope_revision": research.project_scope_revision,
            },
            "scope": research.scope.model_dump(mode="json"),
            "research_policy": {
                "profile": policy.profile.value if policy else "UNKNOWN",
                "settings": policy.settings.model_dump(mode="json") if policy else None,
                "experimental_mode": project.controller_mode.value == "EXPERIMENTAL",
                "approval_mode": project.approval_mode.value,
            },
            "budget": budget.model_dump(mode="json") if budget else None,
            "methodology": {
                "summary": "Typed actions, deterministic policy, evidence acquisition, model/graph projection, and verification.",
                "fact_authority": "Evidence and deterministic verification",
                "llm_authority": "Research proposals only",
            },
            "executive_summary": {
                "research_status": project.status.value,
                "assets_discovered": len(model["assets"]),
                "verified_findings": len(findings),
                "inconclusive_items": sum(
                    item.status.value == "INCONCLUSIVE" for item in hypotheses
                ),
                "open_evidence_gaps": sum(item.status.value != "RESOLVED" for item in gaps),
                "requests": sum(item.tool_id == "http" for item in runs),
                "tool_runs": len(runs),
                "web_resources": web_surface["summary"]["counts"]["resources"],
                "web_template_candidates": web_surface["summary"]["counts"]["template_candidates"],
            },
            "assets": model["assets"],
            "services": model["services"],
            "endpoints": model["endpoints"],
            "identities": model["identities"],
            "identity_access_observations": [item.model_dump(mode="json") for item in observations],
            "candidate_signals": [item.model_dump(mode="json") for item in signals],
            "hypotheses": [item.model_dump(mode="json") for item in hypotheses],
            "experiments": [item.model_dump(mode="json") for item in experiments],
            "verification_results": [item.model_dump(mode="json") for item in verifications],
            "findings": finding_reports,
            "inconclusive_items": [
                item.model_dump(mode="json")
                for item in hypotheses
                if item.status.value == "INCONCLUSIVE"
            ],
            "open_evidence_gaps": [
                item.model_dump(mode="json") for item in gaps if item.status.value != "RESOLVED"
            ],
            "actions": [item.model_dump(mode="json") for item in actions],
            "evidence_index": evidence_index,
            "timeline": [item.model_dump(mode="json") for item in events],
            "web_surface": web_surface,
            "web_observed_resources": web_surface["resources"],
            "web_tool_candidates": web_surface["template_candidates"],
            "web_verified_findings": [
                item
                for item in finding_reports
                if web_observation_ids.intersection(item["observation_ids"])
                or web_evidence_ids.intersection(item["evidence_ids"])
            ],
            "limitations": [
                "Local/development operator control plane; no production multi-user authentication.",
                "Raw evidence bodies are excluded from reports by default.",
            ],
            "hashes": {
                "scope": canonical_hash(research.scope.model_dump(mode="json")),
                "model": model.get("model_sha256"),
                "graph": current_graph.graph_hash if current_graph else None,
                "knowledge": knowledge[-1].sha256 if knowledge else None,
                "web_surface": (
                    web_surface["summary"]["snapshot"]["web_surface_sha256"]
                    if web_surface["summary"]["snapshot"]
                    else None
                ),
            },
            "deterministic_core_hash": "",
        }
        report["deterministic_core_hash"] = canonical_hash(report)
        return redact(report)

    def generate(self, session_id: UUID) -> tuple[ReportMetadata, ReportManifest]:
        report = self.build_core(session_id)
        project_id = UUID(report["project"]["id"])
        directory = self.settings.project_report_directory / str(project_id) / str(session_id)
        directory.mkdir(parents=True, exist_ok=True)
        files: dict[str, Any] = {
            "summary.json": report,
            "findings.json": report["findings"],
            "observations.json": report["identity_access_observations"],
            "evidence-index.json": report["evidence_index"],
            "assets.json": report["assets"],
            "graph.json": {
                "graph_hash": report["hashes"]["graph"],
                "candidate_signals": report["candidate_signals"],
            },
            "timeline.json": report["timeline"],
            "web-surface.json": report["web_surface"],
        }
        entries = []
        for name, payload in files.items():
            encoded = json.dumps(payload, sort_keys=True, indent=2).encode()
            (directory / name).write_bytes(encoded)
            entries.append(
                FileManifestEntry(
                    path=name, sha256=hashlib.sha256(encoded).hexdigest(), size_bytes=len(encoded)
                )
            )
        html = self._html(report).encode()
        (directory / "technical-report.html").write_bytes(html)
        entries.append(
            FileManifestEntry(
                path="technical-report.html",
                sha256=hashlib.sha256(html).hexdigest(),
                size_bytes=len(html),
            )
        )
        from app.domain.common import utc_now

        manifest = ReportManifest(
            project_id=project_id,
            session_id=session_id,
            generated_at=utc_now(),
            aegis_version=__version__,
            scope_hash=report["hashes"]["scope"],
            model_hash=report["hashes"]["model"],
            graph_hash=report["hashes"]["graph"],
            knowledge_hash=report["hashes"]["knowledge"],
            web_surface_hash=report["hashes"]["web_surface"],
            finding_ids=tuple(UUID(item["finding_id"]) for item in report["findings"]),
            files=tuple(entries),
        )
        (directory / "manifest.json").write_text(
            json.dumps(manifest.model_dump(mode="json"), sort_keys=True, indent=2), encoding="utf-8"
        )
        metadata = ReportMetadata(
            project_id=project_id,
            research_session_id=session_id,
            manifest_hash=manifest.sha256,
            path=str(directory),
            status=ReportStatus.COMPLETED,
            provenance=operator_provenance(f"report:{project_id}:{session_id}:{manifest.sha256}"),
        )
        with self.database.session_factory.begin() as session:
            RepositorySet(session).report_metadata.add(metadata)
        self.events.emit(
            project_id,
            ResearchEventType.REPORT_GENERATED,
            "ReportMetadata",
            str(metadata.id),
            "Evidence-backed report generated",
            session_id=session_id,
            data={"manifest_hash": manifest.sha256, "path": str(directory)},
        )
        return metadata, manifest

    @staticmethod
    def _html(report: dict[str, Any]) -> str:
        sections = []
        for title, key in (
            ("Executive Summary", "executive_summary"),
            ("Scope", "scope"),
            ("Research Policy", "research_policy"),
            ("Assets", "assets"),
            ("Services", "services"),
            ("Endpoints", "endpoints"),
            ("Web/Application Surface — Observed Resources", "web_observed_resources"),
            ("Web/Application Surface — Tool Candidates", "web_tool_candidates"),
            ("Web/Application Surface — Verified Findings", "web_verified_findings"),
            ("Candidate Signals", "candidate_signals"),
            ("Hypotheses", "hypotheses"),
            ("Verification Results", "verification_results"),
            ("Findings", "findings"),
            ("Open Evidence Gaps", "open_evidence_gaps"),
            ("Timeline", "timeline"),
            ("Limitations", "limitations"),
        ):
            content = escape(json.dumps(report[key], indent=2, sort_keys=True))
            sections.append(f"<section><h2>{escape(title)}</h2><pre>{content}</pre></section>")
        return (
            "<!doctype html><html><head><meta charset='utf-8'><title>Aegis Technical Report</title><style>body{font-family:system-ui;margin:2rem;max-width:1100px}pre{white-space:pre-wrap;background:#f4f4f4;padding:1rem}section{margin-bottom:2rem}</style></head><body><h1>Aegis Evidence-Backed Technical Report</h1>"
            + "".join(sections)
            + "</body></html>"
        )

    @staticmethod
    def verify_manifest(directory: Path) -> bool:
        payload = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
        for item in payload["files"]:
            data = (directory / item["path"]).read_bytes()
            if hashlib.sha256(data).hexdigest() != item["sha256"]:
                return False
            if len(data) != item["size_bytes"]:
                return False
        return True
