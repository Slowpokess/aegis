from uuid import UUID

from app.domain.common import FactClassification, Provenance, TrustClassification
from app.domain.observations import Observation, ObservationSource
from app.domain.web_surface import (
    BURP_PARSER_VERSION,
    TEMPLATE_ASSESSMENT_PARSER_VERSION,
    ContentSource,
    DiscoveredContent,
    TemplateAssessment,
    WebSurfaceIntake,
    WebTrafficRecord,
)


def _observation(
    *,
    asset_id: UUID,
    research_session_id: UUID,
    tool_artifact_id: UUID,
    artifact_sha256: str,
    request_id: str,
    source_type: str,
    normalized_data: dict[str, object],
    raw_data: dict[str, object],
    collector: str,
    provenance_source: str | None = None,
) -> Observation:
    return Observation(
        asset_id=asset_id,
        research_session_id=research_session_id,
        request_id=request_id,
        tool_artifact_id=tool_artifact_id,
        source=ObservationSource.TOOL,
        raw_data=raw_data,
        normalized_data={"source_type": source_type, **normalized_data},
        trust=TrustClassification.UNTRUSTED,
        normalized_data_trust=TrustClassification.TRUSTED,
        provenance=Provenance(
            source_type=provenance_source or source_type,
            source_reference=str(tool_artifact_id),
            collector=collector,
            classification=FactClassification.OBSERVED,
            metadata={
                "tool_artifact_id": str(tool_artifact_id),
                "artifact_sha256": artifact_sha256,
                "data_trust": "UNTRUSTED_TARGET_DATA",
            },
        ),
    )


def traffic_observations(
    records: tuple[WebTrafficRecord, ...],
    *,
    asset_id: UUID,
    research_session_id: UUID,
    tool_artifact_id: UUID,
    artifact_sha256: str,
) -> tuple[Observation, ...]:
    """Project parsed Burp exchanges into facts with immutable artifact lineage."""
    return tuple(
        _observation(
            asset_id=asset_id,
            research_session_id=research_session_id,
            tool_artifact_id=tool_artifact_id,
            artifact_sha256=artifact_sha256,
            request_id=f"BURP-{record.exchange_id[:32]}",
            source_type="burp_http_exchange",
            raw_data={
                "artifact_id": str(tool_artifact_id),
                "exchange_id": record.exchange_id,
                "request_sha256": record.request_sha256,
                "response_sha256": record.response_sha256,
            },
            normalized_data={
                "url": record.url,
                "scheme": record.scheme,
                "host": record.host,
                "port": record.port,
                "method": record.method,
                "path": record.path,
                "status_code": record.status_code,
                "mime_type": record.mime_type,
                "content_type": next(
                    (
                        value
                        for name, value in record.response_headers.items()
                        if name.lower() == "content-type"
                    ),
                    record.mime_type,
                ),
                "query_parameter_names": list(record.query_parameter_names),
                "body_parameter_names": list(record.body_parameter_names),
                "request_content_type": record.request_content_type,
                "header_names": [
                    name
                    for name in record.request_headers
                    if name.lower()
                    not in {"authorization", "cookie", "proxy-authorization", "set-cookie"}
                ],
            },
            collector=BURP_PARSER_VERSION,
        )
        for record in records
    )


def content_observations(
    records: tuple[DiscoveredContent, ...],
    *,
    asset_id: UUID,
    research_session_id: UUID,
    tool_artifact_id: UUID,
    artifact_sha256: str,
) -> tuple[Observation, ...]:
    return tuple(
        _observation(
            asset_id=asset_id,
            research_session_id=research_session_id,
            tool_artifact_id=tool_artifact_id,
            artifact_sha256=artifact_sha256,
            request_id=f"WEB-{record.semantic_key[:32]}",
            source_type="web_content_discovery",
            raw_data={
                "artifact_id": str(tool_artifact_id),
                "exchange_ids": list(record.exchange_ids),
                "source": record.source.value,
            },
            normalized_data={
                "url": record.url,
                "scheme": record.scheme,
                "host": record.host,
                "port": record.port,
                "method": record.method,
                "path": record.path,
                "resource_type": record.resource_type.value,
                "status_code": record.observed_status_code,
                "content_type": record.content_type,
                "source": record.source.value,
                "parameters": [item.model_dump(mode="json") for item in record.parameter_names],
            },
            collector="web-content-discovery-v1",
        )
        for record in records
        if record.source not in {ContentSource.TRAFFIC, ContentSource.TEMPLATE_RESULT}
    )


def assessment_observations(
    records: tuple[TemplateAssessment, ...],
    *,
    asset_id: UUID,
    research_session_id: UUID,
    tool_artifact_id: UUID,
    artifact_sha256: str,
    provenance_source: str = "web_template_match",
    collector: str = TEMPLATE_ASSESSMENT_PARSER_VERSION,
) -> tuple[Observation, ...]:
    return tuple(
        _observation(
            asset_id=asset_id,
            research_session_id=research_session_id,
            tool_artifact_id=tool_artifact_id,
            artifact_sha256=artifact_sha256,
            request_id=f"TMPL-{record.assessment_id[:32]}",
            source_type="web_template_match",
            raw_data={
                "artifact_id": str(tool_artifact_id),
                "raw_line_sha256": record.raw_line_sha256,
            },
            normalized_data={
                "matched_url": record.matched_url,
                "template_id": record.template_id,
                "template_name": record.template_name,
                "matcher_name": record.matcher_name,
                "tool_reported_severity": (
                    record.severity.value if record.severity else None
                ),
                "assessment_type": record.assessment_type,
                "tool_metadata": record.tool_metadata,
                "classification": "TOOL_REPORTED",
                "candidate_only": True,
            },
            collector=collector,
            provenance_source=provenance_source,
        )
        for record in records
    )


def intake_observations(
    intake: WebSurfaceIntake,
    *,
    asset_id: UUID,
    research_session_id: UUID,
    burp_artifact_id: UUID,
    burp_artifact_sha256: str,
    template_artifact_id: UUID | None = None,
    template_artifact_sha256: str | None = None,
) -> tuple[Observation, ...]:
    values = [
        *traffic_observations(
            intake.traffic,
            asset_id=asset_id,
            research_session_id=research_session_id,
            tool_artifact_id=burp_artifact_id,
            artifact_sha256=burp_artifact_sha256,
        ),
        *content_observations(
            intake.content,
            asset_id=asset_id,
            research_session_id=research_session_id,
            tool_artifact_id=burp_artifact_id,
            artifact_sha256=burp_artifact_sha256,
        ),
    ]
    if intake.assessments:
        if template_artifact_id is None or template_artifact_sha256 is None:
            raise ValueError("template assessments require template artifact lineage")
        values.extend(
            assessment_observations(
                intake.assessments,
                asset_id=asset_id,
                research_session_id=research_session_id,
                tool_artifact_id=template_artifact_id,
                artifact_sha256=template_artifact_sha256,
            )
        )
    return tuple(values)
