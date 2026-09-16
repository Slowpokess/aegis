import hashlib
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import PurePosixPath
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from app.domain.research import TargetScope
from app.domain.web_surface import (
    ContentSource,
    DiscoveredContent,
    ParameterDescriptor,
    TemplateAssessment,
    WebParameterLocation,
    WebResourceType,
    WebSurfaceIntake,
    WebTrafficRecord,
)
from app.execution.protocol import SENSITIVE_HEADERS
from app.web_surface.parsers import BurpExportParser, TemplateAssessmentParser


def canonical_url(url: str) -> str:
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    default_port = 443 if scheme == "https" else 80
    port = parsed.port or default_port
    netloc = host if port == default_port else f"{host}:{port}"
    path = parsed.path or "/"
    return urlunsplit((scheme, netloc, path, "", ""))


def canonical_resource_key(method: str, url: str) -> str:
    return f"{method.upper()}:{canonical_url(url)}"


def _key(method: str, url: str) -> str:
    return hashlib.sha256(canonical_resource_key(method, url).encode()).hexdigest()


def _resource_type(
    *, path: str, source: ContentSource, status: int | None, content_type: str | None
) -> WebResourceType:
    if source is ContentSource.HTML_FORM:
        return WebResourceType.FORM_TARGET
    if status is not None and 300 <= status < 400:
        return WebResourceType.REDIRECT
    lowered_type = (content_type or "").lower()
    if path.startswith("/api/") or "json" in lowered_type:
        return WebResourceType.API_ROUTE
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in {
        ".css",
        ".js",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".ico",
        ".woff",
        ".woff2",
    }:
        return WebResourceType.STATIC_RESOURCE
    if "html" in lowered_type:
        return WebResourceType.PAGE
    if path.endswith("/") and path != "/":
        return WebResourceType.DIRECTORY
    return WebResourceType.UNKNOWN


@dataclass
class _Reference:
    method: str
    target: str
    source: ContentSource
    parameter_names: set[str] = field(default_factory=set)


class _ContentHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.references: list[_Reference] = []
        self._form: _Reference | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "a" and values.get("href"):
            self.references.append(_Reference("GET", values["href"], ContentSource.HTML_LINK))
        elif tag in {"link", "script", "img"}:
            target = values.get("href") or values.get("src")
            if target:
                self.references.append(_Reference("GET", target, ContentSource.HTML_RESOURCE))
        elif tag == "form":
            self._form = _Reference(
                (values.get("method") or "GET").upper(),
                values.get("action") or "",
                ContentSource.HTML_FORM,
            )
            self.references.append(self._form)
        elif tag in {"input", "select", "textarea", "button"} and self._form:
            name = values.get("name")
            if name:
                self._form.parameter_names.add(name)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None


class WebSurfacePipeline:
    def __init__(
        self,
        *,
        burp_parser: BurpExportParser | None = None,
        assessment_parser: TemplateAssessmentParser | None = None,
        max_links_per_response: int = 1000,
    ) -> None:
        self.burp_parser = burp_parser or BurpExportParser()
        self.assessment_parser = assessment_parser or TemplateAssessmentParser()
        self.max_links_per_response = max_links_per_response

    def build(
        self,
        *,
        scope: TargetScope,
        burp_export: bytes,
        template_results: bytes | None = None,
    ) -> WebSurfaceIntake:
        traffic_result = self.burp_parser.parse_result(burp_export, scope)
        assessment_result = (
            self.assessment_parser.parse_result(template_results, scope)
            if template_results is not None
            else None
        )
        assessments = assessment_result.assessments if assessment_result else ()
        content = self._discover(traffic_result.records, assessments, scope)
        return WebSurfaceIntake(
            traffic=traffic_result.records,
            content=content,
            assessments=assessments,
            input_entries=traffic_result.input_entries,
            ignored_out_of_scope=(
                traffic_result.ignored_out_of_scope
                + (assessment_result.ignored_out_of_scope if assessment_result else 0)
            ),
            redacted_sensitive_fields=traffic_result.redacted_sensitive_fields,
        )

    def _discover(
        self,
        traffic: tuple[WebTrafficRecord, ...],
        assessments: tuple[TemplateAssessment, ...],
        scope: TargetScope,
    ) -> tuple[DiscoveredContent, ...]:
        discovered: dict[tuple[str, ContentSource], DiscoveredContent] = {}

        def add(
            method: str,
            url: str,
            source: ContentSource,
            exchange_id: str | None = None,
            status: int | None = None,
            content_type: str | None = None,
            parameters: tuple[ParameterDescriptor, ...] = (),
        ) -> None:
            normalized = canonical_url(url)
            try:
                scope.validate_url(normalized)
            except ValueError:
                return
            parsed = urlsplit(normalized)
            default_port = 443 if parsed.scheme == "https" else 80
            semantic_key = _key(method, normalized)
            source_key = (semantic_key, source)
            existing = discovered.get(source_key)
            exchange_ids = (
                tuple(dict.fromkeys((*existing.exchange_ids, exchange_id)))
                if existing and exchange_id
                else (
                    existing.exchange_ids if existing else ((exchange_id,) if exchange_id else ())
                )
            )
            merged_parameters = (
                {
                    (item.name, item.location): item
                    for item in (*existing.parameter_names, *parameters)
                }
                if existing
                else {(item.name, item.location): item for item in parameters}
            )
            selected_type = _resource_type(
                path=parsed.path or "/",
                source=source,
                status=status,
                content_type=content_type,
            )
            if existing and selected_type is WebResourceType.UNKNOWN:
                selected_type = existing.resource_type
            discovered[source_key] = DiscoveredContent(
                semantic_key=semantic_key,
                url=normalized,
                scheme=parsed.scheme,
                host=parsed.hostname or "",
                port=parsed.port or default_port,
                method=method.upper(),
                path=parsed.path or "/",
                resource_type=selected_type,
                source=source,
                observed_status_code=(
                    status
                    if status is not None
                    else (existing.observed_status_code if existing else None)
                ),
                content_type=content_type or (existing.content_type if existing else None),
                parameter_names=tuple(
                    sorted(
                        merged_parameters.values(),
                        key=lambda item: (item.location.value, item.name),
                    )
                ),
                exchange_ids=exchange_ids,
            )

        for record in traffic:
            parsed_record_url = urlsplit(record.url)
            parameters = [
                ParameterDescriptor(name=name, location=WebParameterLocation.QUERY)
                for name in record.query_parameter_names
            ]
            parameters.extend(
                ParameterDescriptor(name=name, location=WebParameterLocation.BODY_FIELD)
                for name in record.body_parameter_names
            )
            parameters.extend(
                ParameterDescriptor(name=name, location=WebParameterLocation.HEADER_METADATA)
                for name in record.request_headers
                if name.lower() not in SENSITIVE_HEADERS
            )
            response_content_type = next(
                (
                    value
                    for name, value in record.response_headers.items()
                    if name.lower() == "content-type"
                ),
                record.mime_type or "",
            )
            add(
                record.method,
                record.url,
                ContentSource.TRAFFIC,
                record.exchange_id,
                record.status_code,
                response_content_type or None,
                tuple(parameters),
            )
            if record.response_body and (
                "html" in response_content_type.lower()
                or record.response_body.lstrip().lower().startswith(("<!doctype html", "<html"))
            ):
                parser = _ContentHTMLParser()
                parser.feed(record.response_body)
                if len(parser.references) > self.max_links_per_response:
                    raise ValueError("HTML reference count exceeds configured bound")
                for reference in parser.references:
                    target = reference.target or urlunsplit(
                        (
                            parsed_record_url.scheme,
                            parsed_record_url.netloc,
                            parsed_record_url.path or "/",
                            "",
                            "",
                        )
                    )
                    parameter_location = (
                        WebParameterLocation.QUERY
                        if reference.method == "GET"
                        else WebParameterLocation.FORM_FIELD
                    )
                    form_parameters = tuple(
                        ParameterDescriptor(name=name, location=parameter_location)
                        for name in sorted(reference.parameter_names)
                    )
                    resolved = urljoin(record.url, target)
                    query_parameters = tuple(
                        ParameterDescriptor(name=name, location=WebParameterLocation.QUERY)
                        for name, _ in parse_qsl(urlsplit(resolved).query)
                    )
                    add(
                        reference.method,
                        resolved,
                        reference.source,
                        record.exchange_id,
                        parameters=(*form_parameters, *query_parameters),
                    )
        for assessment in assessments:
            add("GET", assessment.matched_url, ContentSource.TEMPLATE_RESULT)
        return tuple(
            sorted(
                discovered.values(),
                key=lambda item: (item.url, item.method, item.source.value),
            )
        )
