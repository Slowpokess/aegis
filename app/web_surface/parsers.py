import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from email.parser import BytesHeaderParser
from email.policy import default
from urllib.parse import parse_qsl, urlsplit
from xml.etree import ElementTree

from app.domain.research import TargetScope
from app.domain.web_surface import (
    AssessmentSeverity,
    BURP_PARSER_VERSION,
    TEMPLATE_ASSESSMENT_PARSER_VERSION,
    TemplateAssessment,
    WebTrafficRecord,
)
from app.execution.protocol import SENSITIVE_HEADERS, redact_headers


@dataclass(frozen=True)
class BurpParseResult:
    records: tuple[WebTrafficRecord, ...]
    input_entries: int
    ignored_out_of_scope: int
    redacted_sensitive_fields: int


@dataclass(frozen=True)
class TemplateParseResult:
    assessments: tuple[TemplateAssessment, ...]
    input_entries: int
    ignored_out_of_scope: int


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _decode_payload(element: ElementTree.Element | None, max_bytes: int) -> bytes:
    if element is None or element.text is None:
        return b""
    encoded = element.text.encode()
    try:
        raw = base64.b64decode(encoded, validate=True) if element.get("base64") == "true" else encoded
    except ValueError as error:
        raise ValueError("Burp payload is not valid base64") from error
    if len(raw) > max_bytes:
        raise ValueError("Burp exchange payload exceeds configured bound")
    return raw


def _headers(raw: bytes) -> tuple[dict[str, str], bytes, int]:
    head, separator, body = raw.partition(b"\r\n\r\n")
    if not separator:
        head, separator, body = raw.partition(b"\n\n")
    lines = head.splitlines()
    if not lines:
        return {}, body, 0
    parsed = BytesHeaderParser(policy=default).parsebytes(b"\n".join(lines[1:]) + b"\n\n")
    values = {name: str(value) for name, value in parsed.items()}
    redactions = sum(name.lower() in SENSITIVE_HEADERS for name in values)
    return redact_headers(values), body, redactions


def _header(headers: dict[str, str], name: str) -> str | None:
    return next((value for key, value in headers.items() if key.lower() == name), None)


def _body_parameter_names(body: bytes, content_type: str | None) -> tuple[str, ...]:
    if not body or not content_type:
        return ()
    lowered = content_type.lower()
    if "application/x-www-form-urlencoded" in lowered:
        return tuple(sorted({name for name, _ in parse_qsl(body.decode(errors="replace")) if name}))
    if "application/json" in lowered:
        try:
            value = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return ()
        if isinstance(value, dict):
            return tuple(sorted(str(name) for name in value if str(name)))
    return ()


class BurpExportParser:
    version = BURP_PARSER_VERSION

    def __init__(
        self,
        *,
        max_bytes: int = 10_000_000,
        max_request_bytes: int = 1_000_000,
        max_response_bytes: int = 1_000_000,
        max_entries: int = 10_000,
    ) -> None:
        self.max_bytes = max_bytes
        self.max_request_bytes = max_request_bytes
        self.max_response_bytes = max_response_bytes
        self.max_entries = max_entries

    def parse(self, raw: bytes, scope: TargetScope) -> tuple[WebTrafficRecord, ...]:
        return self.parse_result(raw, scope).records

    def parse_result(self, raw: bytes, scope: TargetScope) -> BurpParseResult:
        if len(raw) > self.max_bytes:
            raise ValueError("Burp export exceeds configured bound")
        upper = raw.upper()
        if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
            raise ValueError("Burp export must not contain DTD or entity declarations")
        try:
            root = ElementTree.fromstring(raw)
        except ElementTree.ParseError as error:
            raise ValueError("Burp export is not valid XML") from error
        if root.tag != "items":
            raise ValueError("Burp export root must be items")
        items = root.findall("item")
        if len(items) > self.max_entries:
            raise ValueError("Burp export entry count exceeds configured bound")
        records: list[WebTrafficRecord] = []
        ignored = 0
        redacted = 0
        for item in items:
            url = (item.findtext("url") or "").strip()
            try:
                scope.validate_url(url)
            except ValueError:
                ignored += 1
                continue
            parsed_url = urlsplit(url)
            request = _decode_payload(item.find("request"), self.max_request_bytes)
            response = _decode_payload(item.find("response"), self.max_response_bytes)
            request_headers, request_body, request_redactions = _headers(request)
            response_headers, response_body, response_redactions = _headers(response)
            redacted += request_redactions + response_redactions
            method = (item.findtext("method") or "GET").strip().upper()
            status_text = (item.findtext("status") or "").strip()
            try:
                status_code = int(status_text)
            except ValueError as error:
                raise ValueError("Burp item has an invalid response status") from error
            default_port = 443 if parsed_url.scheme == "https" else 80
            captured_at = None
            raw_time = (item.findtext("time") or "").strip()
            if raw_time:
                try:
                    captured_at = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
                except ValueError:
                    captured_at = None
            identity = b"\x00".join(
                (method.encode(), url.encode(), _sha256(request).encode(), _sha256(response).encode())
            )
            request_content_type = _header(request_headers, "content-type")
            records.append(
                WebTrafficRecord(
                    exchange_id=_sha256(identity),
                    url=url,
                    scheme=parsed_url.scheme.lower(),
                    host=(parsed_url.hostname or "").lower(),
                    port=parsed_url.port or default_port,
                    method=method,
                    path=parsed_url.path or "/",
                    status_code=status_code,
                    mime_type=(item.findtext("mimetype") or "").strip() or None,
                    request_headers=request_headers,
                    response_headers=response_headers,
                    query_parameter_names=tuple(
                        sorted({name for name, _ in parse_qsl(parsed_url.query) if name})
                    ),
                    body_parameter_names=_body_parameter_names(
                        request_body, request_content_type
                    ),
                    request_content_type=request_content_type,
                    request_sha256=_sha256(request),
                    response_sha256=_sha256(response),
                    response_body=response_body.decode("utf-8", errors="replace"),
                    captured_at=captured_at,
                )
            )
        return BurpParseResult(
            records=tuple(records),
            input_entries=len(items),
            ignored_out_of_scope=ignored,
            redacted_sensitive_fields=redacted,
        )


class TemplateAssessmentParser:
    version = TEMPLATE_ASSESSMENT_PARSER_VERSION

    def __init__(self, *, max_bytes: int = 5_000_000, max_records: int = 10_000) -> None:
        self.max_bytes = max_bytes
        self.max_records = max_records

    def parse(self, raw: bytes, scope: TargetScope) -> tuple[TemplateAssessment, ...]:
        return self.parse_result(raw, scope).assessments

    def parse_result(self, raw: bytes, scope: TargetScope) -> TemplateParseResult:
        if len(raw) > self.max_bytes:
            raise ValueError("template assessment artifact exceeds configured bound")
        lines = [line for line in raw.splitlines() if line.strip()]
        if len(lines) > self.max_records:
            raise ValueError("template assessment record count exceeds configured bound")
        assessments: list[TemplateAssessment] = []
        ignored = 0
        for index, line in enumerate(lines):
            try:
                payload = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise ValueError(f"template assessment line {index + 1} is not valid JSON") from error
            if not isinstance(payload, dict):
                raise ValueError("template assessment records must be JSON objects")
            matched_url = payload.get("matched-at") or payload.get("url") or payload.get("host")
            if not isinstance(matched_url, str):
                raise ValueError("template assessment record has no matched URL")
            try:
                scope.validate_url(matched_url)
            except ValueError:
                ignored += 1
                continue
            template_id = payload.get("template-id")
            info = payload.get("info") if isinstance(payload.get("info"), dict) else {}
            name = info.get("name")
            if not isinstance(template_id, str) or not template_id:
                raise ValueError("template assessment record has no template ID")
            if not isinstance(name, str) or not name:
                raise ValueError("template assessment record has no template name")
            severity = None
            if isinstance(info.get("severity"), str):
                try:
                    severity = AssessmentSeverity(info["severity"].upper())
                except ValueError:
                    severity = AssessmentSeverity.UNKNOWN
            timestamp = None
            if isinstance(payload.get("timestamp"), str):
                try:
                    timestamp = datetime.fromisoformat(payload["timestamp"].replace("Z", "+00:00"))
                except ValueError:
                    pass
            line_hash = _sha256(line)
            tool_metadata = {
                key: payload[key]
                for key in ("type", "scheme", "port")
                if isinstance(payload.get(key), (str, int, float, bool))
            }
            assessments.append(
                TemplateAssessment(
                    assessment_id=_sha256(f"{template_id}\x00{matched_url}\x00{line_hash}".encode()),
                    template_id=template_id,
                    template_name=name,
                    matcher_name=payload.get("matcher-name") if isinstance(payload.get("matcher-name"), str) else None,
                    matched_url=matched_url,
                    severity=severity,
                    assessment_type=payload.get("type") if isinstance(payload.get("type"), str) else None,
                    tool_metadata=tool_metadata,
                    observed_at=timestamp,
                    raw_line_sha256=line_hash,
                )
            )
        return TemplateParseResult(
            assessments=tuple(assessments),
            input_entries=len(lines),
            ignored_out_of_scope=ignored,
        )
