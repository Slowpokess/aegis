import json
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit

from app.domain.evidence import Evidence
from app.domain.observations import Observation, ObservationSource
from app.domain.discovery import DNSResult, NmapServiceRecord, TLSResult


@dataclass(frozen=True)
class MappedHTTPObservation:
    scheme: str
    host: str
    port: int
    method: str
    path: str
    status_code: int | None
    identity_name: str | None
    identity_roles: tuple[str, ...]
    json_body: object | None


class ObservationModelMapper(Protocol):
    def supports(self, observation: Observation) -> bool: ...

    def map(self, observation: Observation, evidence: Evidence) -> MappedHTTPObservation: ...


class HTTPObservationMapper:
    """Map exact HTTP runtime data without adding a security interpretation."""
    version = "http-observation-mapper-v1"

    def supports(self, observation: Observation) -> bool:
        return observation.source is ObservationSource.HTTP

    def map(self, observation: Observation, evidence: Evidence) -> MappedHTTPObservation:
        parsed = urlsplit(evidence.request.url)
        if parsed.hostname is None or parsed.scheme not in {"http", "https"}:
            raise ValueError("HTTP evidence contains an invalid URL")
        default_port = 443 if parsed.scheme == "https" else 80
        identity_metadata = observation.provenance.metadata.get("identity")
        identity_name: str | None = None
        roles: tuple[str, ...] = ()
        if isinstance(identity_metadata, dict):
            raw_name = identity_metadata.get("name")
            raw_roles = identity_metadata.get("roles")
            if isinstance(raw_name, str) and raw_name:
                identity_name = raw_name
            if isinstance(raw_roles, list):
                roles = tuple(role for role in raw_roles if isinstance(role, str) and role)
        json_body: object | None = None
        if not evidence.response.truncated:
            try:
                json_body = json.loads(evidence.response.body)
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
        return MappedHTTPObservation(
            scheme=parsed.scheme,
            host=parsed.hostname.lower(),
            port=parsed.port or default_port,
            method=evidence.request.method.upper(),
            path=parsed.path or "/",
            status_code=evidence.response.status_code,
            identity_name=identity_name,
            identity_roles=roles,
            json_body=json_body,
        )


class WebSurfaceObservationMapper:
    """Map passive proxy traffic without interpreting template results as facts."""

    version = "web-surface-observation-mapper-v1"

    def supports(self, observation: Observation) -> bool:
        return (
            observation.source is ObservationSource.TOOL
            and observation.normalized_data.get("source_type")
            in {"burp_http_exchange", "web_content_discovery", "ffuf_web_discovery"}
        )

    def map(self, observation: Observation) -> MappedHTTPObservation:
        data = observation.normalized_data
        return MappedHTTPObservation(
            scheme=str(data["scheme"]),
            host=str(data["host"]),
            port=int(data["port"]),
            method=str(data["method"]),
            path=str(data["path"]),
            status_code=(int(data["status_code"]) if data.get("status_code") is not None else None),
            identity_name=None,
            identity_roles=(),
            json_body=None,
        )


class NmapObservationMapper:
    version = "nmap-observation-mapper-v1"
    def supports(self, observation: Observation) -> bool:
        return (
            observation.source is ObservationSource.TOOL
            and observation.normalized_data.get("source_type") == "nmap"
        )

    def map(self, observation: Observation) -> NmapServiceRecord:
        payload = {
            key: value
            for key, value in observation.normalized_data.items()
            if key != "source_type"
        }
        return NmapServiceRecord.model_validate(payload)


class DNSObservationMapper:
    version = "dns-observation-mapper-v1"
    def supports(self, observation: Observation) -> bool:
        return (
            observation.source is ObservationSource.TOOL
            and observation.normalized_data.get("source_type") == "dns"
        )

    def map(self, observation: Observation) -> DNSResult:
        payload = {
            key: value
            for key, value in observation.normalized_data.items()
            if key != "source_type"
        }
        return DNSResult.model_validate(payload)


class TLSObservationMapper:
    version = "tls-observation-mapper-v1"
    def supports(self, observation: Observation) -> bool:
        return (
            observation.source is ObservationSource.TOOL
            and observation.normalized_data.get("source_type") == "tls"
        )

    def map(self, observation: Observation) -> TLSResult:
        payload = {
            key: value
            for key, value in observation.normalized_data.items()
            if key != "source_type"
        }
        return TLSResult.model_validate(payload)
