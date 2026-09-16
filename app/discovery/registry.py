from __future__ import annotations

import os
import re
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

from app.domain.discovery import (
    ArtifactType,
    TOOL_REGISTRY_VERSION,
    ExecutionBackend,
    ToolCapability,
    ToolDescriptor,
    ToolRisk,
    ToolType,
    ToolRequest,
)
from app.discovery.adapters import DNSAdapter, NmapAdapter, TLSAdapter
from app.active_web.adapters import FfufAdapter, NucleiAdapter
from app.active_web.parsers import FfufParser, NucleiParser
from app.discovery.parsers import NmapParser
from app.discovery.sdk import (
    BoundedJSONParser,
    ToolIntegration,
    ToolProfileMetadata,
    ToolUIMetadata,
)
from app.system_model.mapper import DNSObservationMapper, NmapObservationMapper, TLSObservationMapper
from app.logging_config import tool_registry_log

BinaryResolver = Callable[[str], str | None]
VersionInspector = Callable[[str], str | None]


def _inspect_nmap_version(executable: str) -> str | None:
    try:
        result = subprocess.run(
            [executable, "--version"],
            check=False,
            capture_output=True,
            timeout=3,
            env={"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError):
        return None
    first_line = result.stdout.decode(errors="replace").splitlines()
    if not first_line:
        return None
    words = first_line[0].split()
    return words[2] if len(words) >= 3 and words[:2] == ["Nmap", "version"] else None


def _inspect_external_version(executable: str, argument: str) -> str | None:
    try:
        result = subprocess.run(
            [executable, argument],
            check=False,
            capture_output=True,
            timeout=3,
            env={"PATH": "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError):
        return None
    output = (result.stdout + result.stderr).decode(errors="replace").strip().splitlines()
    if not output:
        return None
    pattern = re.compile(r"\bv?\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9.\-]+)?\b")
    for line in output:
        if "version" not in line.lower():
            continue
        match = pattern.search(line)
        if match:
            return match.group(0)
    for line in output:
        match = pattern.search(line)
        if match:
            return match.group(0)
    words = output[0].replace(":", " ").split()
    return words[-1] if words else None


class ToolRegistry:
    version = TOOL_REGISTRY_VERSION

    def __init__(
        self,
        *,
        binary_resolver: BinaryResolver = shutil.which,
        version_inspector: VersionInspector = _inspect_nmap_version,
        ffuf_version_inspector: VersionInspector | None = None,
        nuclei_version_inspector: VersionInspector | None = None,
        enabled: dict[str, bool] | None = None,
    ) -> None:
        resolved_nmap = binary_resolver("nmap")
        nmap_path = str(Path(resolved_nmap).resolve()) if resolved_nmap else None
        nmap_version = version_inspector(nmap_path) if nmap_path else None
        resolved_ffuf = binary_resolver("ffuf")
        ffuf_path = str(Path(resolved_ffuf).resolve()) if resolved_ffuf else None
        ffuf_inspector = ffuf_version_inspector or (
            lambda path: _inspect_external_version(path, "-V")
        )
        ffuf_version = ffuf_inspector(ffuf_path) if ffuf_path else None
        resolved_nuclei = binary_resolver("nuclei")
        nuclei_path = str(Path(resolved_nuclei).resolve()) if resolved_nuclei else None
        nuclei_inspector = nuclei_version_inspector or (
            lambda path: _inspect_external_version(path, "-version")
        )
        nuclei_version = nuclei_inspector(nuclei_path) if nuclei_path else None
        enabled = enabled or {}
        descriptors = (
            ToolDescriptor(
                id="ffuf",
                name="ffuf bounded web content discovery",
                version=ffuf_version,
                tool_type=ToolType.FFUF,
                capabilities=(ToolCapability.WEB_CONTENT_DISCOVERY,),
                execution_backend=ExecutionBackend.EXTERNAL_BINARY,
                supported_profiles=("web_content_small", "web_content_standard"),
                input_schema_version="active-web-action-v1",
                output_schema_version="ffuf-json-v1",
                requires_binary=True,
                binary_name="ffuf",
                executable_path=ffuf_path,
                available=ffuf_path is not None and ffuf_version is not None,
                risk_class=ToolRisk.LOW,
                enabled=enabled.get("ffuf", True),
                max_timeout_seconds=120,
                artifact_types=(ArtifactType.FFUF_JSON,),
                parser_version="ffuf-parser-v1",
                mapper_version="ffuf-web-observation-mapper-v1",
                supports_cancellation=True,
                documentation_summary="Scoped content discovery with approved wordlists and closed profiles.",
            ),
            ToolDescriptor(
                id="http",
                name="Aegis Rust HTTP Executor",
                version="0.2.0",
                tool_type=ToolType.HTTP,
                capabilities=(ToolCapability.HTTP_REQUEST,),
                execution_backend=ExecutionBackend.RUST_HTTP,
                supported_profiles=("metadata", "entity_observe"),
                input_schema_version="http-executor-v1",
                output_schema_version="http-evidence-v1",
                requires_binary=False,
                available=True,
                risk_class=ToolRisk.PASSIVE,
                enabled=enabled.get("http", True),
                max_timeout_seconds=10,
                artifact_types=(ArtifactType.HTTP_RESPONSE,),
                mapper_version="http-observation-mapper-v1",
                documentation_summary="Scoped HTTP observations through the Rust executor.",
            ),
            ToolDescriptor(
                id="dns",
                name="Aegis controlled DNS resolver",
                version=os.environ.get("AEGIS_DNS_ADAPTER_VERSION", "stdlib"),
                tool_type=ToolType.DNS,
                capabilities=(ToolCapability.DNS_LOOKUP,),
                execution_backend=ExecutionBackend.PYTHON_NATIVE,
                supported_profiles=("lookup",),
                input_schema_version="dns-request-v1",
                output_schema_version="dns-result-v1",
                requires_binary=False,
                available=True,
                risk_class=ToolRisk.PASSIVE,
                enabled=enabled.get("dns", True),
                max_timeout_seconds=5,
                artifact_types=(ArtifactType.DNS_JSON,),
                parser_version="bounded-json-parser-v1",
                mapper_version="dns-observation-mapper-v1",
                documentation_summary="Bounded A/AAAA/CNAME resolution for scoped hostnames.",
            ),
            ToolDescriptor(
                id="nuclei",
                name="Nuclei bounded template assessment",
                version=nuclei_version,
                tool_type=ToolType.NUCLEI,
                capabilities=(ToolCapability.TEMPLATE_ASSESSMENT,),
                execution_backend=ExecutionBackend.EXTERNAL_BINARY,
                supported_profiles=("safe_templates",),
                input_schema_version="active-web-action-v1",
                output_schema_version="nuclei-jsonl-v1",
                requires_binary=True,
                binary_name="nuclei",
                executable_path=nuclei_path,
                available=nuclei_path is not None and nuclei_version is not None,
                risk_class=ToolRisk.LOW,
                enabled=enabled.get("nuclei", True),
                max_timeout_seconds=120,
                artifact_types=(ArtifactType.NUCLEI_JSON,),
                parser_version="nuclei-parser-v1",
                mapper_version="nuclei-candidate-observation-mapper-v1",
                supports_cancellation=True,
                documentation_summary="Safe-active approved templates producing tool-reported candidates.",
            ),
            ToolDescriptor(
                id="tls",
                name="Aegis TLS inspector",
                version="stdlib",
                tool_type=ToolType.TLS,
                capabilities=(ToolCapability.TLS_INSPECTION,),
                execution_backend=ExecutionBackend.PYTHON_NATIVE,
                supported_profiles=("inspect",),
                input_schema_version="tls-request-v1",
                output_schema_version="tls-result-v1",
                requires_binary=False,
                available=True,
                risk_class=ToolRisk.PASSIVE,
                enabled=enabled.get("tls", True),
                max_timeout_seconds=10,
                artifact_types=(ArtifactType.TLS_JSON, ArtifactType.TLS_CERTIFICATE),
                parser_version="bounded-json-parser-v1",
                mapper_version="tls-observation-mapper-v1",
                documentation_summary="Read-only TLS handshake and certificate metadata.",
            ),
            ToolDescriptor(
                id="nmap",
                name="Nmap controlled discovery adapter",
                version=nmap_version,
                tool_type=ToolType.NMAP,
                capabilities=(
                    ToolCapability.HOST_DISCOVERY,
                    ToolCapability.PORT_DISCOVERY,
                    ToolCapability.SERVICE_DISCOVERY,
                ),
                execution_backend=ExecutionBackend.EXTERNAL_BINARY,
                supported_profiles=("common_tcp_ports", "service_discovery"),
                input_schema_version="nmap-request-v1",
                output_schema_version="nmap-xml-v1",
                requires_binary=True,
                binary_name="nmap",
                executable_path=nmap_path,
                available=nmap_path is not None and nmap_version is not None,
                risk_class=ToolRisk.LOW,
                enabled=enabled.get("nmap", True),
                max_timeout_seconds=30,
                artifact_types=(ArtifactType.NMAP_XML,),
                parser_version="nmap-parser-v1",
                mapper_version="nmap-observation-mapper-v1",
                supports_cancellation=True,
                documentation_url="https://nmap.org/book/man.html",
                documentation_summary="Exact-host, scoped-port service discovery using fixed profiles.",
            ),
        )
        self._tools: dict[str, ToolDescriptor] = {}
        self._integrations: dict[str, ToolIntegration] = {}
        for descriptor in descriptors:
            self.register(self._built_in_integration(descriptor))
        tool_registry_log.info(
            "registry initialized version=%s tools=%s",
            self.version,
            {
                descriptor.id: {
                    "available": descriptor.available,
                    "enabled": descriptor.enabled,
                    "version": descriptor.version,
                }
                for descriptor in self.list()
            },
        )

    @staticmethod
    def _built_in_integration(descriptor: ToolDescriptor) -> ToolIntegration:
        profile_capabilities = {
            "metadata": ToolCapability.HTTP_REQUEST,
            "entity_observe": ToolCapability.HTTP_REQUEST,
            "lookup": ToolCapability.DNS_LOOKUP,
            "inspect": ToolCapability.TLS_INSPECTION,
            "common_tcp_ports": ToolCapability.PORT_DISCOVERY,
            "service_discovery": ToolCapability.SERVICE_DISCOVERY,
            "web_content_small": ToolCapability.WEB_CONTENT_DISCOVERY,
            "web_content_standard": ToolCapability.WEB_CONTENT_DISCOVERY,
            "safe_templates": ToolCapability.TEMPLATE_ASSESSMENT,
        }
        profiles = tuple(
            ToolProfileMetadata(
                profile_id=profile,
                display_name=profile.replace("_", " ").title(),
                description=f"Bounded {descriptor.name} profile: {profile}",
                capability=profile_capabilities[profile],
                risk_class=descriptor.risk_class,
            )
            for profile in descriptor.supported_profiles
        )
        adapter: object | None = None
        parser: object | None = None
        mapper: object | None = None
        if descriptor.id == "nmap":
            parser = NmapParser()
            adapter = NmapAdapter(descriptor, parser=parser)
            mapper = NmapObservationMapper()
        elif descriptor.id == "dns":
            adapter = DNSAdapter()
            parser = BoundedJSONParser()
            mapper = DNSObservationMapper()
        elif descriptor.id == "tls":
            adapter = TLSAdapter()
            parser = BoundedJSONParser()
            mapper = TLSObservationMapper()
        elif descriptor.id == "ffuf":
            adapter = FfufAdapter(descriptor, output_max_bytes=1_000_000)
            parser = FfufParser(max_bytes=1_000_000, max_results=2_000)
            mapper = object()
        elif descriptor.id == "nuclei":
            adapter = NucleiAdapter(descriptor, output_max_bytes=1_000_000)
            parser = NucleiParser(max_bytes=1_000_000, max_results=2_000)
            mapper = object()
        return ToolIntegration(
            descriptor=descriptor,
            request_schema=ToolRequest,
            profiles=profiles,
            ui=ToolUIMetadata(
                summary=descriptor.documentation_summary or descriptor.name,
                documentation_url=descriptor.documentation_url,
            ),
            adapter=adapter,
            parser=parser,
            mapper=mapper,
            policy_requirements={
                "exact_scope": True,
                "max_timeout_seconds": descriptor.max_timeout_seconds,
            },
        )

    def register(self, integration: ToolIntegration | ToolDescriptor) -> None:
        if isinstance(integration, ToolDescriptor):
            integration = self._built_in_integration(integration)
        integration.validate()
        descriptor = integration.descriptor
        if descriptor.id in self._tools:
            raise ValueError(f"tool already registered: {descriptor.id}")
        self._tools[descriptor.id] = descriptor
        self._integrations[descriptor.id] = integration

    def get(self, tool_id: str) -> ToolDescriptor | None:
        return self._tools.get(tool_id)

    def require(self, tool_id: str) -> ToolDescriptor:
        descriptor = self.get(tool_id)
        if descriptor is None:
            raise ValueError(f"unknown tool: {tool_id}")
        return descriptor

    def list(self) -> list[ToolDescriptor]:
        return [self._tools[key] for key in sorted(self._tools)]

    def integration(self, tool_id: str) -> ToolIntegration | None:
        return self._integrations.get(tool_id)

    def integrations(self) -> list[ToolIntegration]:
        return [self._integrations[key] for key in sorted(self._integrations)]
