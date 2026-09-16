import asyncio
import hashlib
from pathlib import Path
from uuid import uuid4

import pytest

from app.discovery.adapters import DNSAdapter, NmapAdapter, TLSAdapter, ToolAdapter
from app.discovery.errors import ToolExecutionError
from app.discovery.parsers import NmapParser
from app.discovery.registry import ToolRegistry
from app.domain.common import Provenance
from app.domain.discovery import (
    ArtifactType,
    TLSResult,
    ToolArtifact,
    ToolErrorCode,
    ToolRequest,
    ToolTarget,
)


def _request(tool: str, profile: str, scheme: str = "http") -> ToolRequest:
    return ToolRequest(
        tool=tool,
        profile=profile,
        target=ToolTarget.from_scope("127.0.0.1", (8001,), scheme),
        timeout_seconds=2,
    )


def test_nmap_parser_preserves_actual_fields_and_rejects_malformed_xml() -> None:
    raw = Path("tests/fixtures/nmap/sample.xml").read_bytes()
    records = NmapParser().parse(raw)
    assert [(item.port, item.state) for item in records] == [(8001, "open"), (9000, "closed")]
    assert records[0].service_name == "http"
    assert records[0].product == "uvicorn"
    assert records[1].product is None
    assert NmapParser().parse(
        b'<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun/>'
    ) == []
    for invalid in (b"<broken", b"<!DOCTYPE x><nmaprun/>"):
        with pytest.raises(ToolExecutionError) as captured:
            NmapParser().parse(invalid)
        assert captured.value.code is ToolErrorCode.PARSER_FAILED
    with pytest.raises(ToolExecutionError) as unexpected_root:
        NmapParser().parse(b"<not-nmap/>")
    assert unexpected_root.value.code is ToolErrorCode.ARTIFACT_INVALID
    with pytest.raises(ToolExecutionError) as oversized:
        NmapParser(max_bytes=8).parse(b"<nmaprun/>")
    assert oversized.value.code is ToolErrorCode.OUTPUT_TOO_LARGE


def test_nmap_argv_is_closed_profile_generated_and_binary_fixed() -> None:
    registry = ToolRegistry(
        binary_resolver=lambda _: "/fixed/nmap",
        version_inspector=lambda _: "7.95",
    )
    adapter = NmapAdapter(registry.require("nmap"))
    argv = adapter.argv(_request("nmap", "service_discovery"))
    assert argv == (
        "/fixed/nmap",
        "-Pn",
        "-n",
        "-sV",
        "--version-light",
        "-p",
        "8001",
        "-oX",
        "-",
        "127.0.0.1",
    )
    assert not {"--script", "--script-args", "/bin/sh"} & set(argv)
    assert isinstance(adapter, ToolAdapter)


@pytest.mark.asyncio
async def test_dns_and_tls_adapters_use_injected_local_deterministic_probes() -> None:
    dns = DNSAdapter(resolver=lambda _: ("127.0.0.1", "::1"))
    dns_result = await dns.execute(_request("dns", "lookup"))
    assert dns_result.artifact_type is ArtifactType.DNS_JSON
    assert dns_result.parsed_records[0].addresses == ("127.0.0.1", "::1")

    tls_value = TLSResult(
        host="127.0.0.1",
        port=8001,
        tls_available=True,
        protocol="TLSv1.3",
        certificate_presented=True,
        fingerprint_sha256="a" * 64,
    )
    tls = TLSAdapter(probe=lambda host, port, timeout: tls_value)
    tls_result = await tls.execute(_request("tls", "inspect", "https"))
    assert tls_result.artifact_type is ArtifactType.TLS_JSON
    assert tls_result.parsed_records == (tls_value,)


def test_tool_artifact_hash_is_raw_byte_exact_and_tamper_evident() -> None:
    raw = b"<nmaprun/>"
    artifact = ToolArtifact.from_bytes(
        raw=raw,
        research_session_id=uuid4(),
        tool_run_id=uuid4(),
        tool_id="nmap",
        tool_version="7.95",
        artifact_type=ArtifactType.NMAP_XML,
        content_type="application/xml",
        parser_version=NmapParser.version,
        provenance=Provenance(source_type="test", source_reference="artifact"),
    )
    assert artifact.content_bytes() == raw
    assert artifact.sha256 == hashlib.sha256(raw).hexdigest()


def test_unavailable_adapter_fails_closed_without_process() -> None:
    registry = ToolRegistry(binary_resolver=lambda _: None, version_inspector=lambda _: None)
    adapter = NmapAdapter(registry.require("nmap"))
    with pytest.raises(ToolExecutionError) as captured:
        asyncio.run(adapter.execute(_request("nmap", "service_discovery")))
    assert captured.value.code is ToolErrorCode.TOOL_NOT_AVAILABLE
