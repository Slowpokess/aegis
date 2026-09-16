import asyncio
import _ssl
import hashlib
import json
import socket
import ssl
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from app.discovery.errors import ToolExecutionError
from app.discovery.parsers import NmapParser
from app.domain.discovery import (
    ArtifactType,
    DNSResult,
    TLSResult,
    ToolDescriptor,
    ToolErrorCode,
    ToolRequest,
)


@dataclass(frozen=True)
class AdapterExecution:
    raw_artifact: bytes | None
    artifact_type: ArtifactType | None
    content_type: str | None
    parsed_records: tuple[object, ...]
    parser_version: str | None
    argv: tuple[str, ...]
    exit_code: int | None
    stderr: str = ""


@runtime_checkable
class ToolAdapter(Protocol):
    """Typed adapter boundary; authorization remains in ToolPolicy."""

    tool_id: str

    def validate_request(self, request: ToolRequest) -> None: ...

    async def execute(self, request: ToolRequest) -> AdapterExecution: ...


class NmapAdapter:
    tool_id = "nmap"
    profile_versions = {
        "common_tcp_ports": "nmap-common-tcp-ports-v1",
        "service_discovery": "nmap-service-discovery-v1",
    }

    def __init__(
        self,
        descriptor: ToolDescriptor,
        *,
        artifact_max_bytes: int = 1_000_000,
        stderr_max_bytes: int = 32_000,
        parser: NmapParser | None = None,
    ) -> None:
        self.descriptor = descriptor
        self.artifact_max_bytes = artifact_max_bytes
        self.stderr_max_bytes = stderr_max_bytes
        self.parser = parser or NmapParser(max_bytes=artifact_max_bytes)

    def validate_request(self, request: ToolRequest) -> None:
        if request.tool != self.tool_id or request.profile not in self.profile_versions:
            raise ToolExecutionError(
                ToolErrorCode.PROFILE_NOT_ALLOWED, "unknown Nmap tool or profile"
            )

    def argv(self, request: ToolRequest) -> tuple[str, ...]:
        self.validate_request(request)
        executable = self.descriptor.executable_path
        if not executable or not self.descriptor.available:
            raise ToolExecutionError(
                ToolErrorCode.TOOL_NOT_AVAILABLE, "Nmap binary is unavailable"
            )
        ports = ",".join(str(port) for port in request.target.ports)
        fixed = [executable, "-Pn", "-n"]
        if request.profile == "service_discovery":
            fixed.extend(["-sV", "--version-light"])
        fixed.extend(["-p", ports, "-oX", "-", request.target.host])
        return tuple(fixed)

    async def execute(self, request: ToolRequest) -> AdapterExecution:
        argv = self.argv(request)
        with tempfile.TemporaryDirectory(prefix="aegis-nmap-") as working_directory:
            try:
                process = await asyncio.create_subprocess_exec(
                    *argv,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=str(Path(working_directory)),
                    env={"LANG": "C", "LC_ALL": "C"},
                )
            except FileNotFoundError as error:
                raise ToolExecutionError(
                    ToolErrorCode.TOOL_NOT_AVAILABLE,
                    "fixed Nmap executable was not found",
                ) from error

            async def bounded_read(
                stream: asyncio.StreamReader | None, limit: int
            ) -> bytes:
                if stream is None:
                    return b""
                chunks: list[bytes] = []
                size = 0
                while True:
                    chunk = await stream.read(min(65_536, limit + 1 - size))
                    if not chunk:
                        return b"".join(chunks)
                    chunks.append(chunk)
                    size += len(chunk)
                    if size > limit:
                        return b"".join(chunks)

            try:
                stdout, stderr = await asyncio.wait_for(
                    asyncio.gather(
                        bounded_read(process.stdout, self.artifact_max_bytes),
                        bounded_read(process.stderr, self.stderr_max_bytes),
                    ),
                    timeout=request.timeout_seconds,
                )
                if (
                    len(stdout) > self.artifact_max_bytes
                    or len(stderr) > self.stderr_max_bytes
                ):
                    process.kill()
                    await process.wait()
                    raise ToolExecutionError(
                        ToolErrorCode.OUTPUT_TOO_LARGE,
                        "Nmap output exceeded configured bounds",
                    )
                await asyncio.wait_for(process.wait(), timeout=2)
            except TimeoutError as error:
                process.kill()
                await process.wait()
                raise ToolExecutionError(
                    ToolErrorCode.PROCESS_TIMEOUT,
                    "Nmap process exceeded configured timeout",
                ) from error
        diagnostic = stderr.decode(errors="replace")
        if process.returncode != 0:
            raise ToolExecutionError(
                ToolErrorCode.PROCESS_FAILED,
                f"Nmap exited with code {process.returncode}: {diagnostic[:500]}",
            )
        return AdapterExecution(
            raw_artifact=stdout,
            artifact_type=ArtifactType.NMAP_XML,
            content_type="application/xml",
            parsed_records=(),
            parser_version=self.parser.version,
            argv=argv,
            exit_code=process.returncode,
            stderr=diagnostic,
        )


Resolver = Callable[[str], tuple[str, ...]]


def _resolve(host: str) -> tuple[str, ...]:
    answers = {
        item[4][0]
        for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    }
    return tuple(sorted(answers))


class DNSAdapter:
    tool_id = "dns"
    profile_version = "dns-lookup-v1"

    def __init__(self, resolver: Resolver = _resolve) -> None:
        self.resolver = resolver

    def validate_request(self, request: ToolRequest) -> None:
        if request.tool != self.tool_id or request.profile != "lookup":
            raise ToolExecutionError(
                ToolErrorCode.PROFILE_NOT_ALLOWED, "unknown DNS tool or profile"
            )

    async def execute(self, request: ToolRequest) -> AdapterExecution:
        self.validate_request(request)
        try:
            addresses = await asyncio.wait_for(
                asyncio.to_thread(self.resolver, request.target.host),
                timeout=request.timeout_seconds,
            )
        except TimeoutError as error:
            raise ToolExecutionError(
                ToolErrorCode.PROCESS_TIMEOUT, "DNS lookup exceeded configured timeout"
            ) from error
        except OSError as error:
            raise ToolExecutionError(
                ToolErrorCode.PROCESS_FAILED, "DNS lookup failed"
            ) from error
        result = DNSResult(
            requested_hostname=request.target.host,
            addresses=addresses,
        )
        raw = json.dumps(
            result.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode()
        return AdapterExecution(
            raw_artifact=raw,
            artifact_type=ArtifactType.DNS_JSON,
            content_type="application/json",
            parsed_records=(result,),
            parser_version=self.profile_version,
            argv=(),
            exit_code=None,
        )


TLSProbe = Callable[[str, int, float], TLSResult]


def _name(value: tuple[tuple[tuple[str, str], ...], ...] | None) -> str | None:
    if not value:
        return None
    return ",".join(f"{key}={item}" for group in value for key, item in group)


def _decode_certificate(der: bytes) -> dict[str, object]:
    pem = ssl.DER_cert_to_PEM_cert(der)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", encoding="ascii") as certificate:
        certificate.write(pem)
        certificate.flush()
        return _ssl._test_decode_cert(certificate.name)


def _inspect_tls(host: str, port: int, timeout: float) -> TLSResult:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
            der = tls_socket.getpeercert(binary_form=True)
            certificate = _decode_certificate(der) if der else {}
            san_names = tuple(
                value
                for kind, value in certificate.get("subjectAltName", ())
                if kind == "DNS"
            )
            return TLSResult(
                host=host,
                port=port,
                tls_available=True,
                protocol=tls_socket.version(),
                certificate_presented=bool(der),
                subject=_name(certificate.get("subject")),  # type: ignore[arg-type]
                issuer=_name(certificate.get("issuer")),  # type: ignore[arg-type]
                valid_from=certificate.get("notBefore"),
                valid_to=certificate.get("notAfter"),
                san_names=san_names,
                fingerprint_sha256=hashlib.sha256(der).hexdigest() if der else None,
            )


class TLSAdapter:
    tool_id = "tls"
    profile_version = "tls-inspection-v1"

    def __init__(self, probe: TLSProbe = _inspect_tls) -> None:
        self.probe = probe

    def validate_request(self, request: ToolRequest) -> None:
        if request.tool != self.tool_id or request.profile != "inspect":
            raise ToolExecutionError(
                ToolErrorCode.PROFILE_NOT_ALLOWED, "unknown TLS tool or profile"
            )

    async def execute(self, request: ToolRequest) -> AdapterExecution:
        self.validate_request(request)
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(
                    self.probe,
                    request.target.host,
                    request.target.ports[0],
                    request.timeout_seconds,
                ),
                timeout=request.timeout_seconds + 0.5,
            )
        except TimeoutError as error:
            raise ToolExecutionError(
                ToolErrorCode.PROCESS_TIMEOUT,
                "TLS inspection exceeded configured timeout",
            ) from error
        except OSError as error:
            raise ToolExecutionError(
                ToolErrorCode.PROCESS_FAILED, "TLS inspection failed"
            ) from error
        raw = json.dumps(
            result.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode()
        return AdapterExecution(
            raw_artifact=raw,
            artifact_type=ArtifactType.TLS_JSON,
            content_type="application/json",
            parsed_records=(result,),
            parser_version=self.profile_version,
            argv=(),
            exit_code=None,
        )
