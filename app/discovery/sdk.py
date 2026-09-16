import json
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel

from app.domain.discovery import (
    TOOL_INTEGRATION_VERSION,
    ToolCapability,
    ToolDescriptor,
    ToolRisk,
)
from app.domain.observations import Observation


@dataclass(frozen=True)
class ParsedToolResult:
    """Bounded parser output; it is data and never a Finding."""

    tool_id: str
    parser_version: str
    records: tuple[object, ...]


@runtime_checkable
class ToolArtifactParser(Protocol):
    version: str

    def parse(self, raw: bytes) -> object: ...


@runtime_checkable
class ObservationMapper(Protocol):
    version: str

    def map(self, parsed: object) -> tuple[Observation, ...]: ...


@dataclass(frozen=True)
class ToolProfileMetadata:
    profile_id: str
    display_name: str
    description: str
    capability: ToolCapability
    risk_class: ToolRisk


@dataclass(frozen=True)
class ToolUIMetadata:
    summary: str
    documentation_url: str | None = None


@dataclass(frozen=True)
class ToolIntegration:
    descriptor: ToolDescriptor
    request_schema: type[BaseModel]
    profiles: tuple[ToolProfileMetadata, ...]
    ui: ToolUIMetadata
    adapter: object | None = None
    parser: ToolArtifactParser | None = None
    mapper: object | None = None
    policy_requirements: dict[str, Any] | None = None
    integration_version: str = TOOL_INTEGRATION_VERSION

    def validate(self) -> None:
        descriptor = self.descriptor
        if self.integration_version != TOOL_INTEGRATION_VERSION:
            raise ValueError("unsupported tool integration version")
        if descriptor.integration_version != self.integration_version:
            raise ValueError("descriptor/integration version mismatch")
        profile_ids = [profile.profile_id for profile in self.profiles]
        if len(profile_ids) != len(set(profile_ids)):
            raise ValueError("tool integration profile IDs must be unique")
        if set(profile_ids) != set(descriptor.supported_profiles):
            raise ValueError("integration profiles must match descriptor profiles")
        for profile in self.profiles:
            if profile.capability not in descriptor.capabilities:
                raise ValueError("profile capability is not declared by the tool")
            if profile.risk_class != descriptor.risk_class:
                raise ValueError("profile risk must match the bounded descriptor risk")
        if descriptor.artifact_types and self.parser is None and descriptor.id != "http":
            raise ValueError("artifact-producing integrations require a parser")
        if descriptor.requires_binary and descriptor.execution_backend.value not in {
            "FIXED_BINARY",
            "EXTERNAL_BINARY",
        }:
            raise ValueError("binary tools require a fixed external-binary backend")
        if descriptor.requires_binary and self.adapter is None:
            raise ValueError("binary integrations require a bounded adapter")


class BoundedJSONParser:
    version = "bounded-json-parser-v1"

    def __init__(self, *, max_bytes: int = 1_000_000) -> None:
        self.max_bytes = max_bytes

    def parse(self, raw: bytes) -> object:
        if len(raw) > self.max_bytes:
            raise ValueError("tool artifact exceeds parser input bound")
        try:
            return json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("tool artifact is not valid JSON") from error
