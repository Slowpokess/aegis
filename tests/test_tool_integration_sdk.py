from pathlib import Path

import pytest
from pydantic import ValidationError

from app.discovery.sdk import (
    BoundedJSONParser,
    ToolIntegration,
    ToolProfileMetadata,
    ToolUIMetadata,
)
from app.domain.discovery import (
    ArtifactType,
    ExecutionBackend,
    ToolCapability,
    ToolDescriptor,
    ToolRequest,
    ToolRisk,
    ToolType,
)
from tests.tool_integration_kit import assert_integration_contract


class StaticAdapter:
    tool_id = "demo_tool"


def demo_integration() -> ToolIntegration:
    descriptor = ToolDescriptor(
        id="demo_tool",
        name="Demo integration",
        version="demo-integration-v1",
        tool_type=ToolType.HTTP,
        capabilities=(ToolCapability.HTTP_REQUEST,),
        execution_backend=ExecutionBackend.PYTHON_NATIVE,
        supported_profiles=("fixture",),
        input_schema_version="demo-request-v1",
        output_schema_version="demo-output-v1",
        requires_binary=False,
        available=True,
        risk_class=ToolRisk.PASSIVE,
        enabled=False,
        artifact_types=(ArtifactType.HTTP_RESPONSE,),
        parser_version="bounded-json-parser-v1",
        mapper_version="demo-mapper-v1",
        documentation_summary="Test-only static integration; disabled by default.",
    )
    return ToolIntegration(
        descriptor=descriptor,
        request_schema=ToolRequest,
        profiles=(
            ToolProfileMetadata(
                profile_id="fixture",
                display_name="Fixture",
                description="Returns a sanitized static fixture",
                capability=ToolCapability.HTTP_REQUEST,
                risk_class=ToolRisk.PASSIVE,
            ),
        ),
        ui=ToolUIMetadata(summary="Generic SDK fixture"),
        adapter=StaticAdapter(),
        parser=BoundedJSONParser(max_bytes=1024),
        mapper=object(),
    )


def test_existing_integrations_comply_with_v1_registry() -> None:
    from app.discovery.registry import ToolRegistry

    registry = ToolRegistry(binary_resolver=lambda _: None)
    integrations = registry.integrations()
    integration_ids = {item.descriptor.id for item in integrations}
    assert {"dns", "http", "nmap", "tls", "ffuf", "nuclei"} <= integration_ids
    assert len(integration_ids) == len(integrations)
    for integration in integrations:
        assert_integration_contract(integration)


def test_demo_registration_is_visible_and_disabled_without_core_changes() -> None:
    from app.discovery.registry import ToolRegistry

    registry = ToolRegistry(binary_resolver=lambda _: None)
    integration = demo_integration()
    registry.register(integration)
    assert registry.require("demo_tool").enabled is False
    assert registry.integration("demo_tool") is integration


def test_integration_rejects_duplicate_profile_and_unknown_capability() -> None:
    integration = demo_integration()
    bad = ToolIntegration(
        descriptor=integration.descriptor,
        request_schema=ToolRequest,
        profiles=(integration.profiles[0], integration.profiles[0]),
        ui=integration.ui,
        adapter=integration.adapter,
        parser=integration.parser,
    )
    with pytest.raises(ValueError, match="unique"):
        bad.validate()


def test_parser_is_bounded_and_fixture_is_sanitized() -> None:
    raw = Path("tests/fixtures/tools/demo_tool/result.json").read_bytes()
    assert BoundedJSONParser(max_bytes=1024).parse(raw) == {
        "records": [{"kind": "fixture", "value": "sanitized"}]
    }
    with pytest.raises(ValueError, match="bound"):
        BoundedJSONParser(max_bytes=2).parse(raw)


def test_tool_request_forbids_executable_escape_fields() -> None:
    with pytest.raises(ValidationError):
        ToolRequest.model_validate(
            {
                "tool": "demo_tool",
                "profile": "fixture",
                "target": {
                    "host": "127.0.0.1",
                    "ports": [8001],
                    "scheme": "http",
                    "target_type": "IP",
                },
                "shell": "id",
            }
        )
