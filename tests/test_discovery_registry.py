from uuid import uuid4
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.discovery.policy import ToolPolicy
from app.discovery.registry import ToolRegistry
from app.domain.assets import Asset, AssetKind
from app.domain.common import Provenance
from app.domain.discovery import (
    DiscoveryProfile,
    ExecutionBackend,
    PlanItemRequirement,
    ToolCapability,
    ToolDescriptor,
    ToolPolicyReason,
    ToolRequest,
    ToolRisk,
    ToolTarget,
    ToolType,
)
from app.domain.research import ResearchSession, ResearchTarget, TargetScope


def _registry(*, available: bool = True, enabled: bool = True) -> ToolRegistry:
    return ToolRegistry(
        binary_resolver=lambda name: "/fixed/nmap" if name == "nmap" and available else None,
        version_inspector=lambda path: "7.95" if path else None,
        enabled={"nmap": enabled},
    )


def _research() -> ResearchSession:
    provenance = Provenance(source_type="test", source_reference="discovery-policy")
    asset = Asset(name="lab", kind=AssetKind.API, provenance=provenance)
    return ResearchSession(
        name="lab",
        target=ResearchTarget(
            asset_id=asset.id,
            name="lab",
            base_url="http://127.0.0.1:8001",
            provenance=provenance,
        ),
        scope=TargetScope(
            hosts=("127.0.0.1",),
            ports=(8001,),
            schemes=("http",),
            provenance=provenance,
        ),
        provenance=provenance,
    )


def _request(**updates) -> ToolRequest:
    values = {
        "tool": "nmap",
        "profile": "service_discovery",
        "target": ToolTarget.from_scope("127.0.0.1", (8001,), "http"),
        "timeout_seconds": 10,
        "requirement": PlanItemRequirement.OPTIONAL,
    }
    values.update(updates)
    return ToolRequest(**values)


def test_registry_is_unique_typed_and_reports_binary_availability() -> None:
    registry = _registry()
    assert registry.version == "tool-registry-v1"
    descriptors = registry.list()
    tool_ids = [item.id for item in descriptors]
    assert len(tool_ids) == len(set(tool_ids))
    assert {"dns", "http", "nmap", "tls", "ffuf", "nuclei"} <= set(tool_ids)
    nmap = registry.require("nmap")
    assert nmap.available is True
    assert nmap.executable_path == "/fixed/nmap"
    assert nmap.risk_class is ToolRisk.LOW
    assert ToolCapability.SERVICE_DISCOVERY in nmap.capabilities
    ffuf = registry.require("ffuf")
    nuclei = registry.require("nuclei")
    assert ffuf.supported_profiles == ("web_content_small", "web_content_standard")
    assert ffuf.capabilities == (ToolCapability.WEB_CONTENT_DISCOVERY,)
    assert nuclei.supported_profiles == ("safe_templates",)
    assert nuclei.capabilities == (ToolCapability.TEMPLATE_ASSESSMENT,)
    assert registry.require("http").execution_backend is ExecutionBackend.RUST_HTTP
    with pytest.raises(ValueError, match="already registered"):
        registry.register(nmap)
    assert _registry(available=False).require("nmap").available is False


def test_tool_request_schema_has_no_raw_argument_surface() -> None:
    with pytest.raises(ValidationError, match="raw_args"):
        ToolRequest.model_validate(
            {
                **_request().model_dump(mode="json"),
                "raw_args": ["--script", "arbitrary"],
            }
        )


def test_tool_policy_enforces_tool_profile_scope_port_enablement_and_risk() -> None:
    research = _research()
    plan_id = uuid4()

    def decide(registry: ToolRegistry, request: ToolRequest, max_risk=ToolRisk.LOW):
        return ToolPolicy(registry, max_risk=max_risk).evaluate(
            research_session=research,
            discovery_plan_id=plan_id,
            tool_run_id=uuid4(),
            request=request,
        )

    assert decide(_registry(), _request()).reason is ToolPolicyReason.ALLOWED
    assert decide(
        _registry(),
        _request(
            target=ToolTarget.from_scope("outside.invalid", (8001,), "http")
        ),
    ).reason is ToolPolicyReason.TARGET_OUT_OF_SCOPE
    assert decide(
        _registry(),
        _request(target=ToolTarget.from_scope("127.0.0.1", (9000,), "http")),
    ).reason is ToolPolicyReason.PORT_OUT_OF_SCOPE
    assert decide(
        _registry(), _request(profile="unknown")
    ).reason is ToolPolicyReason.PROFILE_NOT_ALLOWED
    assert decide(_registry(enabled=False), _request()).reason is ToolPolicyReason.TOOL_DISABLED
    assert decide(
        _registry(), _request(), max_risk=ToolRisk.PASSIVE
    ).reason is ToolPolicyReason.RISK_NOT_ALLOWED
    assert decide(
        _registry(available=False), _request()
    ).reason is ToolPolicyReason.TOOL_NOT_AVAILABLE
    assert ToolPolicy(_registry()).evaluate(
        research_session=research,
        discovery_plan_id=plan_id,
        tool_run_id=uuid4(),
        request=_request(),
        plan_request_count=9,
        max_plan_requests=8,
    ).reason is ToolPolicyReason.RATE_LIMIT_EXCEEDED


def test_descriptor_rejects_inconsistent_binary_registration() -> None:
    with pytest.raises(ValidationError, match="executable path"):
        ToolDescriptor(
            id="bad",
            name="bad",
            tool_type=ToolType.NMAP,
            capabilities=(ToolCapability.PORT_DISCOVERY,),
            execution_backend=ExecutionBackend.FIXED_BINARY,
            supported_profiles=(DiscoveryProfile.STANDARD.value,),
            input_schema_version="v1",
            output_schema_version="v1",
            requires_binary=False,
            executable_path="/bin/sh",
            available=True,
            risk_class=ToolRisk.LOW,
        )


def test_discovery_plane_has_no_llm_ground_truth_or_shell_command_surface() -> None:
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in Path("app/discovery").glob("*.py")
    )
    for forbidden in (
        "shell=True",
        "lab.ground_truth",
        "lab/scenarios",
        "from evals",
        "import evals",
        "app.llm",
        "HypothesisEngine",
    ):
        assert forbidden not in source
