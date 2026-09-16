from dataclasses import dataclass
from urllib.parse import urlsplit
from uuid import uuid4

from app.domain.discovery import (
    PlanItemRequirement,
    ToolCapability,
    ToolDescriptor,
    ToolPolicyDecision,
    ToolRequest,
    ToolTarget,
)
from app.domain.research import ResearchSession
from app.domain.research_planner import ResearchIntentType
from app.discovery.policy import ToolPolicy
from app.discovery.registry import ToolRegistry


class CapabilityResolver:
    _MAPPING = {
        ResearchIntentType.DISCOVER_SERVICES: ToolCapability.SERVICE_DISCOVERY,
        ResearchIntentType.RESOLVE_HOST: ToolCapability.DNS_LOOKUP,
        ResearchIntentType.INSPECT_TLS: ToolCapability.TLS_INSPECTION,
        ResearchIntentType.OBSERVE_HTTP: ToolCapability.HTTP_REQUEST,
        ResearchIntentType.VERIFY_CANDIDATE_SIGNAL: ToolCapability.HTTP_REQUEST,
        ResearchIntentType.DISCOVER_WEB_CONTENT: ToolCapability.WEB_CONTENT_DISCOVERY,
        ResearchIntentType.ASSESS_WEB_TEMPLATES: ToolCapability.TEMPLATE_ASSESSMENT,
    }

    def resolve(self, intent_type: ResearchIntentType) -> ToolCapability:
        return self._MAPPING[intent_type]


@dataclass(frozen=True)
class ToolResolution:
    capability: ToolCapability
    descriptor: ToolDescriptor | None
    profile: str | None
    reason: str
    request: ToolRequest | None
    policy_preview: ToolPolicyDecision | None


class ToolResolver:
    _PREFERRED = {
        ToolCapability.SERVICE_DISCOVERY: ("nmap", "service_discovery", 30.0),
        ToolCapability.DNS_LOOKUP: ("dns", "lookup", 5.0),
        ToolCapability.TLS_INSPECTION: ("tls", "inspect", 10.0),
        ToolCapability.HTTP_REQUEST: ("http", "metadata", 5.0),
        ToolCapability.WEB_CONTENT_DISCOVERY: ("ffuf", "web_content_small", 20.0),
        ToolCapability.TEMPLATE_ASSESSMENT: ("nuclei", "safe_templates", 30.0),
    }

    def __init__(self, registry: ToolRegistry, policy: ToolPolicy) -> None:
        self.registry = registry
        self.policy = policy

    def resolve(
        self, capability: ToolCapability, research: ResearchSession
    ) -> ToolResolution:
        preferred = self._PREFERRED.get(capability)
        if preferred is None:
            return ToolResolution(
                capability, None, None, "no registered profile for capability", None, None
            )
        tool_id, profile, timeout = preferred
        descriptor = self.registry.get(tool_id)
        if descriptor is None or capability not in descriptor.capabilities:
            return ToolResolution(
                capability, descriptor, profile, "no registered tool provides capability", None, None
            )
        parsed = urlsplit(research.target.base_url)
        if parsed.hostname is None:
            return ToolResolution(
                capability, descriptor, profile, "session target has no host", None, None
            )
        request = ToolRequest(
            tool=tool_id,
            profile=profile,
            target=ToolTarget.from_scope(
                parsed.hostname, research.scope.ports, parsed.scheme
            ),
            timeout_seconds=min(timeout, descriptor.max_timeout_seconds),
            requirement=PlanItemRequirement.REQUIRED,
        )
        policy = self.policy.evaluate(
            research_session=research,
            discovery_plan_id=uuid4(),
            tool_run_id=uuid4(),
            request=request,
        )
        return ToolResolution(
            capability,
            descriptor,
            profile,
            f"deterministic preferred profile for {capability.value}",
            request,
            policy,
        )
