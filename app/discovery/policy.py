import hashlib
import json
from uuid import UUID

from app.domain.common import FactClassification, Provenance
from app.domain.discovery import (
    ToolPolicyDecision,
    ToolPolicyReason,
    ToolRequest,
    ToolRisk,
    TargetType,
)
from app.domain.research import ResearchSession
from app.discovery.registry import ToolRegistry
from app.logging_config import policy_log


class ToolPolicy:
    def __init__(self, registry: ToolRegistry, *, max_risk: ToolRisk = ToolRisk.LOW) -> None:
        self.registry = registry
        self.max_risk = max_risk

    def evaluate(
        self,
        *,
        research_session: ResearchSession,
        discovery_plan_id: UUID,
        tool_run_id: UUID,
        request: ToolRequest,
        plan_request_count: int = 1,
        same_tool_request_count: int = 1,
        max_plan_requests: int = 8,
        max_concurrency: int = 2,
        estimated_request_cost: int = 1,
        remaining_request_budget: int | None = None,
        remaining_tool_run_budget: int | None = None,
        estimated_duration_seconds: float = 0,
        remaining_duration_seconds: float | None = None,
    ) -> ToolPolicyDecision:
        descriptor = self.registry.get(request.tool)
        reason = ToolPolicyReason.ALLOWED
        message = "tool request is within immutable session scope"
        allowed = True
        if descriptor is None or not descriptor.available:
            reason, message, allowed = (
                ToolPolicyReason.TOOL_NOT_AVAILABLE,
                "registered tool is not available",
                False,
            )
        elif not descriptor.enabled:
            reason, message, allowed = (
                ToolPolicyReason.TOOL_DISABLED,
                "registered tool is disabled",
                False,
            )
        elif request.profile not in descriptor.supported_profiles:
            reason, message, allowed = (
                ToolPolicyReason.PROFILE_NOT_ALLOWED,
                "tool profile is not registered",
                False,
            )
        elif request.target.host not in research_session.scope.hosts:
            reason, message, allowed = (
                ToolPolicyReason.TARGET_OUT_OF_SCOPE,
                "tool target host is outside immutable session scope",
                False,
            )
        elif not set(request.target.ports).issubset(research_session.scope.ports):
            reason, message, allowed = (
                ToolPolicyReason.PORT_OUT_OF_SCOPE,
                "tool target ports are outside immutable session scope",
                False,
            )
        elif request.target.scheme not in research_session.scope.schemes:
            reason, message, allowed = (
                ToolPolicyReason.TARGET_OUT_OF_SCOPE,
                "tool target scheme is outside immutable session scope",
                False,
            )
        elif descriptor.id == "nmap" and request.target.target_type is TargetType.HOSTNAME:
            reason, message, allowed = (
                ToolPolicyReason.TARGET_OUT_OF_SCOPE,
                "binary discovery requires an IP-pinned target in session scope",
                False,
            )
        elif request.timeout_seconds > descriptor.max_timeout_seconds:
            reason, message, allowed = (
                ToolPolicyReason.PROFILE_NOT_ALLOWED,
                "requested timeout exceeds the registered profile limit",
                False,
            )
        elif self.max_risk is ToolRisk.PASSIVE and descriptor.risk_class is ToolRisk.LOW:
            reason, message, allowed = (
                ToolPolicyReason.RISK_NOT_ALLOWED,
                "tool risk exceeds discovery policy",
                False,
            )
        elif descriptor.requires_binary and not descriptor.executable_path:
            reason, message, allowed = (
                ToolPolicyReason.BINARY_NOT_ALLOWED,
                "fixed binary path was not resolved by the registry",
                False,
            )
        elif (
            plan_request_count > max_plan_requests
            or same_tool_request_count > descriptor.max_runs_per_plan
            or max_concurrency < 1
        ):
            reason, message, allowed = (
                ToolPolicyReason.RATE_LIMIT_EXCEEDED,
                "discovery plan exceeds configured tool rate or concurrency bounds",
                False,
            )
        elif (
            estimated_request_cost < 0
            or (
                remaining_request_budget is not None
                and estimated_request_cost > remaining_request_budget
            )
        ):
            reason, message, allowed = (
                ToolPolicyReason.RESEARCH_BUDGET_EXCEEDED,
                "estimated request amplification exceeds remaining ResearchBudget",
                False,
            )
        elif (
            (remaining_tool_run_budget is not None and remaining_tool_run_budget < 1)
            or estimated_duration_seconds < 0
            or (
                remaining_duration_seconds is not None
                and estimated_duration_seconds > remaining_duration_seconds
            )
        ):
            reason, message, allowed = (
                ToolPolicyReason.RESEARCH_BUDGET_EXCEEDED,
                "ToolRun or duration estimate exceeds remaining ResearchBudget",
                False,
            )
        policy_payload = {
            "registry_version": self.registry.version,
            "max_risk": self.max_risk.value,
            "limits": {
                "plan_request_count": plan_request_count,
                "same_tool_request_count": same_tool_request_count,
                "max_plan_requests": max_plan_requests,
                "max_concurrency": max_concurrency,
                "tool_max_runs_per_plan": descriptor.max_runs_per_plan if descriptor else None,
                "estimated_request_cost": estimated_request_cost,
                "remaining_request_budget": remaining_request_budget,
                "remaining_tool_run_budget": remaining_tool_run_budget,
                "estimated_duration_seconds": estimated_duration_seconds,
                "remaining_duration_seconds": remaining_duration_seconds,
            },
            "session_scope": {
                "hosts": research_session.scope.hosts,
                "ports": research_session.scope.ports,
                "schemes": research_session.scope.schemes,
            },
            "request": request.model_dump(mode="json"),
        }
        policy_hash = hashlib.sha256(
            json.dumps(policy_payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        decision = ToolPolicyDecision(
            research_session_id=research_session.id,
            discovery_plan_id=discovery_plan_id,
            tool_run_id=tool_run_id,
            allowed=allowed,
            reason=reason,
            message=message,
            policy_hash=policy_hash,
            provenance=Provenance(
                source_type="tool_policy",
                source_reference=policy_hash,
                collector="aegis-tool-policy-v1",
                classification=FactClassification.OBSERVED,
            ),
        )
        policy_log.info(
            "tool policy decision session_id=%s plan_id=%s run_id=%s tool=%s "
            "profile=%s allowed=%s reason=%s",
            research_session.id,
            discovery_plan_id,
            tool_run_id,
            request.tool,
            request.profile,
            decision.allowed,
            decision.reason.value,
        )
        return decision
