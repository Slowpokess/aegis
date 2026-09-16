from pydantic import Field

from app.domain.common import DomainModel


class PolicyEvaluationResult(DomainModel):
    profile: str
    actions: int = Field(ge=0)
    tool_runs: int = Field(ge=0)
    repeated_actions: int = Field(ge=0)
    gaps_resolved: int = Field(ge=0)
    requests: int = Field(ge=0)
    findings: int = Field(ge=0)
    policy_bypasses: int = Field(default=0, ge=0)
    out_of_scope_executions: int = Field(default=0, ge=0)
    credential_exposures: int = Field(default=0, ge=0)
    controller_created_findings: int = Field(default=0, ge=0)


class PolicyComparison(DomainModel):
    conservative: PolicyEvaluationResult
    experimental: PolicyEvaluationResult

    @property
    def safety_invariants_hold(self) -> bool:
        values = (self.conservative, self.experimental)
        return all(
            item.policy_bypasses == 0
            and item.out_of_scope_executions == 0
            and item.credential_exposures == 0
            and item.controller_created_findings == 0
            for item in values
        )


def compare_policies(
    conservative: dict[str, object], experimental: dict[str, object]
) -> PolicyComparison:
    """Project actual session counters without assigning a winning policy."""

    def project(value: dict[str, object]) -> PolicyEvaluationResult:
        return PolicyEvaluationResult(
            profile=str(value["profile"]),
            actions=int(value["actions"]),
            tool_runs=int(value["tool_runs"]),
            repeated_actions=int(value["repeated_actions"]),
            gaps_resolved=int(value["gaps_resolved"]),
            requests=int(value["requests"]),
            findings=int(value["findings"]),
        )

    return PolicyComparison(conservative=project(conservative), experimental=project(experimental))
