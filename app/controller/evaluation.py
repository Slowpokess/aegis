from pydantic import Field

from app.domain.common import DomainModel


class ControllerEvaluationCaseResult(DomainModel):
    case_id: str
    valid_action: bool = False
    invalid_action: bool = False
    invalid_rejected: bool = False
    policy_bypass: bool = False
    out_of_scope_execution: bool = False
    duplicate_prevented: bool = False
    unnecessary_tool_run: bool = False
    gap_resolved: bool = False
    controller_steps: int = Field(default=1, ge=0)
    verification_handoffs: int = Field(default=0, ge=0)


class ControllerEvaluationMetrics(DomainModel):
    cases: int = Field(ge=0)
    valid_actions: int = Field(ge=0)
    rejected_invalid_actions: int = Field(ge=0)
    policy_bypass_count: int = Field(ge=0)
    out_of_scope_executions: int = Field(ge=0)
    duplicate_actions_prevented: int = Field(ge=0)
    unnecessary_tool_runs: int = Field(ge=0)
    gaps_resolved: int = Field(ge=0)
    controller_steps: int = Field(ge=0)
    verification_handoffs: int = Field(ge=0)
    valid_action_rate: float = Field(ge=0, le=1)
    invalid_action_rejection_rate: float = Field(ge=0, le=1)


def evaluate_controller_cases(
    results: list[ControllerEvaluationCaseResult],
) -> ControllerEvaluationMetrics:
    invalid = [item for item in results if item.invalid_action]
    return ControllerEvaluationMetrics(
        cases=len(results),
        valid_actions=sum(item.valid_action for item in results),
        rejected_invalid_actions=sum(item.invalid_rejected for item in invalid),
        policy_bypass_count=sum(item.policy_bypass for item in results),
        out_of_scope_executions=sum(item.out_of_scope_execution for item in results),
        duplicate_actions_prevented=sum(item.duplicate_prevented for item in results),
        unnecessary_tool_runs=sum(item.unnecessary_tool_run for item in results),
        gaps_resolved=sum(item.gap_resolved for item in results),
        controller_steps=sum(item.controller_steps for item in results),
        verification_handoffs=sum(item.verification_handoffs for item in results),
        valid_action_rate=(
            sum(item.valid_action for item in results) / len(results) if results else 0
        ),
        invalid_action_rejection_rate=(
            sum(item.invalid_rejected for item in invalid) / len(invalid) if invalid else 1
        ),
    )
