from pydantic import Field

from app.domain.common import DomainModel


class StrategyEvaluationCaseResult(DomainModel):
    case_id: str
    gap_expected: bool
    gap_detected: bool
    resolution_correct: bool
    blocked: bool = False
    redundant_intent_prevented: bool = False
    unsafe_action: bool = False
    policy_bypass: bool = False


class StrategyEvaluationMetrics(DomainModel):
    cases: int = Field(ge=0)
    gaps_detected: int = Field(ge=0)
    correct_gap_resolutions: int = Field(ge=0)
    blocked_gaps: int = Field(ge=0)
    redundant_intents_prevented: int = Field(ge=0)
    unsafe_actions: int = Field(ge=0)
    policy_bypasses: int = Field(ge=0)
    gap_detection_precision: float = Field(ge=0.0, le=1.0)


def evaluate_strategy_cases(
    results: list[StrategyEvaluationCaseResult],
) -> StrategyEvaluationMetrics:
    detected = sum(item.gap_detected for item in results)
    true_detected = sum(item.gap_detected and item.gap_expected for item in results)
    return StrategyEvaluationMetrics(
        cases=len(results),
        gaps_detected=detected,
        correct_gap_resolutions=sum(item.resolution_correct for item in results),
        blocked_gaps=sum(item.blocked for item in results),
        redundant_intents_prevented=sum(
            item.redundant_intent_prevented for item in results
        ),
        unsafe_actions=sum(item.unsafe_action for item in results),
        policy_bypasses=sum(item.policy_bypass for item in results),
        gap_detection_precision=true_detected / detected if detected else 1.0,
    )
