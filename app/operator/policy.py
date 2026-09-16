from collections import Counter

from app.domain.controller import ResearchAction, ResearchActionType
from app.domain.operator import (
    EvidenceNovelty,
    ResearchPolicy,
    ResearchPolicyProfile,
    ResearchPolicySettings,
    RepeatReason,
    novelty_weight,
)
from app.domain.research_strategy import StrategyCandidate


def policy_settings(profile: ResearchPolicyProfile) -> ResearchPolicySettings:
    if profile is ResearchPolicyProfile.CONSERVATIVE:
        return ResearchPolicySettings(
            max_exploratory_actions=0,
            allow_closed_gap_revisit=False,
            allow_action_repetition=False,
            allow_off_gap_exploration=False,
            prefer_reproduction=False,
            stop_on_no_open_gaps=True,
            min_information_gain=40,
            max_repeated_semantic_action_count=1,
        )
    if profile is ResearchPolicyProfile.BALANCED:
        return ResearchPolicySettings(
            max_exploratory_actions=2,
            allow_closed_gap_revisit=False,
            allow_action_repetition=True,
            allow_off_gap_exploration=True,
            prefer_reproduction=True,
            stop_on_no_open_gaps=True,
            min_information_gain=20,
            max_repeated_semantic_action_count=2,
        )
    return ResearchPolicySettings(
        max_exploratory_actions=5,
        allow_closed_gap_revisit=True,
        allow_action_repetition=True,
        allow_off_gap_exploration=True,
        prefer_reproduction=True,
        stop_on_no_open_gaps=False,
        min_information_gain=0,
        max_repeated_semantic_action_count=3,
    )


class AdaptiveResearchPolicy:
    """Adjusts research priority; it is not an execution authorization policy."""

    def novelty(self, action: ResearchAction, history: list[ResearchAction]) -> EvidenceNovelty:
        exact = [item for item in history if item.semantic_hash == action.semantic_hash]
        if exact:
            return EvidenceNovelty.NONE
        if action.action_type is ResearchActionType.SERVICE_DISCOVERY:
            prior = any(
                item.action_type is ResearchActionType.SERVICE_DISCOVERY for item in history
            )
            return EvidenceNovelty.LOW if prior else EvidenceNovelty.HIGH
        if action.action_type is ResearchActionType.HTTP_OBSERVE:
            same_endpoint = [
                item
                for item in history
                if item.action_type is ResearchActionType.HTTP_OBSERVE
                and getattr(item.proposal, "endpoint_entity_id", None)
                == getattr(action.proposal, "endpoint_entity_id", None)
            ]
            if not same_endpoint:
                return EvidenceNovelty.HIGH
            different_identity = any(
                item.proposal.identity_entity_id != action.proposal.identity_entity_id
                for item in same_endpoint
            )
            return EvidenceNovelty.MEDIUM if different_identity else EvidenceNovelty.LOW
        return EvidenceNovelty.MEDIUM

    def effective_priority(
        self,
        candidate: StrategyCandidate,
        policy: ResearchPolicy,
        *,
        novelty: EvidenceNovelty,
        remaining_budget_ratio: float,
        previous_failures: int = 0,
    ) -> int:
        profile_adjustment = {
            ResearchPolicyProfile.CONSERVATIVE: -10,
            ResearchPolicyProfile.BALANCED: 0,
            ResearchPolicyProfile.EXPERIMENTAL: 10,
        }[policy.profile]
        score = (
            candidate.priority_score
            + novelty_weight(novelty)
            + profile_adjustment
            + round(max(0.0, min(1.0, remaining_budget_ratio)) * 10)
            - min(previous_failures * 15, 45)
        )
        return max(0, min(100, score))

    @staticmethod
    def repeat_count(action: ResearchAction, history: list[ResearchAction]) -> int:
        return Counter(item.semantic_hash for item in history)[action.semantic_hash]

    @staticmethod
    def validate_repeat_reason(reason: RepeatReason | None) -> bool:
        return reason is not None
