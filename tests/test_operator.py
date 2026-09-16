import json
from pathlib import Path

from app.domain.operator import (
    EvidenceNovelty,
    ResearchPolicyProfile,
    canonical_hash,
)
from app.operator.evaluation import PolicyComparison, PolicyEvaluationResult
from app.operator.policy import policy_settings
from app.operator.reporting import redact


def test_builtin_research_policies_are_bounded_and_distinct() -> None:
    conservative = policy_settings(ResearchPolicyProfile.CONSERVATIVE)
    balanced = policy_settings(ResearchPolicyProfile.BALANCED)
    experimental = policy_settings(ResearchPolicyProfile.EXPERIMENTAL)
    assert conservative.allow_off_gap_exploration is False
    assert conservative.allow_action_repetition is False
    assert balanced.max_exploratory_actions == 2
    assert experimental.allow_closed_gap_revisit is True
    assert experimental.max_repeated_semantic_action_count == 3


def test_novelty_vocabulary_and_semantic_hash_are_deterministic() -> None:
    assert [item.value for item in EvidenceNovelty] == ["NONE", "LOW", "MEDIUM", "HIGH"]
    value = {"profile": "CONSERVATIVE", "actions": ["HTTP_OBSERVE"]}
    assert canonical_hash(value) == canonical_hash(dict(value))


def test_report_redaction_is_recursive() -> None:
    value = {
        "Authorization": "Bearer synthetic-secret",
        "nested": {"Cookie": "session=secret", "safe": "value"},
        "provider": "nvapi-secret",
    }
    result = redact(value)
    encoded = json.dumps(result)
    assert "synthetic-secret" not in encoded
    assert "session=secret" not in encoded
    assert "nvapi-secret" not in encoded
    assert result["nested"]["safe"] == "value"


def test_policy_comparison_reports_safety_without_claiming_a_winner() -> None:
    comparison = PolicyComparison(
        conservative=PolicyEvaluationResult(
            profile="CONSERVATIVE",
            actions=1,
            tool_runs=1,
            repeated_actions=0,
            gaps_resolved=1,
            requests=1,
            findings=0,
        ),
        experimental=PolicyEvaluationResult(
            profile="EXPERIMENTAL",
            actions=2,
            tool_runs=2,
            repeated_actions=1,
            gaps_resolved=1,
            requests=2,
            findings=0,
        ),
    )
    assert comparison.safety_invariants_hold is True


def test_phase13_policy_fixture_is_closed_and_safety_focused() -> None:
    payload = json.loads(Path("evals/phase13_policy_cases.json").read_text(encoding="utf-8"))
    assert payload["evaluation_version"] == "research-policy-v1"
    assert len(payload["cases"]) == 8
    assert all("shell" not in case for case in payload["cases"])
