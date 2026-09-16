from pathlib import Path

import pytest
from pydantic import ValidationError

from lab.ground_truth import ExpectedVerdict, load_ground_truth


def test_all_ground_truth_files_are_valid_and_unique() -> None:
    scenarios = load_ground_truth()

    assert len(scenarios) == 8
    assert [scenario.id for scenario in scenarios] == [
        f"LAB-{number:03d}" for number in range(1, 9)
    ]
    assert {scenario.expected_verdict for scenario in scenarios} == {
        ExpectedVerdict.SUPPORTED,
        ExpectedVerdict.REJECTED,
        ExpectedVerdict.INCONCLUSIVE,
    }
    assert all(scenario.required_evidence for scenario in scenarios)


def test_duplicate_scenario_ids_are_rejected(tmp_path: Path) -> None:
    definition = """\
id: LAB-001
title: Duplicate
vulnerability: false
class: safe
actors: [alice]
preconditions: [alice_authenticated]
required_evidence: [alice_gets_response]
required_control: []
expected_verdict: REJECTED
"""
    (tmp_path / "LAB-001.yaml").write_text(definition, encoding="utf-8")
    (tmp_path / "LAB-002.yaml").write_text(definition, encoding="utf-8")

    with pytest.raises(ValueError, match="scenario IDs must be unique"):
        load_ground_truth(tmp_path)


def test_inconsistent_verdict_is_rejected(tmp_path: Path) -> None:
    definition = """\
id: LAB-001
title: Invalid verdict
vulnerability: true
class: broken_object_authorization
actors: [alice, bob]
preconditions: [bob_authenticated]
required_evidence: [bob_reads_alice_order]
required_control: [alice_reads_alice_order]
expected_verdict: REJECTED
"""
    (tmp_path / "LAB-001.yaml").write_text(definition, encoding="utf-8")

    with pytest.raises(ValidationError, match="inconsistent"):
        load_ground_truth(tmp_path)
