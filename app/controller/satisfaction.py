import json

from app.domain.controller import (
    ExpectedEvidenceType,
    ResearchAction,
    ResearchActionResult,
)
from app.domain.research_strategy import GapStatus
from app.storage.repositories import RepositorySet


class ResearchActionSatisfactionEvaluator:
    """Determines evidence acquisition success from persisted evidence, never LLM claims."""

    def evaluate(
        self,
        repositories: RepositorySet,
        action: ResearchAction,
        result: ResearchActionResult,
    ) -> bool:
        if result.status.value not in {"COMPLETED", "SATISFIED"}:
            return False
        gaps = [repositories.evidence_gaps.get(item) for item in action.proposal.supporting_gap_ids]
        if gaps and not all(gap and gap.status is GapStatus.RESOLVED for gap in gaps):
            return False
        if action.action_type.value == "ASSESS_WEB_TEMPLATES":
            runs = [repositories.tool_runs.get(item) for item in result.tool_run_ids]
            return bool(runs) and all(run and run.status.value == "COMPLETED" for run in runs)
        if action.action_type.value != "HTTP_OBSERVE":
            return bool(result.observation_ids)
        evidence = [repositories.evidence.get(item) for item in result.evidence_ids]
        if not evidence or any(item is None for item in evidence):
            return False
        response = evidence[-1].response  # type: ignore[union-attr]
        body: object | None = None
        for expected in action.proposal.expected_information:
            kind = expected.information
            if kind is ExpectedEvidenceType.STATUS_CODE:
                continue
            if kind is ExpectedEvidenceType.CONTENT_TYPE:
                if not any(name.lower() == "content-type" for name in response.headers):
                    return False
            elif kind is ExpectedEvidenceType.REDIRECT_LOCATION:
                if not any(name.lower() == "location" for name in response.headers):
                    return False
            elif kind is ExpectedEvidenceType.BODY_HASH:
                if not evidence[-1].integrity_hash:  # type: ignore[union-attr]
                    return False
            elif kind in {
                ExpectedEvidenceType.JSON_VALIDITY,
                ExpectedEvidenceType.JSON_FIELD,
                ExpectedEvidenceType.RESOURCE_ID,
                ExpectedEvidenceType.RESOURCE_OWNER,
            }:
                if body is None:
                    try:
                        body = json.loads(response.body)
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        return False
                if kind is ExpectedEvidenceType.JSON_FIELD:
                    value = body
                    assert expected.field_selector is not None
                    for segment in expected.field_selector.segments:
                        if not isinstance(value, dict) or segment not in value:
                            return False
                        value = value[segment]
                elif kind is ExpectedEvidenceType.RESOURCE_ID:
                    if not isinstance(body, dict) or "id" not in body:
                        return False
                elif kind is ExpectedEvidenceType.RESOURCE_OWNER:
                    if not isinstance(body, dict) or "owner" not in body:
                        return False
        return True
