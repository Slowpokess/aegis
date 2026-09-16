import base64
import hashlib
import json
from typing import Any

from app.domain.evidence import Evidence
from app.domain.verification import (
    ComparisonOperator,
    ComparisonResult,
    ComparisonSpec,
    ComparisonType,
)

BODY_DEPENDENT = frozenset(
    {
        ComparisonType.BODY_LENGTH,
        ComparisonType.BODY_HASH,
        ComparisonType.JSON_VALIDITY,
        ComparisonType.JSON_FIELD_PRESENCE,
        ComparisonType.JSON_FIELD_VALUE,
        ComparisonType.NORMALIZED_JSON,
    }
)
_MISSING = object()


def captured_body(evidence: Evidence) -> bytes:
    if evidence.response.body_base64 is not None:
        return base64.b64decode(evidence.response.body_base64, validate=True)
    return evidence.response.body.encode()


class EvidenceComparator:
    def compare(
        self, spec: ComparisonSpec, candidate: Evidence, control: Evidence
    ) -> ComparisonResult:
        if spec.type in BODY_DEPENDENT and (
            candidate.response.truncated or control.response.truncated
        ):
            return self._result(
                spec,
                None,
                None,
                complete=False,
                matched=None,
                reason="body-dependent comparison cannot use truncated evidence",
            )
        try:
            candidate_value, control_value, complete = self._values(spec, candidate, control)
        except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError):
            return self._result(
                spec,
                None,
                None,
                complete=False,
                matched=None,
                reason="comparison input could not be decoded",
            )
        if not complete:
            return self._result(
                spec,
                None if candidate_value is _MISSING else candidate_value,
                None if control_value is _MISSING else control_value,
                complete=False,
                matched=None,
                reason="required comparison value is unavailable",
            )
        matched = self._apply_operator(spec.operator, candidate_value, control_value)
        return self._result(
            spec,
            candidate_value,
            control_value,
            complete=True,
            matched=matched,
            reason="declared relation matched" if matched else "declared relation did not match",
        )

    def _values(
        self, spec: ComparisonSpec, candidate: Evidence, control: Evidence
    ) -> tuple[Any, Any, bool]:
        comparison = spec.type
        if comparison is ComparisonType.STATUS_CODE:
            return candidate.response.status_code, control.response.status_code, True
        if comparison is ComparisonType.HEADER_PRESENCE:
            return self._header(spec, candidate) is not _MISSING, self._header(spec, control) is not _MISSING, True
        if comparison is ComparisonType.HEADER_VALUE:
            left, right = self._header(spec, candidate), self._header(spec, control)
            return left, right, left is not _MISSING and right is not _MISSING
        if comparison is ComparisonType.REDIRECT:
            return self._header_name(candidate, "location"), self._header_name(control, "location"), True
        if comparison is ComparisonType.CONTENT_TYPE:
            return self._content_type(candidate), self._content_type(control), True
        if comparison is ComparisonType.BODY_LENGTH:
            return len(captured_body(candidate)), len(captured_body(control)), True
        if comparison is ComparisonType.BODY_HASH:
            return (
                hashlib.sha256(captured_body(candidate)).hexdigest(),
                hashlib.sha256(captured_body(control)).hexdigest(),
                True,
            )
        if comparison is ComparisonType.JSON_VALIDITY:
            return self._json_valid(candidate), self._json_valid(control), True
        if comparison in {
            ComparisonType.JSON_FIELD_PRESENCE,
            ComparisonType.JSON_FIELD_VALUE,
        }:
            left = self._json_field(candidate, spec.field or "")
            right = self._json_field(control, spec.field or "")
            if comparison is ComparisonType.JSON_FIELD_PRESENCE:
                return left is not _MISSING, right is not _MISSING, True
            return left, right, left is not _MISSING and right is not _MISSING
        if comparison is ComparisonType.NORMALIZED_JSON:
            return self._json(candidate), self._json(control), True
        raise ValueError("unsupported comparison type")

    @staticmethod
    def _apply_operator(operator: ComparisonOperator, candidate: Any, control: Any) -> bool:
        if operator is ComparisonOperator.EQUAL:
            return candidate == control
        if operator is ComparisonOperator.NOT_EQUAL:
            return candidate != control
        if operator is ComparisonOperator.PRESENT:
            return candidate is True and control is True
        if operator is ComparisonOperator.ABSENT:
            return candidate is False and control is False
        if operator is ComparisonOperator.GREATER_THAN:
            return bool(candidate > control)
        if operator is ComparisonOperator.LESS_THAN:
            return bool(candidate < control)
        raise ValueError("unsupported comparison operator")

    @staticmethod
    def _header_name(evidence: Evidence, name: str) -> str | object:
        for key, value in evidence.response.headers.items():
            if key.lower() == name.lower():
                return value
        return _MISSING

    def _header(self, spec: ComparisonSpec, evidence: Evidence) -> str | object:
        return self._header_name(evidence, spec.field or "")

    def _content_type(self, evidence: Evidence) -> str | None:
        value = self._header_name(evidence, "content-type")
        return None if value is _MISSING else str(value).split(";", 1)[0].strip().lower()

    @staticmethod
    def _json(evidence: Evidence) -> Any:
        return json.loads(captured_body(evidence))

    def _json_valid(self, evidence: Evidence) -> bool:
        try:
            self._json(evidence)
        except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError):
            return False
        return True

    def _json_field(self, evidence: Evidence, field: str) -> Any:
        value = self._json(evidence)
        for segment in field.split("."):
            if isinstance(value, dict) and segment in value:
                value = value[segment]
            elif isinstance(value, list) and segment.isdigit() and int(segment) < len(value):
                value = value[int(segment)]
            else:
                return _MISSING
        return value

    @staticmethod
    def _result(
        spec: ComparisonSpec,
        candidate: Any,
        control: Any,
        *,
        complete: bool,
        matched: bool | None,
        reason: str,
    ) -> ComparisonResult:
        return ComparisonResult(
            comparator=spec.type,
            operator=spec.operator,
            field=spec.field,
            candidate=candidate,
            control=control,
            complete=complete,
            matched=matched,
            required=spec.required,
            impact=spec.impact,
            reason=reason,
        )
