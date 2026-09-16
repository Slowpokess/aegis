import base64
import json

import pytest

from app.domain.common import Provenance
from app.domain.evidence import Evidence, HTTPRequestRecord, HTTPResponseRecord
from app.domain.verification import ComparisonOperator, ComparisonSpec, ComparisonType
from app.execution.protocol import canonical_evidence_sha256
from app.verification.comparisons import EvidenceComparator


def evidence(
    body: object,
    *,
    status: int = 200,
    headers: dict[str, str] | None = None,
    truncated: bool = False,
) -> Evidence:
    raw = body if isinstance(body, str) else json.dumps(body, sort_keys=True)
    body_bytes = raw.encode()
    request_headers: dict[str, str] = {}
    response_headers = headers or {"content-type": "application/json"}
    return Evidence(
        request_id="REQ-COMPARISON",
        request=HTTPRequestRecord(method="GET", url="http://127.0.0.1/item", headers={}),
        response=HTTPResponseRecord(
            status_code=status,
            headers=response_headers,
            body=raw,
            body_base64=base64.b64encode(body_bytes).decode(),
            body_bytes=len(body_bytes),
            elapsed_ms=1,
            truncated=truncated,
        ),
        integrity_hash=canonical_evidence_sha256(
            method="GET",
            url="http://127.0.0.1/item",
            request_headers=request_headers,
            status_code=status,
            response_headers=response_headers,
            body=body_bytes,
        ),
        provenance=Provenance(source_type="test", source_reference="comparison"),
    )


@pytest.mark.parametrize(
    ("comparison", "field", "candidate", "control", "operator", "matched"),
    [
        (ComparisonType.STATUS_CODE, None, evidence({"x": 1}), evidence({"x": 2}), ComparisonOperator.EQUAL, True),
        (ComparisonType.STATUS_CODE, None, evidence({}, status=403), evidence({}, status=200), ComparisonOperator.NOT_EQUAL, True),
        (ComparisonType.HEADER_PRESENCE, "x-test", evidence({}, headers={"x-test": "1"}), evidence({}, headers={"X-Test": "2"}), ComparisonOperator.PRESENT, True),
        (ComparisonType.HEADER_VALUE, "x-test", evidence({}, headers={"x-test": "1"}), evidence({}, headers={"X-Test": "1"}), ComparisonOperator.EQUAL, True),
        (ComparisonType.REDIRECT, None, evidence({}, status=302, headers={"location": "/login"}), evidence({}, status=302, headers={"Location": "/login"}), ComparisonOperator.EQUAL, True),
        (ComparisonType.CONTENT_TYPE, None, evidence({}, headers={"Content-Type": "application/json; charset=utf-8"}), evidence({}, headers={"content-type": "application/json"}), ComparisonOperator.EQUAL, True),
        (ComparisonType.BODY_LENGTH, None, evidence("long"), evidence("x"), ComparisonOperator.GREATER_THAN, True),
        (ComparisonType.BODY_HASH, None, evidence("same"), evidence("same"), ComparisonOperator.EQUAL, True),
        (ComparisonType.JSON_VALIDITY, None, evidence({"x": 1}), evidence({"x": 2}), ComparisonOperator.EQUAL, True),
        (ComparisonType.JSON_FIELD_PRESENCE, "owner", evidence({"owner": "alice"}), evidence({"owner": "bob"}), ComparisonOperator.PRESENT, True),
        (ComparisonType.JSON_FIELD_VALUE, "owner", evidence({"owner": "alice"}), evidence({"owner": "alice"}), ComparisonOperator.EQUAL, True),
        (ComparisonType.NORMALIZED_JSON, None, evidence({"b": 2, "a": 1}), evidence({"a": 1, "b": 2}), ComparisonOperator.EQUAL, True),
    ],
)
def test_comparison_primitives(comparison, field, candidate, control, operator, matched):
    result = EvidenceComparator().compare(
        ComparisonSpec(type=comparison, field=field, operator=operator), candidate, control
    )
    assert result.complete
    assert result.matched is matched
    assert result.candidate is not None


def test_missing_json_field_invalid_json_and_truncation_are_incomplete() -> None:
    comparator = EvidenceComparator()
    field = ComparisonSpec(
        type=ComparisonType.JSON_FIELD_VALUE,
        field="owner",
        operator=ComparisonOperator.EQUAL,
    )
    assert not comparator.compare(field, evidence({}), evidence({"owner": "alice"})).complete
    assert not comparator.compare(field, evidence("not-json"), evidence({})).complete
    assert not comparator.compare(field, evidence({"owner": "alice"}, truncated=True), evidence({"owner": "alice"})).complete


def test_closed_spec_rejects_invalid_operator_and_missing_field() -> None:
    with pytest.raises(ValueError):
        ComparisonSpec(type=ComparisonType.JSON_FIELD_VALUE, operator=ComparisonOperator.EQUAL)
    with pytest.raises(ValueError):
        ComparisonSpec(type=ComparisonType.BODY_HASH, operator=ComparisonOperator.PRESENT)
