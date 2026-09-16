import base64

from app.execution.protocol import canonical_evidence_sha256, redact_headers


def test_sensitive_headers_are_redacted_case_insensitively() -> None:
    redacted = redact_headers(
        {
            "Authorization": "Bearer secret",
            "cookie": "session=secret",
            "Set-Cookie": "session=secret",
            "Proxy-Authorization": "Basic secret",
            "Accept": "application/json",
        }
    )

    assert redacted["Authorization"] == "<redacted>"
    assert redacted["cookie"] == "<redacted>"
    assert redacted["Set-Cookie"] == "<redacted>"
    assert redacted["Proxy-Authorization"] == "<redacted>"
    assert redacted["Accept"] == "application/json"


def test_python_canonical_hash_is_deterministic() -> None:
    parameters = {
        "method": "GET",
        "url": "http://127.0.0.1/test",
        "request_headers": {"Accept": "application/json"},
        "status_code": 200,
        "response_headers": {"content-type": "application/json"},
        "body": base64.b64decode("e30="),
    }
    first = canonical_evidence_sha256(**parameters)
    repeated = canonical_evidence_sha256(**parameters)

    assert first == repeated
    assert len(first) == 64
