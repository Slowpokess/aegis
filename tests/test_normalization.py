from app.collectors.normalization import ObservationNormalizer
from app.execution.protocol import ExecutionResult


def test_normalizer_extracts_deterministic_metadata_without_interpretation() -> None:
    result = ExecutionResult(
        effective_url="http://127.0.0.1:8001/api/portal",
        status_code=302,
        headers={
            "content-type": "application/json; charset=utf-8",
            "location": "/login",
            "server": "uvicorn",
        },
        body='{"detail":"redirect"}',
        body_base64="eyJkZXRhaWwiOiJyZWRpcmVjdCJ9",
        body_bytes=21,
        truncated=False,
        elapsed_ms=2,
        evidence_sha256="a" * 64,
    )

    normalized = ObservationNormalizer().normalize(result)

    assert normalized == {
        "status_code": 302,
        "content_type": "application/json",
        "body_length": 21,
        "redirect_location": "/login",
        "server": "uvicorn",
        "is_json": True,
        "json_top_level_type": "object",
        "truncated": False,
        "response_hash": "a" * 64,
    }
