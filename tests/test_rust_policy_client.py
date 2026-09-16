from pathlib import Path

import pytest

from app.execution.policy_protocol import PolicyAction, PolicyConfig, PolicyReasonCode, PolicyRequest
from app.execution.rust_policy import PolicyClientError, RustPolicyClient


def policy() -> PolicyConfig:
    return PolicyConfig(
        allowed_hosts=["127.0.0.1"],
        allowed_ports=[8001],
        allowed_schemes=["http"],
        allowed_methods=["GET", "HEAD", "OPTIONS"],
    )


def request(url: str = "http://127.0.0.1:8001/health") -> PolicyRequest:
    return PolicyRequest(
        decision_id="DEC-TEST",
        policy=policy(),
        action=PolicyAction(
            method="GET",
            url=url,
            timeout_ms=5000,
            max_response_bytes=100_000,
            follow_redirects=False,
        ),
    )


@pytest.mark.asyncio
async def test_real_rust_policy_and_python_hash_agree() -> None:
    response = await RustPolicyClient(
        Path("native/rust/target/debug/aegis-policy")
    ).evaluate(request())
    assert response.allowed
    assert response.reason_code is PolicyReasonCode.WITHIN_SCOPE
    assert response.policy_sha256 == policy().canonical_sha256()


@pytest.mark.asyncio
async def test_real_rust_policy_rejects_ambiguous_and_external_urls() -> None:
    client = RustPolicyClient(Path("native/rust/target/debug/aegis-policy"))
    external = await client.evaluate(request("http://127.0.0.1.attacker.invalid:8001/"))
    ambiguous = await client.evaluate(request("http://attacker.invalid@127.0.0.1:8001/"))
    assert external.reason_code is PolicyReasonCode.HOST_NOT_ALLOWED
    assert ambiguous.reason_code is PolicyReasonCode.INVALID_URL


@pytest.mark.asyncio
async def test_policy_missing_is_fail_closed() -> None:
    with pytest.raises(PolicyClientError, match="not found"):
        await RustPolicyClient(Path("/nonexistent/aegis-policy")).evaluate(request())
