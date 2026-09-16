import httpx
import pytest


def auth(username: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {username}-token"}


@pytest.mark.asyncio
async def test_health_and_synthetic_authentication(lab_client: httpx.AsyncClient) -> None:
    health = await lab_client.get("/health")
    anonymous = await lab_client.get("/api/profile")
    invalid = await lab_client.get("/api/profile", headers={"Authorization": "Bearer invalid"})

    assert health.status_code == 200
    assert health.json() == {"status": "ok", "service": "aegis-controlled-lab"}
    assert anonymous.status_code == 401
    assert anonymous.headers["www-authenticate"] == "Bearer"
    assert invalid.status_code == 401


@pytest.mark.asyncio
async def test_lab_001_lists_only_owned_orders(lab_client: httpx.AsyncClient) -> None:
    alice = await lab_client.get("/api/orders", headers=auth("alice"))
    bob = await lab_client.get("/api/orders", headers=auth("bob"))

    assert alice.status_code == bob.status_code == 200
    assert {order["id"] for order in alice.json()["orders"]} == {101, 102}
    assert {order["owner"] for order in alice.json()["orders"]} == {"alice"}
    assert {order["id"] for order in bob.json()["orders"]} == {201, 202}
    assert {order["owner"] for order in bob.json()["orders"]} == {"bob"}


@pytest.mark.asyncio
async def test_lab_002_reproduces_authenticated_bola(lab_client: httpx.AsyncClient) -> None:
    owner_control = await lab_client.get("/api/orders/101", headers=auth("alice"))
    cross_identity = await lab_client.get("/api/orders/101", headers=auth("bob"))

    assert owner_control.status_code == 200
    assert cross_identity.status_code == 200
    assert owner_control.json() == cross_identity.json()
    assert cross_identity.json()["owner"] == "alice"


@pytest.mark.asyncio
async def test_lab_003_profile_difference_is_identity_scoped(lab_client: httpx.AsyncClient) -> None:
    alice = await lab_client.get("/api/profile", headers=auth("alice"))
    bob = await lab_client.get("/api/profile", headers=auth("bob"))

    assert alice.status_code == bob.status_code == 200
    assert alice.content != bob.content
    assert alice.json()["username"] == "alice"
    assert bob.json()["username"] == "bob"
    assert "synthetic_email" not in alice.json()
    assert "synthetic_email" not in bob.json()


@pytest.mark.asyncio
async def test_lab_004_discloses_only_controlled_synthetic_fields(
    lab_client: httpx.AsyncClient,
) -> None:
    settings = await lab_client.get("/api/account/settings", headers=auth("alice"))
    profile = await lab_client.get("/api/profile", headers=auth("alice"))

    assert settings.status_code == 200
    assert settings.json()["internal_account_id"] == "acct-lab-0001"
    assert settings.json()["synthetic_email"] == "alice@example.invalid"
    assert "internal_account_id" not in profile.json()
    assert "synthetic_email" not in profile.json()


@pytest.mark.asyncio
async def test_lab_005_receipt_control_rejects_false_positive(
    lab_client: httpx.AsyncClient,
) -> None:
    alice_cross = await lab_client.get("/api/orders/201/receipt", headers=auth("alice"))
    bob_cross = await lab_client.get("/api/orders/101/receipt", headers=auth("bob"))
    alice_control = await lab_client.get("/api/orders/101/receipt", headers=auth("alice"))
    bob_control = await lab_client.get("/api/orders/201/receipt", headers=auth("bob"))

    assert alice_cross.status_code == bob_cross.status_code == 403
    assert alice_cross.json()["detail"]["message"] == "receipt unavailable"
    assert "item" not in alice_cross.json()["detail"]
    assert "amount" not in bob_cross.json()["detail"]
    assert alice_control.status_code == bob_control.status_code == 200
    assert alice_control.json()["order_id"] == 101
    assert bob_control.json()["order_id"] == 201


@pytest.mark.asyncio
async def test_lab_006_single_denial_is_insufficient_evidence(
    lab_client: httpx.AsyncClient,
) -> None:
    limited_observation = await lab_client.get(
        "/api/account/settings/restricted", headers=auth("alice")
    )
    omitted_privileged_baseline = await lab_client.get(
        "/api/account/settings/restricted", headers=auth("admin")
    )

    assert limited_observation.status_code == 403
    assert limited_observation.json() == {"detail": "access unavailable"}
    assert omitted_privileged_baseline.status_code == 200
    assert omitted_privileged_baseline.json()["feature"] == "advanced-settings"


@pytest.mark.asyncio
async def test_lab_007_enforces_role_boundary(lab_client: httpx.AsyncClient) -> None:
    authenticated_user = await lab_client.get("/api/admin/stats", headers=auth("alice"))
    authenticated_admin = await lab_client.get("/api/admin/stats", headers=auth("admin"))

    assert authenticated_user.status_code == 403
    assert authenticated_admin.status_code == 200
    assert authenticated_admin.json() == {"synthetic_users": 3, "synthetic_orders": 4}


@pytest.mark.asyncio
async def test_lab_008_distinguishes_redirect_authentication_and_authorization(
    lab_client: httpx.AsyncClient,
) -> None:
    anonymous = await lab_client.get("/api/portal")
    authenticated_user = await lab_client.get("/api/portal", headers=auth("alice"))
    authenticated_admin = await lab_client.get("/api/portal", headers=auth("admin"))

    assert anonymous.status_code == 302
    assert anonymous.headers["location"] == "/login"
    assert authenticated_user.status_code == 403
    assert authenticated_admin.status_code == 200


@pytest.mark.asyncio
async def test_ground_truth_is_not_exposed_by_target_api(lab_client: httpx.AsyncClient) -> None:
    openapi = (await lab_client.get("/openapi.json")).json()
    paths = set(openapi["paths"])

    assert all("ground" not in path and "scenario" not in path for path in paths)
    assert not any("LAB-" in str(operation) for operation in openapi["paths"].values())
    for candidate in ("/ground-truth", "/api/ground-truth", "/scenarios", "/api/scenarios"):
        assert (await lab_client.get(candidate)).status_code == 404
