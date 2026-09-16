import httpx
import pytest

from app.config import Settings
from app.main import create_app
from tests.test_tool_integration_sdk import demo_integration


@pytest.mark.asyncio
async def test_dashboard_tool_api_autodiscovers_fixture(tmp_path) -> None:
    app = create_app(
        Settings(
            database_url=f"sqlite:///{tmp_path / 'dashboard.db'}",
            auto_create_schema=True,
        )
    )
    async with app.router.lifespan_context(app):
        app.state.tool_registry.register(demo_integration())
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/tools")
            detail = await client.get("/tools/demo_tool")
            runtime = await client.get("/runtime")
            openapi = await client.get("/openapi.json")
    assert response.status_code == 200
    assert any(item["tool_id"] == "demo_tool" for item in response.json())
    assert detail.json()["enabled"] is False
    assert runtime.json()["tool_integration_version"] == "tool-integration-v1"
    serialized = openapi.text.lower()
    assert "nvidia_api_key" not in serialized
    assert "authorization" not in serialized
