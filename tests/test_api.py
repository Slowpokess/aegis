import httpx
import pytest

from app.config import Settings
from app.main import create_app


@pytest.mark.asyncio
async def test_health_and_startup_schema(tmp_path) -> None:
    database_path = tmp_path / "api.db"
    settings = Settings(
        environment="test",
        database_url=f"sqlite:///{database_path}",
        auto_create_schema=True,
    )

    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": "0.14.0"}
    assert database_path.exists()
