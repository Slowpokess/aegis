from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app import __version__
from app.config import Settings, get_settings
from app.discovery.registry import ToolRegistry
from app.storage.database import Database
from app.operator.api import router as operator_router


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved_settings = settings or get_settings()
    database = Database(resolved_settings.database_url)

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        if resolved_settings.auto_create_schema:
            database.create_schema()
        application.state.database = database
        application.state.settings = resolved_settings
        application.state.tool_registry = ToolRegistry(
            enabled={
                "nmap": resolved_settings.nmap_enabled,
                "ffuf": resolved_settings.ffuf_enabled,
                "nuclei": resolved_settings.nuclei_enabled,
            }
        )
        yield
        database.dispose()

    application = FastAPI(
        title="Aegis",
        version=__version__,
        description="Evidence-driven local security research platform",
        lifespan=lifespan,
    )

    @application.get("/health", tags=["system"])
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    application.include_router(operator_router)
    dashboard = Path("web/dist")
    if dashboard.is_dir():
        application.mount(
            "/ui", StaticFiles(directory=dashboard, html=True), name="operator-dashboard"
        )

    return application


app = create_app()
