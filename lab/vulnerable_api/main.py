from fastapi import FastAPI

from lab.vulnerable_api.routes import account, admin, orders, portal, profile


def create_lab_app() -> FastAPI:
    application = FastAPI(
        title="Aegis Controlled Laboratory",
        version="1.0.0",
        description="Deterministic synthetic target for authorized local research.",
    )

    @application.get("/health", tags=["system"])
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "aegis-controlled-lab"}

    application.include_router(profile.router)
    application.include_router(orders.router)
    application.include_router(account.router)
    application.include_router(admin.router)
    application.include_router(portal.router)
    return application


app = create_lab_app()
