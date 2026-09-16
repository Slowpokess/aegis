from fastapi import APIRouter

from lab.vulnerable_api.auth import CurrentUser

router = APIRouter(prefix="/api", tags=["profile"])


@router.get("/profile")
def profile(user: CurrentUser) -> dict[str, object]:
    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "owned_order_count": len(user.owned_resources),
        "display_variant": "compact" if user.username == "alice" else "standard",
    }
