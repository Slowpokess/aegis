from fastapi import APIRouter, HTTPException, status

from lab.vulnerable_api.auth import CurrentUser

router = APIRouter(prefix="/api/admin", tags=["admin"])


@router.get("/stats")
def admin_stats(user: CurrentUser) -> dict[str, int]:
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin role required")
    return {"synthetic_users": 3, "synthetic_orders": 4}
