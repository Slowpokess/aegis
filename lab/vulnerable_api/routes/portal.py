from fastapi import APIRouter, HTTPException, status
from fastapi.responses import RedirectResponse

from lab.vulnerable_api.auth import OptionalUser

router = APIRouter(tags=["portal"])


@router.get("/login")
def login() -> dict[str, str]:
    return {"message": "synthetic login endpoint"}


@router.get("/api/portal", response_model=None)
def portal(user: OptionalUser) -> dict[str, str] | RedirectResponse:
    if user is None:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="portal access denied")
    return {"message": "synthetic admin portal"}
