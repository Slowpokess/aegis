from fastapi import APIRouter, HTTPException, status

from lab.vulnerable_api.auth import CurrentUser
from lab.vulnerable_api.data import SETTINGS

router = APIRouter(prefix="/api/account", tags=["account"])


@router.get("/settings")
def account_settings(user: CurrentUser) -> dict[str, object]:
    settings = SETTINGS[user.username].model_dump()
    # Synthetic internal identifiers are deliberately included for LAB-004.
    settings["internal_account_id"] = user.internal_account_id
    settings["synthetic_email"] = user.synthetic_email
    return settings


@router.get("/settings/restricted")
def restricted_settings(user: CurrentUser) -> dict[str, object]:
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="access unavailable")
    return {"feature": "advanced-settings", "enabled": False}
