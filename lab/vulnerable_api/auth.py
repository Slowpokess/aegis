from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from lab.vulnerable_api.data import TOKENS, USERS
from lab.vulnerable_api.models import SyntheticUser

bearer = HTTPBearer(auto_error=False)
Credentials = Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]


def get_optional_user(credentials: Credentials) -> SyntheticUser | None:
    if credentials is None:
        return None
    username = TOKENS.get(credentials.credentials)
    if credentials.scheme.lower() != "bearer" or username is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token")
    return USERS[username]


def get_current_user(
    user: Annotated[SyntheticUser | None, Depends(get_optional_user)]
) -> SyntheticUser:
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


CurrentUser = Annotated[SyntheticUser, Depends(get_current_user)]
OptionalUser = Annotated[SyntheticUser | None, Depends(get_optional_user)]
