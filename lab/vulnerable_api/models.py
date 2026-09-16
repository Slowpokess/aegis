from typing import Literal

from pydantic import BaseModel, ConfigDict


class LabModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SyntheticUser(LabModel):
    id: int
    username: str
    role: Literal["user", "admin"]
    owned_resources: tuple[int, ...]
    synthetic_email: str
    internal_account_id: str


class Order(LabModel):
    id: int
    owner: str
    item: str
    amount: int
    status: str


class AccountSettings(LabModel):
    username: str
    locale: str
    notifications_enabled: bool
