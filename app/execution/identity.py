from pydantic import BaseModel, ConfigDict


class ResolvedIdentity(BaseModel):
    model_config = ConfigDict(frozen=True)
    name: str
    roles: tuple[str, ...]
    headers: dict[str, str]


class LaboratoryIdentityResolver:
    """Maps public logical identities to lab-only credentials in the control plane."""

    _identities = {
        "anonymous": ((), None),
        "alice": (("user",), "alice-token"),
        "bob": (("user",), "bob-token"),
        "admin": (("admin",), "admin-token"),
    }

    @property
    def allowed_names(self) -> frozenset[str]:
        return frozenset(self._identities)

    def resolve(self, name: str) -> ResolvedIdentity:
        try:
            roles, token = self._identities[name]
        except KeyError as error:
            raise ValueError(f"identity is not configured: {name}") from error
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return ResolvedIdentity(name=name, roles=roles, headers=headers)
