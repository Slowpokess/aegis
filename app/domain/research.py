from datetime import datetime
from enum import StrEnum
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator

from app.domain.common import EntityModel, Identifier, utc_now


class ResearchSessionStatus(StrEnum):
    CREATED = "CREATED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class TargetScope(EntityModel):
    hosts: tuple[str, ...] = Field(min_length=1)
    ports: tuple[int, ...] = Field(min_length=1)
    schemes: tuple[str, ...] = Field(min_length=1)

    @field_validator("hosts")
    @classmethod
    def normalize_hosts(cls, hosts: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(host.strip().lower() for host in hosts)
        if any(not host or "/" in host or "@" in host for host in normalized):
            raise ValueError("scope hosts must be plain hostnames or IP addresses")
        return tuple(dict.fromkeys(normalized))

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, ports: tuple[int, ...]) -> tuple[int, ...]:
        if any(port < 1 or port > 65535 for port in ports):
            raise ValueError("scope ports must be between 1 and 65535")
        return tuple(dict.fromkeys(ports))

    @field_validator("schemes")
    @classmethod
    def validate_schemes(cls, schemes: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(scheme.lower() for scheme in schemes)
        if any(scheme not in {"http", "https"} for scheme in normalized):
            raise ValueError("scope schemes support only http and https")
        return tuple(dict.fromkeys(normalized))

    def validate_url(self, url: str) -> None:
        parsed = urlsplit(url)
        if (
            parsed.scheme.lower() not in self.schemes
            or parsed.hostname is None
            or parsed.hostname.lower() not in self.hosts
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise ValueError("URL is outside the immutable research scope")
        default_port = 443 if parsed.scheme.lower() == "https" else 80
        try:
            port = parsed.port or default_port
        except ValueError as error:
            raise ValueError("URL contains an invalid port") from error
        if port not in self.ports:
            raise ValueError("URL port is outside the immutable research scope")


class ResearchTarget(EntityModel):
    asset_id: Identifier
    name: str = Field(min_length=1, max_length=200)
    base_url: str = Field(min_length=1, max_length=2048)

    @model_validator(mode="after")
    def validate_base_url(self) -> "ResearchTarget":
        parsed = urlsplit(self.base_url)
        if not parsed.scheme or parsed.hostname is None or parsed.path not in {"", "/"}:
            raise ValueError("target base_url must contain only scheme, host, and port")
        if parsed.query or parsed.fragment or parsed.username or parsed.password:
            raise ValueError("target base_url cannot contain credentials, query, or fragment")
        return self


class ResearchSession(EntityModel):
    project_id: Identifier | None = None
    project_scope_revision: int | None = Field(default=None, ge=1)
    name: str = Field(min_length=1, max_length=200)
    target: ResearchTarget
    scope: TargetScope
    status: ResearchSessionStatus = ResearchSessionStatus.CREATED
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def target_must_be_in_scope(self) -> "ResearchSession":
        self.scope.validate_url(self.target.base_url)
        if self.status is ResearchSessionStatus.CREATED and self.started_at is not None:
            raise ValueError("CREATED session cannot have started_at")
        if self.status is ResearchSessionStatus.RUNNING and self.started_at is None:
            raise ValueError("RUNNING session requires started_at")
        if self.status in {ResearchSessionStatus.COMPLETED, ResearchSessionStatus.FAILED}:
            if self.started_at is None or self.finished_at is None:
                raise ValueError("finished session requires started_at and finished_at")
        return self

    def start(self) -> "ResearchSession":
        if self.status is not ResearchSessionStatus.CREATED:
            return self
        return self.model_copy(
            update={"status": ResearchSessionStatus.RUNNING, "started_at": utc_now()}
        )
