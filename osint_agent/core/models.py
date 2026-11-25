"""Core data model shared by every module."""

import re
from datetime import UTC, datetime
from enum import StrEnum

import phonenumbers
from pydantic import BaseModel, Field

DEFAULT_REGION = "MY"
# One or more dot-separated labels ending in a letters-only TLD. Deliberately loose: it rejects
# typos and free text, not unusual-but-real hostnames.
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


class SeedType(StrEnum):
    email = "email"
    username = "username"
    phone = "phone"
    domain = "domain"
    name = "name"


class Seed(BaseModel):
    type: SeedType
    value: str

    @property
    def normalized(self) -> str:
        """Canonical form of the seed. Never raises: invalid input is returned as-is
        so a module can report it as a finding-level error instead of crashing the run."""
        raw = self.value.strip()
        if self.type is SeedType.email:
            return raw.lower()
        if self.type is SeedType.username:
            return raw.lstrip("@")
        if self.type is SeedType.phone:
            try:
                parsed = phonenumbers.parse(raw, DEFAULT_REGION)
            except phonenumbers.NumberParseException:
                return raw
            return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        if self.type is SeedType.domain:
            host = raw.lower().split("://")[-1].split("/")[0].split(":")[0]
            return host.removeprefix("www.").strip(".")
        if self.type is SeedType.name:
            return " ".join(raw.split())
        return raw


def looks_like_hostname(value: str) -> bool:
    return bool(HOSTNAME_RE.match(value))


class Finding(BaseModel):
    module: str
    entity_type: str
    value: str
    source_url: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    raw: dict = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ModuleResult(BaseModel):
    module: str
    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    duration_s: float = 0.0
