"""Core data model shared by every module."""

from datetime import UTC, datetime
from enum import StrEnum

import phonenumbers
from pydantic import BaseModel, Field

DEFAULT_REGION = "MY"


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
        return raw


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
