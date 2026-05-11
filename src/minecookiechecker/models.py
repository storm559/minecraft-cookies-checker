"""Domain models for cookie checking results and audit records."""

from __future__ import annotations

import datetime
import enum
from dataclasses import dataclass, field


class CookieStatus(str, enum.Enum):
    VALID = "valid"
    INVALID = "invalid"
    EXPIRED = "expired"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass
class CookieCandidate:
    """A single cookie extracted from a source."""

    name: str
    value: str
    domain: str = ".minecraft.net"
    source_file: str = ""
    line_number: int = 0
    raw: str = ""

    def header_string(self) -> str:
        return f"{self.name}={self.value}"

    def redacted_value(self) -> str:
        if len(self.value) <= 6:
            return "***"
        return self.value[:3] + "***" + self.value[-3:]


@dataclass
class ValidationResult:
    """Result of validating a single cookie or cookie set."""

    cookie: CookieCandidate
    status: CookieStatus
    http_status: int | None = None
    redirect_url: str | None = None
    detail: str = ""
    timestamp: datetime.datetime = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc)
    )


@dataclass
class RunSummary:
    """Aggregate summary for a scan run."""

    total: int = 0
    valid: int = 0
    invalid: int = 0
    errors: int = 0
    skipped: int = 0
    results: list[ValidationResult] = field(default_factory=list)
