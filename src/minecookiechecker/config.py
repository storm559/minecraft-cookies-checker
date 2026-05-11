"""Application configuration via environment variables and CLI overrides."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class Settings:
    """Runtime settings with env-var defaults."""

    concurrency: int = int(os.getenv("MC_CHECKER_CONCURRENCY", "5"))
    rate_limit: float = float(os.getenv("MC_CHECKER_RATE_LIMIT", "1"))
    timeout_ms: int = int(os.getenv("MC_CHECKER_TIMEOUT_MS", "5000"))
    db_path: str = os.getenv("MC_CHECKER_DB_PATH", "./data/audit.db")
    encryption_passphrase: str | None = os.getenv("MC_CHECKER_ENCRYPTION_PASSPHRASE")
    redact_cookies: bool = True
    dry_run: bool = False
    output_format: str = "table"
    retries: int = 3
    retry_backoff: float = 1.0
    domain_filter: str | None = None
    cookie_whitelist: list[str] = field(default_factory=list)
    cookie_blacklist: list[str] = field(default_factory=list)

    @property
    def timeout_seconds(self) -> float:
        return self.timeout_ms / 1000.0

    def merge_cli(self, **kwargs: object) -> None:
        """Override fields from CLI flags (non-None values only)."""
        for key, value in kwargs.items():
            if value is not None and hasattr(self, key):
                setattr(self, key, value)
