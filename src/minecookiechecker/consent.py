"""Consent management – mandatory operator acknowledgement before any network I/O."""

from __future__ import annotations

import getpass
import os
from pathlib import Path

CONSENT_BANNER = """
╔══════════════════════════════════════════════════════════════════════╗
║                     MineCookieChecker – Legal Notice                ║
╠══════════════════════════════════════════════════════════════════════╣
║  This tool validates HTTP cookies against minecraft.net.            ║
║                                                                     ║
║  BY PROCEEDING YOU CONFIRM:                                         ║
║   1. You own the accounts associated with these cookies, OR         ║
║   2. You have explicit written consent from the account owners.     ║
║                                                                     ║
║  PROHIBITED USES:                                                   ║
║   • Credential stuffing or unauthorised access attempts             ║
║   • Automated harvesting of third-party cookies                     ║
║   • Any activity violating Minecraft/Mojang Terms of Service        ║
║   • Any activity violating applicable law                           ║
║                                                                     ║
║  All runs are audited and logged locally.                           ║
╚══════════════════════════════════════════════════════════════════════╝
"""


def get_operator_identity() -> str:
    """Return a best-effort operator identifier."""
    return os.getenv("USER") or os.getenv("USERNAME") or getpass.getuser()


def prompt_consent_interactive() -> bool:
    """Prompt the operator for interactive consent. Returns True if granted."""
    print(CONSENT_BANNER)
    answer = input("Do you confirm you have authorisation to test these cookies? [yes/NO]: ")
    return answer.strip().lower() in ("yes", "y")


def check_consent_file(consent_file: str | Path) -> bool:
    """Read a pre-authorised consent file.

    The file must contain the exact text ``CONSENT_GRANTED`` on its first
    non-empty line.
    """
    path = Path(consent_file)
    if not path.is_file():
        return False
    text = path.read_text(encoding="utf-8").strip()
    first_line = text.splitlines()[0].strip() if text else ""
    return first_line == "CONSENT_GRANTED"
