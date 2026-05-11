"""Cookie extraction from log files and cookies.txt (Netscape format)."""

from __future__ import annotations

import re
from pathlib import Path

from minecookiechecker.models import CookieCandidate

# Regex patterns for extracting cookie-like strings from arbitrary log text.
# Matches: name=value with typical cookie characters.
_COOKIE_PAIR_RE = re.compile(
    r"(?:^|[\s;,&])([A-Za-z_][A-Za-z0-9_.\-]*)=([^\s;,\"'<>]{4,512})",
)

# Known minecraft.net / Microsoft auth cookie names for prioritised matching.
_KNOWN_COOKIE_NAMES = frozenset(
    {
        "MUID",
        "MSCC",
        "MC_PROFILE",
        "MC_SESSION",
        "sid",
        "at",
        "rt",
        "XSRF-TOKEN",
        "laravel_session",
        "_csrf",
        "PLAY_SESSION",
        "JSESSIONID",
        "connect.sid",
    }
)

# Additional pattern: Cookie or Set-Cookie header lines.
_HEADER_RE = re.compile(
    r"(?:Cookie|Set-Cookie)\s*:\s*(.+)",
    re.IGNORECASE,
)


def parse_cookie_header(
    header: str, source_file: str = "", line_number: int = 0
) -> list[CookieCandidate]:
    """Parse a Cookie header string into individual cookie candidates."""
    candidates: list[CookieCandidate] = []
    for pair in header.split(";"):
        pair = pair.strip()
        if "=" not in pair:
            continue
        name, _, value = pair.partition("=")
        name = name.strip()
        value = value.strip()
        if name and value:
            candidates.append(
                CookieCandidate(
                    name=name,
                    value=value,
                    source_file=source_file,
                    line_number=line_number,
                    raw=pair,
                )
            )
    return candidates


def extract_cookies_from_text(
    text: str,
    source_file: str = "",
    domain_filter: str | None = None,
) -> list[CookieCandidate]:
    """Extract candidate cookies from arbitrary text (log content)."""
    candidates: list[CookieCandidate] = []
    seen: set[str] = set()

    for line_number, line in enumerate(text.splitlines(), start=1):
        # Try Cookie/Set-Cookie header lines first.
        header_match = _HEADER_RE.search(line)
        if header_match:
            header_cookies = parse_cookie_header(
                header_match.group(1),
                source_file=source_file,
                line_number=line_number,
            )
            for c in header_cookies:
                key = f"{c.name}={c.value}"
                if key not in seen:
                    seen.add(key)
                    candidates.append(c)
            continue

        # Fall back to generic name=value extraction.
        for match in _COOKIE_PAIR_RE.finditer(line):
            name = match.group(1)
            value = match.group(2)
            key = f"{name}={value}"
            if key in seen:
                continue
            seen.add(key)
            candidates.append(
                CookieCandidate(
                    name=name,
                    value=value,
                    source_file=source_file,
                    line_number=line_number,
                    raw=match.group(0).strip(),
                )
            )

    if domain_filter:
        candidates = [c for c in candidates if domain_filter in c.domain]

    return candidates


def scan_logs_directory(
    logs_path: str | Path,
    domain_filter: str | None = None,
) -> list[CookieCandidate]:
    """Recursively scan a logs directory for cookie candidates."""
    logs_path = Path(logs_path)
    if not logs_path.is_dir():
        raise FileNotFoundError(f"Logs directory not found: {logs_path}")

    all_candidates: list[CookieCandidate] = []
    seen_global: set[str] = set()

    for file_path in sorted(logs_path.rglob("*")):
        if not file_path.is_file():
            continue
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        file_candidates = extract_cookies_from_text(
            text,
            source_file=str(file_path),
            domain_filter=domain_filter,
        )
        for c in file_candidates:
            key = f"{c.name}={c.value}"
            if key not in seen_global:
                seen_global.add(key)
                all_candidates.append(c)

    return all_candidates


def parse_cookies_txt(
    file_path: str | Path,
    cookie_whitelist: list[str] | None = None,
    cookie_blacklist: list[str] | None = None,
    domain_override: str | None = None,
) -> list[CookieCandidate]:
    """Parse a Netscape-format cookies.txt file."""
    file_path = Path(file_path)
    if not file_path.is_file():
        raise FileNotFoundError(f"Cookies file not found: {file_path}")

    text = file_path.read_text(encoding="utf-8", errors="replace")
    candidates: list[CookieCandidate] = []

    for line_number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split("\t")
        if len(parts) < 7:
            continue

        domain = parts[0].lstrip(".")
        name = parts[5]
        value = parts[6]

        if cookie_whitelist and name not in cookie_whitelist:
            continue
        if cookie_blacklist and name in cookie_blacklist:
            continue

        actual_domain = domain_override or f".{domain}"

        candidates.append(
            CookieCandidate(
                name=name,
                value=value,
                domain=actual_domain,
                source_file=str(file_path),
                line_number=line_number,
                raw=line,
            )
        )

    return candidates


def parse_single_cookie_header(
    header_string: str,
    domain_override: str | None = None,
) -> list[CookieCandidate]:
    """Parse a single Cookie header string supplied directly."""
    candidates = parse_cookie_header(header_string, source_file="<cli-input>")
    if domain_override:
        for c in candidates:
            c.domain = domain_override
    return candidates
