"""CLI entry-point built with Click."""

from __future__ import annotations

import asyncio
import logging
import sys

import click

from minecookiechecker.config import Settings
from minecookiechecker.consent import (
    CONSENT_BANNER,
    check_consent_file,
    get_operator_identity,
    prompt_consent_interactive,
)
from minecookiechecker.database import AuditDB
from minecookiechecker.output import write_output
from minecookiechecker.parser import (
    parse_cookies_txt,
    parse_single_cookie_header,
    scan_logs_directory,
)
from minecookiechecker.validator import validate_batch

logger = logging.getLogger("minecookiechecker")

# Exit codes
EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_NO_CONSENT = 2
EXIT_VALIDATION_FAILURES = 3


def _configure_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


@click.group()
@click.version_option(package_name="minecookiechecker")
def main() -> None:
    """MineCookieChecker – safe, auditable cookie validation for minecraft.net."""


@main.command()
@click.option("--mode", type=click.Choice(["logs", "file"]), required=True, help="Scan mode.")
@click.option("--path", default="./logs", help="Path to logs directory (logs mode).")
@click.option("--file", "cookie_file", default=None, help="Path to cookies.txt (file mode).")
@click.option("--cookie-header", default=None, help="Raw Cookie header string.")
@click.option("--output", "output_path", default=None, help="Output file path.")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "csv", "table"]),
    default="table",
)
@click.option("--concurrency", type=int, default=None)
@click.option("--rate-limit", type=float, default=None)
@click.option("--timeout", "timeout_ms", type=int, default=None)
@click.option("--dry-run", is_flag=True, default=False)
@click.option("--no-redact", is_flag=True, default=False, help="Show full cookie values.")
@click.option("--consent-file", default=None, help="Path to pre-authorised consent file.")
@click.option("--domain-filter", default=None, help="Filter cookies by domain substring.")
@click.option("--verbose", "-v", is_flag=True, default=False)
def scan(
    mode: str,
    path: str,
    cookie_file: str | None,
    cookie_header: str | None,
    output_path: str | None,
    output_format: str,
    concurrency: int | None,
    rate_limit: float | None,
    timeout_ms: int | None,
    dry_run: bool,
    no_redact: bool,
    consent_file: str | None,
    domain_filter: str | None,
    verbose: bool,
) -> None:
    """Scan and validate cookies against minecraft.net."""
    _configure_logging(verbose)

    settings = Settings()
    settings.merge_cli(
        concurrency=concurrency,
        rate_limit=rate_limit,
        timeout_ms=timeout_ms,
        dry_run=dry_run,
        output_format=output_format,
        domain_filter=domain_filter,
    )
    settings.redact_cookies = not no_redact

    # --- Consent ---
    consent_granted = False
    consent_method = "interactive"

    if consent_file:
        consent_granted = check_consent_file(consent_file)
        consent_method = "file"
    else:
        consent_granted = prompt_consent_interactive()
        consent_method = "interactive"

    if not consent_granted:
        click.echo("Consent not provided. Exiting.", err=True)
        sys.exit(EXIT_NO_CONSENT)

    operator = get_operator_identity()
    audit_db = AuditDB(settings.db_path)

    source_path = path if mode == "logs" else (cookie_file or "<cli-header>")
    audit_id = audit_db.log_consent(
        operator=operator,
        consent_method=consent_method,
        source_type=mode,
        source_path=source_path,
    )
    logger.info("Audit record created: id=%d operator=%s", audit_id, operator)

    # --- Parse ---
    if mode == "logs":
        candidates = scan_logs_directory(path, domain_filter=domain_filter)
    elif cookie_header:
        candidates = parse_single_cookie_header(cookie_header, domain_override=domain_filter)
    elif cookie_file:
        candidates = parse_cookies_txt(cookie_file)
    else:
        click.echo("File mode requires --file or --cookie-header.", err=True)
        sys.exit(EXIT_ERROR)

    if not candidates:
        click.echo("No cookie candidates found.")
        sys.exit(EXIT_SUCCESS)

    logger.info("Found %d cookie candidate(s)", len(candidates))

    # --- Validate ---
    summary = asyncio.run(
        validate_batch(candidates, settings, audit_db=audit_db, audit_id=audit_id)
    )

    # --- Output ---
    write_output(summary, output_path, fmt=output_format, redact=settings.redact_cookies)

    if summary.valid > 0:
        sys.exit(EXIT_VALIDATION_FAILURES)
    sys.exit(EXIT_SUCCESS)


@main.command()
@click.option("--dry-run", is_flag=True, default=True)
@click.option("--verbose", "-v", is_flag=True, default=False)
def run(dry_run: bool, verbose: bool) -> None:
    """Quick dry-run with default settings."""
    _configure_logging(verbose)
    click.echo(CONSENT_BANNER)
    click.echo("Dry-run mode: no network requests will be made.")
    settings = Settings()
    settings.dry_run = True
    click.echo(f"Concurrency: {settings.concurrency}, Rate limit: {settings.rate_limit}/s")
    click.echo("Ready. Use 'scan' command to process cookies.")


@main.command()
@click.option("--port", type=int, default=8080)
@click.option("--host", default="0.0.0.0")
def serve(port: int, host: str) -> None:
    """Start the web UI server."""
    import uvicorn

    from minecookiechecker.web.app import create_app

    app = create_app()
    uvicorn.run(app, host=host, port=port)
