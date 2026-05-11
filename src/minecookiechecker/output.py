"""Output formatting: JSON, CSV, and human-readable table."""

from __future__ import annotations

import csv
import io
import json
from typing import TextIO

from rich.console import Console
from rich.table import Table

from minecookiechecker.models import RunSummary, ValidationResult


def _result_dict(result: ValidationResult, redact: bool = True) -> dict:
    value = result.cookie.redacted_value() if redact else result.cookie.value
    return {
        "cookie_name": result.cookie.name,
        "cookie_value": value,
        "domain": result.cookie.domain,
        "status": result.status.value,
        "http_status": result.http_status,
        "redirect_url": result.redirect_url,
        "detail": result.detail,
        "source_file": result.cookie.source_file,
        "timestamp": result.timestamp.isoformat(),
    }


def format_json(summary: RunSummary, redact: bool = True) -> str:
    data = {
        "summary": {
            "total": summary.total,
            "valid": summary.valid,
            "invalid": summary.invalid,
            "errors": summary.errors,
            "skipped": summary.skipped,
        },
        "results": [_result_dict(r, redact) for r in summary.results],
    }
    return json.dumps(data, indent=2)


def format_csv(summary: RunSummary, redact: bool = True) -> str:
    buf = io.StringIO()
    fieldnames = [
        "cookie_name",
        "cookie_value",
        "domain",
        "status",
        "http_status",
        "redirect_url",
        "detail",
        "source_file",
        "timestamp",
    ]
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for r in summary.results:
        writer.writerow(_result_dict(r, redact))
    return buf.getvalue()


def print_table(summary: RunSummary, redact: bool = True, file: TextIO | None = None) -> None:
    console = Console(file=file)
    table = Table(title="MineCookieChecker Results")
    table.add_column("Cookie", style="cyan")
    table.add_column("Value", style="dim")
    table.add_column("Status", style="bold")
    table.add_column("HTTP", justify="right")
    table.add_column("Detail")
    table.add_column("Source")

    for r in summary.results:
        value = r.cookie.redacted_value() if redact else r.cookie.value
        status_style = {
            "valid": "green",
            "invalid": "red",
            "expired": "yellow",
            "error": "red",
            "skipped": "dim",
        }.get(r.status.value, "")
        table.add_row(
            r.cookie.name,
            value,
            f"[{status_style}]{r.status.value}[/{status_style}]",
            str(r.http_status or "-"),
            r.detail,
            r.cookie.source_file,
        )

    console.print(table)
    console.print(
        f"\nTotal: {summary.total}  Valid: {summary.valid}  "
        f"Invalid: {summary.invalid}  Errors: {summary.errors}  "
        f"Skipped: {summary.skipped}"
    )


def write_output(
    summary: RunSummary,
    output_path: str | None,
    fmt: str = "table",
    redact: bool = True,
) -> None:
    """Write results to stdout or file in the specified format."""
    if fmt == "json":
        text = format_json(summary, redact)
    elif fmt == "csv":
        text = format_csv(summary, redact)
    else:
        print_table(summary, redact)
        return

    if output_path:
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        print(text)
