"""Tests for output formatting."""

from __future__ import annotations

import io
import json

from minecookiechecker.models import CookieCandidate, CookieStatus, RunSummary, ValidationResult
from minecookiechecker.output import format_csv, format_json, print_table


def _make_summary() -> RunSummary:
    cookie = CookieCandidate(name="sess", value="secret_value_123456", source_file="test.log")
    result = ValidationResult(
        cookie=cookie,
        status=CookieStatus.VALID,
        http_status=200,
        detail="HTTP 200 -> valid",
    )
    return RunSummary(total=1, valid=1, results=[result])


class TestFormatJSON:
    def test_valid_json(self) -> None:
        summary = _make_summary()
        text = format_json(summary, redact=True)
        data = json.loads(text)
        assert data["summary"]["total"] == 1
        assert data["summary"]["valid"] == 1
        assert "***" in data["results"][0]["cookie_value"]

    def test_no_redact(self) -> None:
        summary = _make_summary()
        text = format_json(summary, redact=False)
        data = json.loads(text)
        assert data["results"][0]["cookie_value"] == "secret_value_123456"


class TestFormatCSV:
    def test_csv_output(self) -> None:
        summary = _make_summary()
        text = format_csv(summary, redact=True)
        assert "cookie_name" in text
        assert "sess" in text
        assert "***" in text


class TestPrintTable:
    def test_table_output(self) -> None:
        summary = _make_summary()
        buf = io.StringIO()
        print_table(summary, redact=True, file=buf)
        output = buf.getvalue()
        assert "sess" in output
        assert "valid" in output.lower()
