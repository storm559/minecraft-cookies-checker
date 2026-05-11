"""End-to-end CLI tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from minecookiechecker.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


class TestScanCommand:
    def test_scan_logs_dry_run(self, runner: CliRunner, tmp_path: Path) -> None:
        consent = tmp_path / "consent.txt"
        consent.write_text("CONSENT_GRANTED\n")
        output_file = tmp_path / "results.json"

        result = runner.invoke(
            main,
            [
                "scan",
                "--mode", "logs",
                "--path", str(FIXTURES / "logs"),
                "--consent-file", str(consent),
                "--dry-run",
                "--format", "json",
                "--output", str(output_file),
            ],
        )
        assert result.exit_code == 0
        assert output_file.exists()
        data = json.loads(output_file.read_text())
        assert data["summary"]["total"] > 0
        assert data["summary"]["skipped"] == data["summary"]["total"]

    def test_scan_file_dry_run(self, runner: CliRunner, tmp_path: Path) -> None:
        consent = tmp_path / "consent.txt"
        consent.write_text("CONSENT_GRANTED\n")

        result = runner.invoke(
            main,
            [
                "scan",
                "--mode", "file",
                "--file", str(FIXTURES / "cookies.txt"),
                "--consent-file", str(consent),
                "--dry-run",
                "--format", "json",
            ],
        )
        assert result.exit_code == 0
        output = json.loads(result.output)
        assert output["summary"]["total"] == 4

    def test_scan_no_consent(self, runner: CliRunner) -> None:
        result = runner.invoke(
            main,
            [
                "scan",
                "--mode", "logs",
                "--path", str(FIXTURES / "logs"),
            ],
            input="no\n",
        )
        assert result.exit_code == 2

    def test_scan_invalid_consent_file(self, runner: CliRunner, tmp_path: Path) -> None:
        bad_consent = tmp_path / "bad.txt"
        bad_consent.write_text("NOPE\n")

        result = runner.invoke(
            main,
            [
                "scan",
                "--mode", "logs",
                "--path", str(FIXTURES / "logs"),
                "--consent-file", str(bad_consent),
            ],
        )
        assert result.exit_code == 2

    def test_scan_csv_output(self, runner: CliRunner, tmp_path: Path) -> None:
        consent = tmp_path / "consent.txt"
        consent.write_text("CONSENT_GRANTED\n")

        result = runner.invoke(
            main,
            [
                "scan",
                "--mode", "file",
                "--file", str(FIXTURES / "cookies.txt"),
                "--consent-file", str(consent),
                "--dry-run",
                "--format", "csv",
            ],
        )
        assert result.exit_code == 0
        assert "cookie_name" in result.output

    def test_scan_cookie_header(self, runner: CliRunner, tmp_path: Path) -> None:
        consent = tmp_path / "consent.txt"
        consent.write_text("CONSENT_GRANTED\n")

        result = runner.invoke(
            main,
            [
                "scan",
                "--mode", "file",
                "--cookie-header", "session=abcdef123456; token=xyz789abcdef",
                "--consent-file", str(consent),
                "--dry-run",
                "--format", "json",
            ],
        )
        assert result.exit_code == 0


class TestRunCommand:
    def test_dry_run(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["run", "--dry-run"])
        assert result.exit_code == 0
        assert "Dry-run" in result.output


class TestVersionFlag:
    def test_version(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "1.0.0" in result.output
