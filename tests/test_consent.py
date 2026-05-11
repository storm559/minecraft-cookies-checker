"""Tests for consent management."""

from __future__ import annotations

from pathlib import Path

from minecookiechecker.consent import check_consent_file, get_operator_identity

FIXTURES = Path(__file__).parent / "fixtures"


class TestCheckConsentFile:
    def test_valid_consent_file(self) -> None:
        assert check_consent_file(FIXTURES / "consent.txt") is True

    def test_invalid_consent_file(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad_consent.txt"
        bad.write_text("NOPE\n")
        assert check_consent_file(bad) is False

    def test_missing_file(self) -> None:
        assert check_consent_file("/nonexistent/consent.txt") is False

    def test_empty_file(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty.txt"
        empty.write_text("")
        assert check_consent_file(empty) is False


class TestGetOperatorIdentity:
    def test_returns_string(self) -> None:
        identity = get_operator_identity()
        assert isinstance(identity, str)
        assert len(identity) > 0
