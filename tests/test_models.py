"""Tests for domain models."""

from __future__ import annotations

from minecookiechecker.models import CookieCandidate, CookieStatus


class TestCookieCandidate:
    def test_header_string(self) -> None:
        c = CookieCandidate(name="session", value="abc123")
        assert c.header_string() == "session=abc123"

    def test_redacted_value_long(self) -> None:
        c = CookieCandidate(name="tok", value="abcdefghijklmnop")
        redacted = c.redacted_value()
        assert redacted.startswith("abc")
        assert redacted.endswith("nop")
        assert "***" in redacted

    def test_redacted_value_short(self) -> None:
        c = CookieCandidate(name="tok", value="abc")
        assert c.redacted_value() == "***"


class TestCookieStatus:
    def test_values(self) -> None:
        assert CookieStatus.VALID.value == "valid"
        assert CookieStatus.INVALID.value == "invalid"
        assert CookieStatus.EXPIRED.value == "expired"
        assert CookieStatus.ERROR.value == "error"
        assert CookieStatus.SKIPPED.value == "skipped"
