"""Unit tests for cookie parsing logic."""

from __future__ import annotations

from pathlib import Path

import pytest

from minecookiechecker.parser import (
    extract_cookies_from_text,
    parse_cookie_header,
    parse_cookies_txt,
    parse_single_cookie_header,
    scan_logs_directory,
)

FIXTURES = Path(__file__).parent / "fixtures"


class TestParseCookieHeader:
    def test_simple_header(self) -> None:
        cookies = parse_cookie_header("session=abc123; token=xyz789")
        assert len(cookies) == 2
        assert cookies[0].name == "session"
        assert cookies[0].value == "abc123"
        assert cookies[1].name == "token"
        assert cookies[1].value == "xyz789"

    def test_single_cookie(self) -> None:
        cookies = parse_cookie_header("sid=test_value")
        assert len(cookies) == 1
        assert cookies[0].name == "sid"

    def test_empty_string(self) -> None:
        cookies = parse_cookie_header("")
        assert cookies == []

    def test_malformed_no_value(self) -> None:
        cookies = parse_cookie_header("novalue; another=ok")
        assert len(cookies) == 1
        assert cookies[0].name == "another"

    def test_value_with_equals(self) -> None:
        cookies = parse_cookie_header("token=abc=def=ghi")
        assert len(cookies) == 1
        assert cookies[0].name == "token"
        assert cookies[0].value == "abc=def=ghi"

    def test_whitespace_handling(self) -> None:
        cookies = parse_cookie_header("  name = value ;  other = val2 ")
        assert len(cookies) == 2
        assert cookies[0].name == "name"
        assert cookies[0].value == "value"


class TestExtractCookiesFromText:
    def test_cookie_header_line(self) -> None:
        text = "DEBUG Cookie: MC_SESSION=abc123def456; MUID=aabbccdd11223344"
        cookies = extract_cookies_from_text(text)
        assert len(cookies) == 2
        names = {c.name for c in cookies}
        assert "MC_SESSION" in names
        assert "MUID" in names

    def test_set_cookie_header(self) -> None:
        text = "Set-Cookie: sid=session_value_123; Domain=.minecraft.net; Path=/"
        cookies = extract_cookies_from_text(text)
        assert any(c.name == "sid" for c in cookies)

    def test_generic_key_value(self) -> None:
        text = "some_token=abcdef1234567890 other text"
        cookies = extract_cookies_from_text(text)
        assert any(c.name == "some_token" for c in cookies)

    def test_deduplication(self) -> None:
        text = "Cookie: a=val1; b=val2\nCookie: a=val1; c=val3"
        cookies = extract_cookies_from_text(text)
        names_values = [(c.name, c.value) for c in cookies]
        assert names_values.count(("a", "val1")) == 1

    def test_multiline_log(self) -> None:
        text = (
            "2024 INFO startup\n"
            "2024 DEBUG Cookie: sess=tok123456; auth=abc789def\n"
            "2024 INFO done\n"
        )
        cookies = extract_cookies_from_text(text)
        assert len(cookies) == 2

    def test_short_values_filtered(self) -> None:
        text = "x=ab y=abcdef1234"
        cookies = extract_cookies_from_text(text)
        # x=ab has value length < 4, should not be matched
        assert all(c.name != "x" for c in cookies)


class TestScanLogsDirectory:
    def test_scan_fixtures(self) -> None:
        logs_dir = FIXTURES / "logs"
        cookies = scan_logs_directory(logs_dir)
        assert len(cookies) > 0
        names = {c.name for c in cookies}
        assert "MC_SESSION" in names

    def test_directory_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            scan_logs_directory("/nonexistent/path")

    def test_dedup_across_files(self) -> None:
        logs_dir = FIXTURES / "logs"
        cookies = scan_logs_directory(logs_dir)
        keys = [f"{c.name}={c.value}" for c in cookies]
        assert len(keys) == len(set(keys))


class TestParseCookiesTxt:
    def test_parse_fixture(self) -> None:
        cookies = parse_cookies_txt(FIXTURES / "cookies.txt")
        assert len(cookies) == 4
        names = {c.name for c in cookies}
        assert "MC_SESSION" in names
        assert "MUID" in names
        assert "sid" in names
        assert "other_cookie" in names

    def test_whitelist(self) -> None:
        cookies = parse_cookies_txt(
            FIXTURES / "cookies.txt", cookie_whitelist=["MC_SESSION"]
        )
        assert len(cookies) == 1
        assert cookies[0].name == "MC_SESSION"

    def test_blacklist(self) -> None:
        cookies = parse_cookies_txt(
            FIXTURES / "cookies.txt", cookie_blacklist=["other_cookie"]
        )
        assert all(c.name != "other_cookie" for c in cookies)

    def test_domain_override(self) -> None:
        cookies = parse_cookies_txt(
            FIXTURES / "cookies.txt", domain_override=".custom.net"
        )
        assert all(c.domain == ".custom.net" for c in cookies)

    def test_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            parse_cookies_txt("/nonexistent/cookies.txt")


class TestParseSingleCookieHeader:
    def test_basic(self) -> None:
        cookies = parse_single_cookie_header("foo=bar123456; baz=qux789012")
        assert len(cookies) == 2
        assert cookies[0].source_file == "<cli-input>"

    def test_domain_override(self) -> None:
        cookies = parse_single_cookie_header("a=value12345", domain_override=".test.net")
        assert cookies[0].domain == ".test.net"
