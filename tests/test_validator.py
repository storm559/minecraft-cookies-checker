"""Integration tests for cookie validation using httpx mock transport."""

from __future__ import annotations

import httpx
import pytest
import respx
from aiolimiter import AsyncLimiter

from minecookiechecker.config import Settings
from minecookiechecker.models import CookieCandidate, CookieStatus
from minecookiechecker.validator import VALIDATION_URL, validate_batch, validate_cookie


@pytest.fixture
def settings() -> Settings:
    s = Settings()
    s.concurrency = 2
    s.rate_limit = 100  # high limit for tests
    s.timeout_ms = 5000
    s.dry_run = False
    return s


@pytest.fixture
def sample_cookie() -> CookieCandidate:
    return CookieCandidate(
        name="MC_SESSION",
        value="test_session_value",
        domain=".minecraft.net",
        source_file="test",
    )


@pytest.fixture
def limiter() -> AsyncLimiter:
    return AsyncLimiter(max_rate=100, time_period=1)


class TestValidateCookie:
    @respx.mock
    @pytest.mark.asyncio
    async def test_valid_200(
        self,
        settings: Settings,
        sample_cookie: CookieCandidate,
        limiter: AsyncLimiter,
    ) -> None:
        respx.get(VALIDATION_URL).mock(return_value=httpx.Response(200))
        async with httpx.AsyncClient() as client:
            result = await validate_cookie(client, sample_cookie, settings, limiter)
        assert result.status == CookieStatus.VALID
        assert result.http_status == 200

    @respx.mock
    @pytest.mark.asyncio
    async def test_invalid_302_login_redirect(
        self,
        settings: Settings,
        sample_cookie: CookieCandidate,
        limiter: AsyncLimiter,
    ) -> None:
        respx.get(VALIDATION_URL).mock(
            return_value=httpx.Response(
                302, headers={"Location": "https://login.live.com/signin"}
            )
        )
        async with httpx.AsyncClient() as client:
            result = await validate_cookie(client, sample_cookie, settings, limiter)
        assert result.status == CookieStatus.INVALID
        assert result.http_status == 302

    @respx.mock
    @pytest.mark.asyncio
    async def test_invalid_401(
        self,
        settings: Settings,
        sample_cookie: CookieCandidate,
        limiter: AsyncLimiter,
    ) -> None:
        respx.get(VALIDATION_URL).mock(return_value=httpx.Response(401))
        async with httpx.AsyncClient() as client:
            result = await validate_cookie(client, sample_cookie, settings, limiter)
        assert result.status == CookieStatus.INVALID

    @respx.mock
    @pytest.mark.asyncio
    async def test_expired_403(
        self,
        settings: Settings,
        sample_cookie: CookieCandidate,
        limiter: AsyncLimiter,
    ) -> None:
        respx.get(VALIDATION_URL).mock(return_value=httpx.Response(403))
        async with httpx.AsyncClient() as client:
            result = await validate_cookie(client, sample_cookie, settings, limiter)
        assert result.status == CookieStatus.EXPIRED

    @respx.mock
    @pytest.mark.asyncio
    async def test_timeout(
        self,
        settings: Settings,
        sample_cookie: CookieCandidate,
        limiter: AsyncLimiter,
    ) -> None:
        respx.get(VALIDATION_URL).mock(side_effect=httpx.ReadTimeout("timeout"))
        async with httpx.AsyncClient() as client:
            result = await validate_cookie(client, sample_cookie, settings, limiter)
        assert result.status == CookieStatus.ERROR
        assert "timed out" in result.detail.lower()

    @respx.mock
    @pytest.mark.asyncio
    async def test_network_error(
        self,
        settings: Settings,
        sample_cookie: CookieCandidate,
        limiter: AsyncLimiter,
    ) -> None:
        respx.get(VALIDATION_URL).mock(side_effect=httpx.ConnectError("refused"))
        async with httpx.AsyncClient() as client:
            result = await validate_cookie(client, sample_cookie, settings, limiter)
        assert result.status == CookieStatus.ERROR


class TestValidateBatch:
    @respx.mock
    @pytest.mark.asyncio
    async def test_batch_mixed_results(self, settings: Settings) -> None:
        route = respx.get(VALIDATION_URL)
        responses = [
            httpx.Response(200),
            httpx.Response(
                302, headers={"Location": "https://login.live.com/signin"}
            ),
            httpx.Response(401),
        ]
        route.side_effect = responses

        candidates = [
            CookieCandidate(name="a", value="valid_cookie_value_1", source_file="test"),
            CookieCandidate(name="b", value="invalid_cookie_value_2", source_file="test"),
            CookieCandidate(name="c", value="invalid_cookie_value_3", source_file="test"),
        ]

        summary = await validate_batch(candidates, settings)
        assert summary.total == 3
        assert summary.valid == 1
        assert summary.invalid == 2

    @pytest.mark.asyncio
    async def test_dry_run(self, settings: Settings) -> None:
        settings.dry_run = True
        candidates = [
            CookieCandidate(name="a", value="value1234", source_file="test"),
        ]
        summary = await validate_batch(candidates, settings)
        assert summary.total == 1
        assert summary.skipped == 1
        assert summary.results[0].status == CookieStatus.SKIPPED

    @respx.mock
    @pytest.mark.asyncio
    async def test_empty_batch(self, settings: Settings) -> None:
        summary = await validate_batch([], settings)
        assert summary.total == 0
