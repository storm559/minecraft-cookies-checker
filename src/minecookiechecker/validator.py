"""Cookie validation against minecraft.net using safe HTTP requests."""

from __future__ import annotations

import asyncio
import hashlib
import logging
from typing import TYPE_CHECKING

import httpx
from aiolimiter import AsyncLimiter

from minecookiechecker.config import Settings
from minecookiechecker.models import CookieCandidate, CookieStatus, RunSummary, ValidationResult

if TYPE_CHECKING:
    from minecookiechecker.database import AuditDB

logger = logging.getLogger("minecookiechecker.validator")

VALIDATION_URL = "https://www.minecraft.net/en-us/profile"
VALIDATION_HEADERS = {
    "User-Agent": "MineCookieChecker/1.0 (audit-tool)",
    "Accept": "text/html",
}


def _hash_value(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]


async def validate_cookie(
    client: httpx.AsyncClient,
    candidate: CookieCandidate,
    settings: Settings,
    limiter: AsyncLimiter,
) -> ValidationResult:
    """Validate a single cookie candidate with a safe HEAD/GET request."""
    async with limiter:
        try:
            cookies = {candidate.name: candidate.value}
            response = await client.get(
                VALIDATION_URL,
                cookies=cookies,
                headers=VALIDATION_HEADERS,
                follow_redirects=False,
                timeout=settings.timeout_seconds,
            )

            status = _interpret_response(response)
            redirect_url = response.headers.get("location")

            return ValidationResult(
                cookie=candidate,
                status=status,
                http_status=response.status_code,
                redirect_url=redirect_url,
                detail=_status_detail(response.status_code, status),
            )
        except httpx.TimeoutException:
            return ValidationResult(
                cookie=candidate,
                status=CookieStatus.ERROR,
                detail="Request timed out",
            )
        except httpx.HTTPError as exc:
            return ValidationResult(
                cookie=candidate,
                status=CookieStatus.ERROR,
                detail=f"HTTP error: {exc}",
            )


def _interpret_response(response: httpx.Response) -> CookieStatus:
    """Interpret the HTTP response to determine cookie validity."""
    code = response.status_code

    # 200 with profile content suggests a valid authenticated session.
    if code == 200:
        return CookieStatus.VALID

    # Redirect to login page means the cookie is not valid for auth.
    if code in (301, 302, 303, 307, 308):
        location = response.headers.get("location", "")
        if "login" in location.lower() or "signin" in location.lower():
            return CookieStatus.INVALID
        return CookieStatus.INVALID

    if code == 401:
        return CookieStatus.INVALID

    if code == 403:
        return CookieStatus.EXPIRED

    return CookieStatus.ERROR


def _status_detail(http_status: int, cookie_status: CookieStatus) -> str:
    return f"HTTP {http_status} → {cookie_status.value}"


async def validate_batch(
    candidates: list[CookieCandidate],
    settings: Settings,
    audit_db: AuditDB | None = None,
    audit_id: int | None = None,
    http_client: httpx.AsyncClient | None = None,
) -> RunSummary:
    """Validate a batch of cookie candidates with concurrency and rate limiting."""
    limiter = AsyncLimiter(max_rate=settings.rate_limit, time_period=1)
    summary = RunSummary(total=len(candidates))

    if settings.dry_run:
        for c in candidates:
            result = ValidationResult(
                cookie=c,
                status=CookieStatus.SKIPPED,
                detail="Dry run – no network request sent",
            )
            summary.skipped += 1
            summary.results.append(result)
        return summary

    own_client = http_client is None
    client = http_client or httpx.AsyncClient(
        follow_redirects=False,
        timeout=settings.timeout_seconds,
    )

    try:
        semaphore = asyncio.Semaphore(settings.concurrency)

        async def _limited(cand: CookieCandidate) -> ValidationResult:
            async with semaphore:
                return await validate_cookie(client, cand, settings, limiter)

        tasks = [_limited(c) for c in candidates]
        results = await asyncio.gather(*tasks)

        for result in results:
            summary.results.append(result)
            if result.status == CookieStatus.VALID:
                summary.valid += 1
            elif result.status == CookieStatus.INVALID:
                summary.invalid += 1
            elif result.status == CookieStatus.ERROR:
                summary.errors += 1
            elif result.status == CookieStatus.EXPIRED:
                summary.invalid += 1
            else:
                summary.skipped += 1

            if audit_db and audit_id:
                audit_db.log_result(
                    audit_id=audit_id,
                    cookie_name=result.cookie.name,
                    cookie_value_hash=_hash_value(result.cookie.value),
                    domain=result.cookie.domain,
                    status=result.status.value,
                    http_status=result.http_status,
                    detail=result.detail,
                )

        if audit_db and audit_id:
            audit_db.update_summary(
                audit_id=audit_id,
                total=summary.total,
                valid=summary.valid,
                invalid=summary.invalid,
                errors=summary.errors,
                skipped=summary.skipped,
            )
    finally:
        if own_client:
            await client.aclose()

    return summary
