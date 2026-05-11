"""Tests for audit database operations."""

from __future__ import annotations

from pathlib import Path

import pytest

from minecookiechecker.database import AuditDB


@pytest.fixture
def db(tmp_path: Path) -> AuditDB:
    return AuditDB(str(tmp_path / "test_audit.db"))


class TestAuditDB:
    def test_log_consent(self, db: AuditDB) -> None:
        audit_id = db.log_consent(
            operator="test-user",
            consent_method="interactive",
            source_type="logs",
            source_path="./logs",
        )
        assert audit_id > 0

    def test_update_summary(self, db: AuditDB) -> None:
        audit_id = db.log_consent(
            operator="test-user",
            consent_method="file",
            source_type="file",
        )
        db.update_summary(
            audit_id=audit_id,
            total=10,
            valid=3,
            invalid=5,
            errors=2,
            skipped=0,
            run_mode="file",
        )
        runs = db.get_recent_runs(limit=1)
        assert len(runs) == 1
        assert runs[0].total_cookies == 10
        assert runs[0].valid_cookies == 3

    def test_log_result(self, db: AuditDB) -> None:
        audit_id = db.log_consent(
            operator="test-user",
            consent_method="interactive",
            source_type="logs",
        )
        db.log_result(
            audit_id=audit_id,
            cookie_name="MC_SESSION",
            cookie_value_hash="abc123",
            domain=".minecraft.net",
            status="valid",
            http_status=200,
            detail="OK",
        )

    def test_get_recent_runs(self, db: AuditDB) -> None:
        for i in range(5):
            db.log_consent(
                operator=f"user-{i}",
                consent_method="interactive",
                source_type="logs",
            )
        runs = db.get_recent_runs(limit=3)
        assert len(runs) == 3
