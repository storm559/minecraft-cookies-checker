"""SQLite audit-log database via SQLAlchemy."""

from __future__ import annotations

import datetime
from pathlib import Path

from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


class AuditRecord(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(
        DateTime,
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
        nullable=False,
    )
    operator = Column(String(256), nullable=False)
    consent_given = Column(String(10), nullable=False)
    consent_method = Column(String(64), nullable=False, default="interactive")
    source_type = Column(String(32), nullable=False)
    source_path = Column(Text, nullable=True)
    total_cookies = Column(Integer, default=0)
    valid_cookies = Column(Integer, default=0)
    invalid_cookies = Column(Integer, default=0)
    errors = Column(Integer, default=0)
    skipped = Column(Integer, default=0)
    run_mode = Column(String(32), nullable=True)
    detail = Column(Text, nullable=True)


class CheckResult(Base):
    __tablename__ = "check_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    audit_id = Column(Integer, nullable=False)
    cookie_name = Column(String(256), nullable=False)
    cookie_value_hash = Column(String(64), nullable=False)
    domain = Column(String(256), nullable=False)
    status = Column(String(32), nullable=False)
    http_status = Column(Integer, nullable=True)
    detail = Column(Text, nullable=True)
    timestamp = Column(
        DateTime,
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
        nullable=False,
    )


class AuditDB:
    """Thin wrapper around the audit SQLite database."""

    def __init__(self, db_path: str = "./data/audit.db") -> None:
        db_dir = Path(db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(f"sqlite:///{db_path}", echo=False)
        Base.metadata.create_all(self.engine)
        self._session_factory = sessionmaker(bind=self.engine)

    def session(self) -> Session:
        return self._session_factory()

    def log_consent(
        self,
        operator: str,
        consent_method: str,
        source_type: str,
        source_path: str | None = None,
    ) -> int:
        with self.session() as sess:
            record = AuditRecord(
                operator=operator,
                consent_given="yes",
                consent_method=consent_method,
                source_type=source_type,
                source_path=source_path,
            )
            sess.add(record)
            sess.commit()
            return record.id  # type: ignore[return-value]

    def update_summary(
        self,
        audit_id: int,
        total: int,
        valid: int,
        invalid: int,
        errors: int,
        skipped: int,
        run_mode: str | None = None,
    ) -> None:
        with self.session() as sess:
            record = sess.query(AuditRecord).filter_by(id=audit_id).first()
            if record:
                record.total_cookies = total
                record.valid_cookies = valid
                record.invalid_cookies = invalid
                record.errors = errors
                record.skipped = skipped
                record.run_mode = run_mode
                sess.commit()

    def log_result(
        self,
        audit_id: int,
        cookie_name: str,
        cookie_value_hash: str,
        domain: str,
        status: str,
        http_status: int | None = None,
        detail: str = "",
    ) -> None:
        with self.session() as sess:
            result = CheckResult(
                audit_id=audit_id,
                cookie_name=cookie_name,
                cookie_value_hash=cookie_value_hash,
                domain=domain,
                status=status,
                http_status=http_status,
                detail=detail,
            )
            sess.add(result)
            sess.commit()

    def get_recent_runs(self, limit: int = 20) -> list[AuditRecord]:
        with self.session() as sess:
            return (
                sess.query(AuditRecord)
                .order_by(AuditRecord.timestamp.desc())
                .limit(limit)
                .all()
            )
