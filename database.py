#!/usr/bin/env python3
"""
Database layer basata su SQLAlchemy.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Generator

from pathlib import Path

from sqlalchemy import Column, DateTime, Float, Index, Integer, String, Text, create_engine, event, inspect, text
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from config import settings

Base = declarative_base()


def _build_engine():
    database_url = settings.database_url
    connect_args = {
        "check_same_thread": False
    } if database_url.startswith("sqlite") else {}
    if settings.sqlcipher_key:
        try:
            import pysqlcipher3  # noqa: F401
        except ImportError as exc:
            raise RuntimeError(
                "SQLCipher support requires the optional dependency "
                "`pysqlcipher3-binary`. Install it when setting "
                "VAP_SQLCIPHER_KEY."
            ) from exc
        if database_url.startswith("sqlite:///"):
            database_url = database_url.replace("sqlite:///", "sqlite+pysqlcipher:///")
        elif database_url.startswith("sqlite://"):
            database_url = database_url.replace("sqlite://", "sqlite+pysqlcipher://")

    engine = create_engine(database_url, connect_args=connect_args)

    if settings.sqlcipher_key:

        @event.listens_for(engine, "connect")
        def set_sqlcipher_key(dbapi_connection, _):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA key = '{}';".format(settings.sqlcipher_key))
            cursor.execute("PRAGMA cipher_page_size = 4096;")
            cursor.close()

    return engine


engine = _build_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (
        Index("ix_scans_created_at", "created_at"),
        Index("ix_scans_status", "status"),
        Index("ix_scans_deleted_at", "deleted_at"),
        Index("ix_scans_subject_id", "data_subject_id"),
    )

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String(255), nullable=False)
    scan_type = Column(String(50), nullable=False)
    status = Column(String(30), nullable=False, default="queued")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    completed_at = Column(DateTime, nullable=True)
    deleted_at = Column(DateTime, nullable=True)
    findings_json = Column(Text, nullable=True)
    report_path = Column(String(255), nullable=True)
    progress = Column(Integer, nullable=False, default=0)
    priority = Column(Integer, nullable=False, default=5)
    celery_task_id = Column(String(255), nullable=True)
    child_task_ids_json = Column(Text, nullable=True)
    total_scanners = Column(Integer, nullable=True)
    completed_scanners = Column(Integer, nullable=True)
    logs_json = Column(Text, nullable=True)
    notifications_json = Column(Text, nullable=True)
    data_subject_id = Column(String(64), nullable=True)
    data_classification = Column(String(40), nullable=False, default="internal")
    # B9 – scan stats & redirect tracking
    tests_performed = Column(Integer, nullable=True)
    urls_spidered = Column(Integer, nullable=True)
    injection_points = Column(Integer, nullable=True)
    http_requests_total = Column(Integer, nullable=True)
    avg_response_time_ms = Column(Float, nullable=True)
    redirect_from = Column(String(512), nullable=True)


class ConsentRecord(Base):
    __tablename__ = "consent_records"
    __table_args__ = (
        Index("ix_consent_subject_type", "subject_id", "consent_type"),
        Index("ix_consent_accepted_at", "accepted_at"),
    )

    id = Column(Integer, primary_key=True, index=True)
    subject_id = Column(String(64), nullable=False)
    consent_type = Column(String(40), nullable=False)
    version = Column(String(40), nullable=False)
    accepted_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(255), nullable=True)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_event", "event"),
        Index("ix_audit_subject", "subject_id"),
        Index("ix_audit_created_at", "created_at"),
    )

    id = Column(Integer, primary_key=True, index=True)
    event = Column(String(80), nullable=False)
    subject_id = Column(String(64), nullable=True)
    actor = Column(String(120), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(255), nullable=True)
    metadata_json = Column(Text, nullable=True)


class LearningFeedback(Base):
    __tablename__ = "learning_feedback"
    __table_args__ = (
        Index("ix_learning_feedback_created_at", "created_at"),
        Index("ix_learning_feedback_scan_type", "scan_type"),
        Index("ix_learning_feedback_rating", "rating"),
    )

    id = Column(Integer, primary_key=True, index=True)
    scan_type = Column(String(50), nullable=False)
    target_experience_level = Column(String(20), nullable=False)
    rating = Column(Integer, nullable=False)
    clarity_score = Column(Integer, nullable=False)
    confidence_after_scan = Column(Integer, nullable=False)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)


class LearningPathProgress(Base):
    __tablename__ = "learning_path_progress"
    __table_args__ = (
        Index("ix_learning_path_progress_subject_path", "subject_id", "path_id"),
        Index("ix_learning_path_progress_subject_completed", "subject_id", "is_completed"),
        Index("ix_learning_path_progress_updated_at", "updated_at"),
    )

    id = Column(Integer, primary_key=True, index=True)
    subject_id = Column(String(64), nullable=False)
    path_id = Column(String(80), nullable=False)
    completed_modules = Column(Integer, nullable=False, default=0)
    total_modules = Column(Integer, nullable=False, default=0)
    is_completed = Column(Integer, nullable=False, default=0)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

_B9_MIGRATIONS = [
    ("tests_performed", "INTEGER"),
    ("urls_spidered", "INTEGER"),
    ("injection_points", "INTEGER"),
    ("http_requests_total", "INTEGER"),
    ("avg_response_time_ms", "REAL"),
    ("redirect_from", "VARCHAR(512)"),
]


def _migrate_scans_table(conn) -> None:
    """Add B9 columns to an existing scans table (idempotent)."""
    inspector = inspect(conn)
    existing = {col["name"] for col in inspector.get_columns("scans")}
    for col_name, col_type in _B9_MIGRATIONS:
        if col_name not in existing:
            conn.execute(text(f"ALTER TABLE scans ADD COLUMN {col_name} {col_type}"))


def _run_alembic_upgrade() -> bool:
    alembic_ini = Path(__file__).resolve().parent / "alembic.ini"
    if not alembic_ini.exists():
        return False

    try:
        from alembic import command
        from alembic.config import Config
    except ImportError:
        return False

    alembic_cfg = Config(str(alembic_ini))
    alembic_cfg.set_main_option("sqlalchemy.url", settings.database_url)
    alembic_cfg.set_main_option("script_location", str((Path(__file__).resolve().parent / "db_migrations").resolve()))
    command.upgrade(alembic_cfg, "head")
    return True


def init_db() -> None:
    migrated = _run_alembic_upgrade()

    if not migrated:
        Base.metadata.create_all(bind=engine)

    with engine.begin() as conn:
        _migrate_scans_table(conn)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
