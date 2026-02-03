#!/usr/bin/env python3
"""
Database layer basata su SQLAlchemy.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Generator

from sqlalchemy import Column, DateTime, Index, Integer, String, Text, create_engine, event
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from config import settings

Base = declarative_base()


def _build_engine():
    database_url = settings.database_url
    connect_args = {
        "check_same_thread": False
    } if database_url.startswith("sqlite") else {}
    if settings.sqlcipher_key:
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


def init_db() -> None:
    Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
