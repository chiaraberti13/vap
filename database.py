#!/usr/bin/env python3
"""
Database layer basata su SQLAlchemy.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Generator

from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine, event
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

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String(255), nullable=False)
    scan_type = Column(String(50), nullable=False)
    status = Column(String(30), nullable=False, default="queued")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    completed_at = Column(DateTime, nullable=True)
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


def init_db() -> None:
    Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
