#!/usr/bin/env python3
"""
Database layer basata su SQLAlchemy.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Generator

from sqlalchemy import create_engine, Column, DateTime, Integer, String, Text
from sqlalchemy.orm import declarative_base, sessionmaker, Session

from config import settings

Base = declarative_base()

engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False} if settings.database_url.startswith("sqlite") else {},
)
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


def init_db() -> None:
    Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
