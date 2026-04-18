from pathlib import Path
import sys
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

import app
from database import (
    AuditEvent,
    LearningFeedback,
    LearningPathProgress,
    Scan,
    ScanConfigurationPreset,
    SessionLocal,
    init_db,
)


def clear_persistent_state(include_learning_artifacts: bool = True) -> None:
    """
    Ripulisce lo stato persistente condiviso tra test.

    include_learning_artifacts=False mantiene il cleanup minimale usato dalle suite
    che non toccano direttamente preset/progress didattici.
    """
    init_db()
    with SessionLocal() as session:
        session.query(Scan).delete()
        session.query(AuditEvent).delete()
        if include_learning_artifacts:
            session.query(LearningFeedback).delete()
            session.query(LearningPathProgress).delete()
            session.query(ScanConfigurationPreset).delete()
        session.commit()


@pytest.fixture(autouse=True)
def reset_runtime_state():
    """Isola lo stato runtime tra i test API (override dependency + rate limit)."""
    app.app.dependency_overrides.clear()
    limiter_storage = getattr(app.limiter, "_storage", None)
    if limiter_storage is not None:
        limiter_storage.reset()

    yield

    app.app.dependency_overrides.clear()
    limiter_storage = getattr(app.limiter, "_storage", None)
    if limiter_storage is not None:
        limiter_storage.reset()


@pytest.fixture
def seed_scan() -> Callable[..., Scan]:
    """Factory per creare scansioni nei test UI/API riducendo boilerplate."""

    def _seed_scan(**overrides: Any) -> Scan:
        defaults = {
            "target": "example.com",
            "scan_type": "full",
            "status": "completed",
            "data_classification": "internal",
            "logs_json": "[]",
            "findings_json": "[]",
        }
        defaults.update(overrides)
        with SessionLocal() as session:
            scan = Scan(**defaults)
            session.add(scan)
            session.commit()
            session.refresh(scan)
            session.expunge(scan)
            return scan

    return _seed_scan


@pytest.fixture
def seed_audit_event() -> Callable[..., AuditEvent]:
    """Factory per creare eventi audit espliciti nei test API/analytics."""

    def _seed_audit_event(**overrides: Any) -> AuditEvent:
        defaults = {
            "event": "test_event",
            "subject_id": "test-subject",
            "actor": "session:test-subject",
            "metadata_json": "{}",
        }
        defaults.update(overrides)
        with SessionLocal() as session:
            event = AuditEvent(**defaults)
            session.add(event)
            session.commit()
            session.refresh(event)
            session.expunge(event)
            return event

    return _seed_audit_event
