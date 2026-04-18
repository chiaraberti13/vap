from pathlib import Path
import sys

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
