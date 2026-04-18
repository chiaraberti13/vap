from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

import app


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
