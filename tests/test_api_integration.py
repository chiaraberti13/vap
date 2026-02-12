from fastapi.testclient import TestClient

import app
from database import Scan, SessionLocal, init_db


def _clear_scans() -> None:
    init_db()
    with SessionLocal() as session:
        session.query(Scan).delete()
        session.commit()


def test_list_scans_empty():
    _clear_scans()
    app.app.dependency_overrides[app.enforce_api_key] = lambda: None
    app.app.dependency_overrides[app.enforce_jwt] = lambda: None

    with TestClient(app.app) as client:
        response = client.get("/api/v1/scans")

    assert response.status_code == 200
    assert response.json() == []
    app.app.dependency_overrides.clear()


def test_create_scan(monkeypatch):
    _clear_scans()
    app.app.dependency_overrides[app.enforce_api_key] = lambda: None
    app.app.dependency_overrides[app.enforce_jwt] = lambda: None

    class DummyResult:
        id = "dummy-task"

    def fake_apply_async(*_args, **_kwargs):
        return DummyResult()

    monkeypatch.setattr(app.orchestrate_scan, "apply_async", fake_apply_async)

    with TestClient(app.app) as client:
        response = client.post(
            "/api/v1/scans",
            json={"target": "example.com", "scan_type": "full", "priority": 3, "accept_privacy": True, "accept_terms": True},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["target"] == "example.com"
    assert payload["scan_type"] == "full"
    assert payload["priority"] == 3
    app.app.dependency_overrides.clear()
