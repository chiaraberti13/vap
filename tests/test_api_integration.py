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
    app.app.dependency_overrides[app.enforce_viewer_role] = lambda: "viewer"

    with TestClient(app.app) as client:
        response = client.get("/api/v1/scans")

    assert response.status_code == 200
    assert response.json() == []
    app.app.dependency_overrides.clear()


def test_create_scan(monkeypatch):
    _clear_scans()
    app.app.dependency_overrides[app.enforce_api_key] = lambda: None
    app.app.dependency_overrides[app.enforce_operator_role] = lambda: "operator"

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


def test_issue_token_returns_503_if_demo_credentials_not_configured(monkeypatch):
    app.app.dependency_overrides[app.get_db] = lambda: iter([SessionLocal()])
    monkeypatch.setattr(
        app,
        "settings",
        type("S", (), {**app.settings.__dict__, "jwt_secret": "secret", "jwt_demo_user": "", "jwt_demo_password": ""})(),
    )

    with TestClient(app.app) as client:
        response = client.post("/auth/token", data={"username": "admin", "password": "change-me"})

    assert response.status_code == 503
    app.app.dependency_overrides.clear()


def test_scan_detail_displays_learning_sidebar():
    _clear_scans()
    with SessionLocal() as session:
        scan = Scan(
            target="example.com",
            scan_type="full",
            status="running",
            data_classification="internal",
            logs_json="[]",
            findings_json="[]",
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)
        scan_id = scan.id

    with TestClient(app.app) as client:
        response = client.get(f"/scans/{scan_id}")

    assert response.status_code == 200
    assert "Learning sidebar" in response.text
    assert "Comprendere una valutazione completa multi-tool end-to-end." in response.text


def test_homepage_uses_legacy_form_when_guided_explorer_flag_is_disabled(monkeypatch):
    _clear_scans()
    monkeypatch.setattr(
        app,
        "settings",
        type(
            "S",
            (),
            {**app.settings.__dict__, "ui_guided_scan_explorer_enabled": False},
        )(),
    )

    with TestClient(app.app) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert "Scan Type Explorer" not in response.text
    assert 'name="scan_type"' in response.text


def test_list_scans_forbidden_for_role_not_allowed():
    _clear_scans()
    app.app.dependency_overrides[app.enforce_api_key] = lambda: None
    app.app.dependency_overrides[app.enforce_viewer_role] = lambda: (_ for _ in ()).throw(
        app.HTTPException(status_code=403, detail="Permessi insufficienti per questa operazione")
    )

    with TestClient(app.app) as client:
        response = client.get("/api/v1/scans")

    assert response.status_code == 403
    app.app.dependency_overrides.clear()


def test_create_scan_forbidden_for_viewer_role():
    _clear_scans()
    app.app.dependency_overrides[app.enforce_api_key] = lambda: None
    app.app.dependency_overrides[app.enforce_operator_role] = lambda: (_ for _ in ()).throw(
        app.HTTPException(status_code=403, detail="Permessi insufficienti per questa operazione")
    )

    with TestClient(app.app) as client:
        response = client.post(
            "/api/v1/scans",
            json={"target": "example.com", "scan_type": "full", "priority": 3, "accept_privacy": True, "accept_terms": True},
        )

    assert response.status_code == 403
    app.app.dependency_overrides.clear()
