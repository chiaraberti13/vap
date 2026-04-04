import re

from fastapi.testclient import TestClient

import app
from database import AuditEvent, LearningFeedback, Scan, SessionLocal, init_db


def _clear_scans() -> None:
    init_db()
    with SessionLocal() as session:
        session.query(Scan).delete()
        session.query(AuditEvent).delete()
        session.query(LearningFeedback).delete()
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
    assert 'id="scan-detail-config"' in response.text
    assert '<script src="/static/js/scan-detail.js"></script>' in response.text


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


def test_homepage_guided_explorer_exposes_top3_poc_scan_cards():
    """Verifica POC Sprint 1: homepage guidata contiene i 3 scan type principali."""
    _clear_scans()

    with TestClient(app.app) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert "Scan Type Explorer" in response.text
    assert "Full Stack Assessment" in response.text
    assert "Light Baseline Scan" in response.text
    assert "WordPress Focused Assessment" in response.text

    payload_match = re.search(
        r'<script id="scan-catalog-json" type="application/json">(.*?)</script>',
        response.text,
        re.DOTALL,
    )
    assert payload_match is not None
    payload = payload_match.group(1)
    assert '"id": "full"' in payload
    assert '"id": "light"' in payload
    assert '"id": "wordpress"' in payload


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


def test_list_audit_events_returns_sensitive_actions_only_by_default():
    _clear_scans()
    app.app.dependency_overrides[app.enforce_api_key] = lambda: None
    app.app.dependency_overrides[app.enforce_admin_role] = lambda: "admin"

    with SessionLocal() as session:
        session.add_all(
            [
                AuditEvent(event="gdpr_export", subject_id="subject-1", actor="jwt:admin"),
                AuditEvent(event="scan_canceled", subject_id="subject-1", actor="jwt:admin"),
            ]
        )
        session.commit()

    with TestClient(app.app) as client:
        response = client.get("/api/v1/audit/events")

    assert response.status_code == 200
    payload = response.json()
    assert len(payload) == 1
    assert payload[0]["event"] == "gdpr_export"
    app.app.dependency_overrides.clear()


def test_list_audit_events_include_all_supports_event_filter():
    _clear_scans()
    app.app.dependency_overrides[app.enforce_api_key] = lambda: None
    app.app.dependency_overrides[app.enforce_admin_role] = lambda: "admin"

    with SessionLocal() as session:
        session.add_all(
            [
                AuditEvent(event="gdpr_export", subject_id="subject-1", actor="jwt:admin"),
                AuditEvent(event="scan_canceled", subject_id="subject-2", actor="jwt:admin"),
            ]
        )
        session.commit()

    with TestClient(app.app) as client:
        response = client.get("/api/v1/audit/events?include_all_events=true&event=scan_canceled")

    assert response.status_code == 200
    payload = response.json()
    assert len(payload) == 1
    assert payload[0]["event"] == "scan_canceled"
    assert payload[0]["subject_id"] == "subject-2"
    app.app.dependency_overrides.clear()


def test_guided_scan_form_end_to_end_journey(monkeypatch):
    """Copre il journey guidato: homepage -> submit form -> redirect dettaglio scansione."""
    _clear_scans()
    app.app.dependency_overrides[app.enforce_api_key_form_dependency] = lambda: None

    class DummyResult:
        id = "dummy-task-e2e"

    def fake_apply_async(*_args, **_kwargs):
        return DummyResult()

    monkeypatch.setattr(app.orchestrate_scan, "apply_async", fake_apply_async)

    with TestClient(app.app) as client:
        homepage = client.get("/")
        assert homepage.status_code == 200

        csrf_cookie = client.cookies.get(app.settings.csrf_cookie_name)
        assert csrf_cookie

        create_response = client.post(
            "/scans",
            data={
                "target": "https://example.com",
                "learning_goal": "baseline",
                "scan_type": "wordpress",
                "priority": "7",
                "data_classification": "internal",
                "accept_privacy": "on",
                "accept_terms": "on",
                "csrf_token": csrf_cookie,
            },
            follow_redirects=False,
        )

        assert create_response.status_code == 303
        detail_url = create_response.headers["location"]
        assert detail_url.startswith("/scans/")

        detail = client.get(detail_url)
        assert detail.status_code == 200
        assert "Learning sidebar" in detail.text
        assert "WORDPRESS" in detail.text

    with SessionLocal() as session:
        saved_scan = session.query(Scan).filter(Scan.target == "https://example.com").first()
        assert saved_scan is not None
        assert saved_scan.scan_type == "wordpress"
        assert saved_scan.priority == 7

    app.app.dependency_overrides.clear()


def test_submit_learning_feedback_persists_and_normalizes_notes():
    _clear_scans()
    app.app.dependency_overrides[app.enforce_api_key] = lambda: None
    app.app.dependency_overrides[app.enforce_viewer_role] = lambda: "viewer"

    with TestClient(app.app) as client:
        response = client.post(
            "/api/v1/learning-feedback",
            json={
                "scan_type": "FULL",
                "target_experience_level": "beginner",
                "rating": 5,
                "clarity_score": 4,
                "confidence_after_scan": 4,
                "notes": "  ottima   guida   passo-passo  ",
            },
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["scan_type"] == "full"
    assert payload["notes"] == "ottima guida passo-passo"
    assert payload["rating"] == 5

    with SessionLocal() as session:
        saved = session.query(LearningFeedback).filter(LearningFeedback.id == payload["id"]).one_or_none()
        assert saved is not None
        assert saved.target_experience_level == "beginner"
        assert saved.clarity_score == 4

    app.app.dependency_overrides.clear()


def test_submit_learning_feedback_rejects_unknown_scan_type():
    _clear_scans()
    app.app.dependency_overrides[app.enforce_api_key] = lambda: None
    app.app.dependency_overrides[app.enforce_viewer_role] = lambda: "viewer"

    with TestClient(app.app) as client:
        response = client.post(
            "/api/v1/learning-feedback",
            json={
                "scan_type": "unknown_type",
                "target_experience_level": "beginner",
                "rating": 3,
                "clarity_score": 3,
                "confidence_after_scan": 2,
            },
        )

    assert response.status_code == 400
    assert "catalogo didattico" in response.json()["detail"]
    app.app.dependency_overrides.clear()


def test_auth_token_endpoint_enforces_rate_limit(monkeypatch):
    """
    Regression security test: simula un brute-force burst su /auth/token
    e verifica che il rate-limit applicativo risponda con HTTP 429.
    """
    _clear_scans()
    app.limiter._storage.reset()
    original_settings = app.settings
    monkeypatch.setattr(
        app,
        "settings",
        type(
            "S",
            (),
            {
                **original_settings.__dict__,
                "jwt_secret": "a" * 32,
                "jwt_demo_user": "admin",
                "jwt_demo_password": "change-me",
            },
        )(),
    )

    with TestClient(app.app) as client:
        status_codes = []
        for _ in range(16):
            response = client.post(
                "/auth/token",
                data={"username": "admin", "password": "wrong-password"},
            )
            status_codes.append(response.status_code)

    assert all(code in {401, 429} for code in status_codes)
    assert 429 in status_codes
