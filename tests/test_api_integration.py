import json
import re

from fastapi.testclient import TestClient

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


def _clear_scans() -> None:
    init_db()
    with SessionLocal() as session:
        session.query(Scan).delete()
        session.query(AuditEvent).delete()
        session.query(LearningFeedback).delete()
        session.query(LearningPathProgress).delete()
        session.query(ScanConfigurationPreset).delete()
        session.commit()




def test_download_report_endpoint_preserves_pdf_delivery_and_audit(tmp_path):
    _clear_scans()
    report_file = tmp_path / "scan-report.pdf"
    report_file.write_bytes(b"%PDF-1.4\n% regression fixture\n")

    with SessionLocal() as session:
        scan = Scan(
            target="example.com",
            scan_type="full",
            status="completed",
            report_path=str(report_file),
            data_classification="internal",
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)
        scan_id = scan.id

    app.app.dependency_overrides[app.enforce_api_key] = lambda: None
    app.app.dependency_overrides[app.enforce_viewer_role] = lambda: "viewer"

    with TestClient(app.app) as client:
        response = client.get(f"/api/v1/scans/{scan_id}/report/download")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/pdf")
    assert response.content.startswith(b"%PDF-1.4")

    with SessionLocal() as session:
        audit_event = session.query(AuditEvent).filter(AuditEvent.event == "report_downloaded").order_by(AuditEvent.id.desc()).first()

    assert audit_event is not None
    metadata = json.loads(audit_event.metadata_json or "{}")
    assert metadata["scan_id"] == scan_id
    app.app.dependency_overrides.clear()

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
    app.app.dependency_overrides[app.enforce_operator_role] = lambda: "admin"

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


def test_scan_configuration_snapshot_is_persisted_and_retrievable(monkeypatch):
    _clear_scans()
    app.app.dependency_overrides[app.enforce_api_key] = lambda: None
    app.app.dependency_overrides[app.enforce_operator_role] = lambda: "operator"
    app.app.dependency_overrides[app.enforce_viewer_role] = lambda: "viewer"

    class DummyResult:
        id = "dummy-task"

    def fake_apply_async(*_args, **_kwargs):
        return DummyResult()

    monkeypatch.setattr(app.orchestrate_scan, "apply_async", fake_apply_async)

    with TestClient(app.app) as client:
        create_response = client.post(
            "/api/v1/scans",
            json={
                "target": "example.com",
                "scan_type": "full",
                "priority": 3,
                "accept_privacy": True,
                "accept_terms": True,
                    "scan_configuration": {
                        "crawler": {"enabled": True, "max_depth": 2},
                        "runtime": {"requests_per_minute": 80, "max_concurrency": 3, "request_timeout_seconds": 20},
                    },
                },
            )
        assert create_response.status_code == 200
        scan_id = create_response.json()["id"]

        snapshot_response = client.get(f"/api/v1/scans/{scan_id}/configuration")

    assert snapshot_response.status_code == 200
    snapshot_payload = snapshot_response.json()
    assert snapshot_payload["schema_version"] == "scan-config/v1"
    assert re.match(r"^[a-f0-9]{64}$", snapshot_payload["checksum"])
    assert snapshot_payload["configuration"]["crawler"]["max_depth"] == 2
    assert snapshot_payload["configuration"]["runtime"]["requests_per_minute"] == 80
    app.app.dependency_overrides.clear()


def test_create_scan_rejects_unknown_scan_configuration_fields(monkeypatch):
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
            json={
                "target": "example.com",
                "scan_type": "full",
                "priority": 3,
                "accept_privacy": True,
                "accept_terms": True,
                "scan_configuration": {"unexpected_field": True},
            },
        )

    assert response.status_code == 422
    app.app.dependency_overrides.clear()


def test_get_scan_catalog_endpoint():
    _clear_scans()
    app.app.dependency_overrides[app.enforce_api_key] = lambda: None
    app.app.dependency_overrides[app.enforce_viewer_role] = lambda: "viewer"

    with TestClient(app.app) as client:
        response = client.get("/api/v1/scan-catalog")

    assert response.status_code == 200
    payload = response.json()
    assert isinstance(payload, list)
    assert any(entry["id"] == "full" for entry in payload)
    assert any(entry["id"] == "light" for entry in payload)
    assert any(entry["id"] == "wordpress" for entry in payload)
    app.app.dependency_overrides.clear()


def test_get_scan_config_schema_endpoint():
    _clear_scans()
    app.app.dependency_overrides[app.enforce_api_key] = lambda: None
    app.app.dependency_overrides[app.enforce_viewer_role] = lambda: "viewer"

    with TestClient(app.app) as client:
        response = client.get("/api/v1/scan-config/schema")

    assert response.status_code == 200
    payload = response.json()
    assert payload["title"] == "ScanConfigurationV1"
    assert payload["properties"]["schema_version"]["default"] == "scan-config/v1"
    assert "runtime" in payload["properties"]
    app.app.dependency_overrides.clear()

def test_scan_configuration_preset_crud_and_subject_isolation():
    _clear_scans()
    app.app.dependency_overrides[app.enforce_api_key] = lambda: None
    app.app.dependency_overrides[app.enforce_operator_role] = lambda: "operator"
    app.app.dependency_overrides[app.enforce_viewer_role] = lambda: "viewer"

    with TestClient(app.app) as client:
        create_response = client.post(
            "/api/v1/scan-config/presets",
            json={
                "name": "Baseline didattica",
                "description": "Preset con limiti conservativi",
                "scan_type": "full",
                "configuration": {
                    "runtime": {"requests_per_minute": 45, "max_concurrency": 2, "request_timeout_seconds": 25},
                    "crawler": {"enabled": True, "max_depth": 1},
                },
            },
            cookies={app.settings.csrf_cookie_name: "tkn"},
            headers={"x-csrf-token": "tkn", "x-data-subject": "student-alpha"},
        )
        assert create_response.status_code == 200
        created_payload = create_response.json()
        preset_id = created_payload["id"]
        assert created_payload["scan_type"] == "full"
        assert created_payload["configuration"]["crawler"]["max_depth"] == 1

        list_response = client.get(
            "/api/v1/scan-config/presets",
            headers={"x-data-subject": "student-alpha"},
        )
        assert list_response.status_code == 200
        listed = list_response.json()
        assert len(listed) == 1
        assert listed[0]["id"] == preset_id
        assert listed[0]["name"] == "Baseline didattica"

        unauthorized_delete = client.delete(
            f"/api/v1/scan-config/presets/{preset_id}",
            cookies={app.settings.csrf_cookie_name: "tkn2"},
            headers={"x-csrf-token": "tkn2", "x-data-subject": "student-beta"},
        )
        assert unauthorized_delete.status_code == 404

        delete_response = client.delete(
            f"/api/v1/scan-config/presets/{preset_id}",
            cookies={app.settings.csrf_cookie_name: "tkn3"},
            headers={"x-csrf-token": "tkn3", "x-data-subject": "student-alpha"},
        )
        assert delete_response.status_code == 204

    app.app.dependency_overrides.clear()


def test_create_scan_rejects_tampered_scan_type(monkeypatch):
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
            json={"target": "example.com", "scan_type": "evilscan", "priority": 3, "accept_privacy": True, "accept_terms": True},
        )

    assert response.status_code == 400
    assert response.json()["detail"] == "Tipologia di scansione non valida."
    app.app.dependency_overrides.clear()


def test_create_scan_rejects_mutually_exclusive_tool_overrides(monkeypatch):
    _clear_scans()
    app.app.dependency_overrides[app.enforce_api_key] = lambda: None
    app.app.dependency_overrides[app.enforce_operator_role] = lambda: "admin"

    class DummyResult:
        id = "dummy-task"

    def fake_apply_async(*_args, **_kwargs):
        return DummyResult()

    monkeypatch.setattr(app.orchestrate_scan, "apply_async", fake_apply_async)

    with TestClient(app.app) as client:
        response = client.post(
            "/api/v1/scans",
            json={
                "target": "example.com",
                "scan_type": "full",
                "priority": 3,
                "accept_privacy": True,
                "accept_terms": True,
                "scan_configuration": {
                    "tool_overrides": {
                        "zap": {"enabled": True},
                        "burp": {"enabled": True},
                    }
                },
            },
        )

    assert response.status_code == 400
    assert "non possono essere abilitati insieme" in response.json()["detail"]
    app.app.dependency_overrides.clear()


def test_create_scan_rejects_high_risk_tool_without_admin_role(monkeypatch):
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
            json={
                "target": "example.com",
                "scan_type": "full",
                "priority": 3,
                "accept_privacy": True,
                "accept_terms": True,
                "scan_configuration": {
                    "tool_overrides": {"sqlmap": {"enabled": True}}
                },
            },
        )

    assert response.status_code == 400
    assert "richiedono ruolo admin" in response.json()["detail"]
    app.app.dependency_overrides.clear()


def test_create_scan_rejects_tool_not_compatible_with_scan_type(monkeypatch):
    _clear_scans()
    app.app.dependency_overrides[app.enforce_api_key] = lambda: None
    app.app.dependency_overrides[app.enforce_operator_role] = lambda: "admin"

    class DummyResult:
        id = "dummy-task"

    def fake_apply_async(*_args, **_kwargs):
        return DummyResult()

    monkeypatch.setattr(app.orchestrate_scan, "apply_async", fake_apply_async)

    with TestClient(app.app) as client:
        response = client.post(
            "/api/v1/scans",
            json={
                "target": "example.com",
                "scan_type": "light",
                "priority": 3,
                "accept_privacy": True,
                "accept_terms": True,
                "scan_configuration": {
                    "tool_overrides": {"sqlmap": {"enabled": True}}
                },
            },
        )

    assert response.status_code == 400
    assert "non sono compatibili" in response.json()["detail"]
    app.app.dependency_overrides.clear()


def test_create_scan_rejects_disabled_crawler_with_depth(monkeypatch):
    _clear_scans()
    app.app.dependency_overrides[app.enforce_api_key] = lambda: None
    app.app.dependency_overrides[app.enforce_operator_role] = lambda: "admin"

    class DummyResult:
        id = "dummy-task"

    def fake_apply_async(*_args, **_kwargs):
        return DummyResult()

    monkeypatch.setattr(app.orchestrate_scan, "apply_async", fake_apply_async)

    with TestClient(app.app) as client:
        response = client.post(
            "/api/v1/scans",
            json={
                "target": "example.com",
                "scan_type": "full",
                "priority": 3,
                "accept_privacy": True,
                "accept_terms": True,
                "scan_configuration": {"crawler": {"enabled": False, "max_depth": 2}},
            },
        )

    assert response.status_code == 400
    assert "Crawler disabilitato" in response.json()["detail"]
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


def test_scan_detail_displays_trend_summary_with_previous_baseline():
    _clear_scans()
    with SessionLocal() as session:
        baseline = Scan(
            target="example.com",
            scan_type="full",
            status="completed",
            data_classification="internal",
            findings_json='[{"title":"Legacy issue","severity":"high","confidence":0.9},{"title":"Minor","severity":"low","confidence":0.5}]',
            logs_json="[]",
        )
        current = Scan(
            target="example.com",
            scan_type="full",
            status="completed",
            data_classification="internal",
            findings_json='[{"title":"Current issue","severity":"critical","confidence":0.95}]',
            logs_json="[]",
        )
        session.add_all([baseline, current])
        session.commit()
        session.refresh(current)
        scan_id = current.id

    with TestClient(app.app) as client:
        response = client.get(f"/scans/{scan_id}")

    assert response.status_code == 200
    assert "Trend report (target)" in response.text
    assert "Delta findings" in response.text
    assert "Delta critici/alti" in response.text
    assert "Nessuna baseline precedente disponibile" not in response.text


def test_scan_detail_trend_summary_handles_missing_baseline_gracefully():
    _clear_scans()
    with SessionLocal() as session:
        current = Scan(
            target="new-target.example",
            scan_type="light",
            status="completed",
            data_classification="internal",
            findings_json='[{"title":"Only finding","severity":"medium","confidence":0.7}]',
            logs_json="[]",
        )
        session.add(current)
        session.commit()
        session.refresh(current)
        scan_id = current.id

    with TestClient(app.app) as client:
        response = client.get(f"/scans/{scan_id}")

    assert response.status_code == 200
    assert "Trend report (target)" in response.text
    assert "Nessuna baseline precedente disponibile" in response.text


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
                "scope_acknowledged": "on",
                "scope_reference": "CAB-2026-041",
                "run_compliance_acknowledged": "on",
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


def test_guided_scan_form_blocks_submission_without_required_consents(monkeypatch):
    """Journey negativo: il form guidato deve bloccare run senza consensi obbligatori."""
    _clear_scans()
    app.app.dependency_overrides[app.enforce_api_key_form_dependency] = lambda: None

    class DummyResult:
        id = "dummy-task-should-not-run"

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
                "target": "https://consent-missing.example",
                "learning_goal": "baseline",
                "scope_acknowledged": "on",
                "run_compliance_acknowledged": "on",
                "scan_type": "full",
                "priority": "5",
                "data_classification": "internal",
                "accept_privacy": "on",
                # accept_terms volontariamente assente.
                "csrf_token": csrf_cookie,
            },
        )

    assert create_response.status_code == 403
    assert "Accetta privacy policy e termini di servizio per procedere." in create_response.text

    with SessionLocal() as session:
        blocked_scan = session.query(Scan).filter(Scan.target == "https://consent-missing.example").first()
        assert blocked_scan is None

    app.app.dependency_overrides.clear()


def test_guided_scan_form_blocks_submission_without_scope_acknowledgement(monkeypatch):
    """Step 1 negativo: senza conferma scope legale il server deve bloccare la creazione scan."""
    _clear_scans()
    app.app.dependency_overrides[app.enforce_api_key_form_dependency] = lambda: None

    class DummyResult:
        id = "dummy-task-should-not-run"

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
                "target": "https://scope-missing.example",
                "learning_goal": "baseline",
                "scan_type": "light",
                "priority": "5",
                "data_classification": "internal",
                "accept_privacy": "on",
                "accept_terms": "on",
                "csrf_token": csrf_cookie,
            },
        )

    assert create_response.status_code == 400
    assert "perimetro legale autorizzato" in create_response.text

    with SessionLocal() as session:
        blocked_scan = session.query(Scan).filter(Scan.target == "https://scope-missing.example").first()
        assert blocked_scan is None

    app.app.dependency_overrides.clear()


def test_guided_scan_form_blocks_incompatible_module_selection(monkeypatch):
    """Step 2 negativo: il server deve bloccare moduli non compatibili con scan_type scelto."""
    _clear_scans()
    app.app.dependency_overrides[app.enforce_api_key_form_dependency] = lambda: None

    class DummyResult:
        id = "dummy-task-should-not-run"

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
                "target": "https://module-invalid.example",
                "learning_goal": "verification",
                "scope_acknowledged": "on",
                "run_compliance_acknowledged": "on",
                "scan_type": "light",
                "selected_modules_json": json.dumps(["sqlmap"]),
                "priority": "5",
                "data_classification": "internal",
                "accept_privacy": "on",
                "accept_terms": "on",
                "csrf_token": csrf_cookie,
            },
        )

    assert create_response.status_code == 400
    with SessionLocal() as session:
        blocked_scan = session.query(Scan).filter(Scan.target == "https://module-invalid.example").first()
        assert blocked_scan is None

    app.app.dependency_overrides.clear()


def test_guided_scan_form_blocks_submission_without_compliance_confirmation(monkeypatch):
    """Step 5 negativo: senza conferma checklist compliance il server deve bloccare la run."""
    _clear_scans()
    app.app.dependency_overrides[app.enforce_api_key_form_dependency] = lambda: None

    class DummyResult:
        id = "dummy-task-should-not-run"

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
                "target": "https://compliance-missing.example",
                "learning_goal": "verification",
                "scope_acknowledged": "on",
                "scan_type": "light",
                "priority": "5",
                "data_classification": "internal",
                "accept_privacy": "on",
                "accept_terms": "on",
                "csrf_token": csrf_cookie,
            },
        )

    assert create_response.status_code == 400
    assert "checklist compliance pre-run" in create_response.text
    with SessionLocal() as session:
        blocked_scan = session.query(Scan).filter(Scan.target == "https://compliance-missing.example").first()
        assert blocked_scan is None

    app.app.dependency_overrides.clear()


def test_guided_scan_form_persists_advanced_module_configuration(monkeypatch):
    _clear_scans()
    app.app.dependency_overrides[app.enforce_api_key_form_dependency] = lambda: None

    class DummyResult:
        id = "dummy-task-advanced-module-config"

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
                "target": "https://advanced-config.example",
                "learning_goal": "verification",
                "scope_acknowledged": "on",
                "run_compliance_acknowledged": "on",
                "scan_type": "light",
                "selected_modules_json": json.dumps(["httpx", "whatweb"]),
                "advanced_modules_json": json.dumps(
                    {
                        "httpx": {"timeout_seconds": 42, "max_payloads": 18},
                        "whatweb": {"timeout_seconds": 25, "max_payloads": 12},
                    }
                ),
                "priority": "5",
                "data_classification": "internal",
                "accept_privacy": "on",
                "accept_terms": "on",
                "csrf_token": csrf_cookie,
            },
            follow_redirects=False,
        )

    assert create_response.status_code == 303
    with SessionLocal() as session:
        saved_scan = session.query(Scan).filter(Scan.target == "https://advanced-config.example").one_or_none()
        assert saved_scan is not None
        saved_config = json.loads(saved_scan.scan_configuration_json)
        assert saved_config["tool_overrides"]["httpx"]["timeout_seconds"] == 42
        assert saved_config["tool_overrides"]["httpx"]["max_payloads"] == 18
        assert saved_config["tool_overrides"]["whatweb"]["timeout_seconds"] == 25
        assert saved_config["tool_overrides"]["whatweb"]["max_payloads"] == 12

    app.app.dependency_overrides.clear()


def test_guided_scan_form_blocks_advanced_params_for_unselected_modules(monkeypatch):
    _clear_scans()
    app.app.dependency_overrides[app.enforce_api_key_form_dependency] = lambda: None

    class DummyResult:
        id = "dummy-task-should-not-run"

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
                "target": "https://invalid-advanced-config.example",
                "learning_goal": "verification",
                "scope_acknowledged": "on",
                "run_compliance_acknowledged": "on",
                "scan_type": "light",
                "selected_modules_json": json.dumps(["httpx"]),
                "advanced_modules_json": json.dumps(
                    {"whatweb": {"timeout_seconds": 40, "max_payloads": 20}}
                ),
                "priority": "5",
                "data_classification": "internal",
                "accept_privacy": "on",
                "accept_terms": "on",
                "csrf_token": csrf_cookie,
            },
        )

    assert create_response.status_code == 400
    assert "moduli non selezionati" in create_response.text
    with SessionLocal() as session:
        blocked_scan = (
            session.query(Scan)
            .filter(Scan.target == "https://invalid-advanced-config.example")
            .one_or_none()
        )
        assert blocked_scan is None

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


def test_submit_learning_feedback_rejects_html_in_notes():
    _clear_scans()
    app.app.dependency_overrides[app.enforce_api_key] = lambda: None
    app.app.dependency_overrides[app.enforce_viewer_role] = lambda: "viewer"

    with TestClient(app.app) as client:
        response = client.post(
            "/api/v1/learning-feedback",
            json={
                "scan_type": "light",
                "target_experience_level": "beginner",
                "rating": 4,
                "clarity_score": 4,
                "confidence_after_scan": 3,
                "notes": "<script>alert('xss')</script>",
            },
        )

    assert response.status_code == 422
    assert "tag HTML" in response.json()["detail"]
    app.app.dependency_overrides.clear()


def test_submit_learning_feedback_rejects_control_chars_in_notes():
    _clear_scans()
    app.app.dependency_overrides[app.enforce_api_key] = lambda: None
    app.app.dependency_overrides[app.enforce_viewer_role] = lambda: "viewer"

    with TestClient(app.app) as client:
        response = client.post(
            "/api/v1/learning-feedback",
            json={
                "scan_type": "light",
                "target_experience_level": "beginner",
                "rating": 4,
                "clarity_score": 4,
                "confidence_after_scan": 3,
                "notes": "nota valida\u0007con controllo",
            },
        )

    assert response.status_code == 422
    assert "caratteri di controllo" in response.json()["detail"]
    app.app.dependency_overrides.clear()


def test_upsert_learning_progress_and_list_returns_subject_rows():
    _clear_scans()
    app.app.dependency_overrides[app.enforce_api_key] = lambda: None
    app.app.dependency_overrides[app.enforce_viewer_role] = lambda: "viewer"

    with TestClient(app.app) as client:
        create_response = client.post(
            "/api/v1/learning-progress",
            json={"path_id": "beginner-path", "completed_modules": 2, "total_modules": 5},
        )
        assert create_response.status_code == 200
        created_payload = create_response.json()
        assert created_payload["path_id"] == "beginner-path"
        assert created_payload["completion_ratio"] == 0.4
        assert created_payload["is_completed"] is False

        list_response = client.get("/api/v1/learning-progress")

    assert list_response.status_code == 200
    listed_payload = list_response.json()
    assert len(listed_payload) == 1
    assert listed_payload[0]["path_id"] == "beginner-path"
    assert listed_payload[0]["completed_modules"] == 2
    assert listed_payload[0]["total_modules"] == 5
    app.app.dependency_overrides.clear()


def test_learning_progress_rejects_completed_modules_over_total():
    _clear_scans()
    app.app.dependency_overrides[app.enforce_api_key] = lambda: None
    app.app.dependency_overrides[app.enforce_viewer_role] = lambda: "viewer"

    with TestClient(app.app) as client:
        response = client.post(
            "/api/v1/learning-progress",
            json={"path_id": "beginner-path", "completed_modules": 6, "total_modules": 5},
        )

    assert response.status_code == 422
    assert "non può superare" in response.json()["detail"]
    app.app.dependency_overrides.clear()


def test_learning_progress_rejects_invalid_path_id():
    _clear_scans()
    app.app.dependency_overrides[app.enforce_api_key] = lambda: None
    app.app.dependency_overrides[app.enforce_viewer_role] = lambda: "viewer"

    with TestClient(app.app) as client:
        response = client.post(
            "/api/v1/learning-progress",
            json={"path_id": "!!", "completed_modules": 1, "total_modules": 5},
        )

    assert response.status_code == 422
    assert response.json()["detail"] == "path_id non valido."
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


def test_create_scan_rejects_when_kill_switch_enabled(monkeypatch):
    _clear_scans()
    app.app.dependency_overrides[app.enforce_api_key] = lambda: None
    app.app.dependency_overrides[app.enforce_operator_role] = lambda: "admin"

    class DummyResult:
        id = "dummy-task"

    def fake_apply_async(*_args, **_kwargs):
        return DummyResult()

    monkeypatch.setattr(app.orchestrate_scan, "apply_async", fake_apply_async)
    monkeypatch.setattr(
        app,
        "settings",
        type("S", (), {**app.settings.__dict__, "scan_kill_switch_enabled": True})(),
    )

    with TestClient(app.app) as client:
        response = client.post(
            "/api/v1/scans",
            json={
                "target": "example.com",
                "scan_type": "full",
                "priority": 3,
                "accept_privacy": True,
                "accept_terms": True,
            },
        )

    assert response.status_code == 400
    assert "Kill switch attivo" in response.json()["detail"]
    app.app.dependency_overrides.clear()


def test_create_scan_enforces_safe_mode_for_non_admin(monkeypatch):
    _clear_scans()
    app.app.dependency_overrides[app.enforce_api_key] = lambda: None
    app.app.dependency_overrides[app.enforce_operator_role] = lambda: "operator"

    class DummyResult:
        id = "dummy-task"

    def fake_apply_async(*_args, **_kwargs):
        return DummyResult()

    monkeypatch.setattr(app.orchestrate_scan, "apply_async", fake_apply_async)
    monkeypatch.setattr(
        app,
        "settings",
        type(
            "S",
            (),
            {
                **app.settings.__dict__,
                "scan_guardrails_safe_mode_max_depth": 2,
            },
        )(),
    )

    with TestClient(app.app) as client:
        response = client.post(
            "/api/v1/scans",
            json={
                "target": "example.com",
                "scan_type": "full",
                "priority": 3,
                "accept_privacy": True,
                "accept_terms": True,
                "scan_configuration": {
                    "crawler": {"enabled": True, "max_depth": 4}
                },
            },
        )

    assert response.status_code == 400
    assert "Safe mode obbligatorio" in response.json()["detail"]
    app.app.dependency_overrides.clear()
