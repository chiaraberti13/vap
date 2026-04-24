from datetime import datetime, timezone
from types import SimpleNamespace

import compliance
from config import settings
from database import AuditEvent, ConsentRecord, Scan, SessionLocal
from conftest import clear_persistent_state


def _build_request(headers=None, session=None, query_params=None):
    return SimpleNamespace(
        headers=headers or {},
        session=session if session is not None else {},
        query_params=query_params or {},
        client=SimpleNamespace(host="127.0.0.1"),
    )


def test_get_subject_id_uses_header_value_when_present():
    request = _build_request(headers={"x-data-subject": "subject-from-header"}, session={"subject_id": "session-subject"})

    subject_id = compliance.get_subject_id(request)

    assert subject_id == "subject-from-header"
    assert request.session["subject_id"] == "session-subject"


def test_get_subject_id_generates_and_persists_subject_when_missing():
    request = _build_request()

    subject_id = compliance.get_subject_id(request)

    assert subject_id
    assert request.session["subject_id"] == subject_id


def test_resolve_actor_prioritizes_actor_header_over_other_auth_paths(monkeypatch):
    monkeypatch.setattr(compliance, "verify_jwt_token", lambda _token: {"sub": "jwt-user"})
    request = _build_request(
        headers={
            "x-actor-id": "admin:explicit",
            "Authorization": "Bearer valid-token",
            "x-api-key": "api-key-value",
        }
    )

    actor = compliance.resolve_actor(request)

    assert actor == "admin:explicit"


def test_resolve_actor_uses_session_subject_when_no_credentials_available():
    request = _build_request(session={"subject_id": "session-subject-1"})

    actor = compliance.resolve_actor(request)

    assert actor == "session:session-subject-1"


def test_record_consent_and_has_required_consents_for_current_versions():
    clear_persistent_state()
    request = _build_request(headers={"user-agent": "pytest-consent"})
    subject_id = "subject-consent-1"

    with SessionLocal() as session:
        assert compliance.has_required_consents(session, subject_id) is False

        compliance.record_consent(
            db=session,
            request=request,
            subject_id=subject_id,
            consent_type="privacy_policy",
            version=settings.privacy_policy_version,
        )
        assert compliance.has_required_consents(session, subject_id) is False

        compliance.record_consent(
            db=session,
            request=request,
            subject_id=subject_id,
            consent_type="terms_of_service",
            version=settings.terms_of_service_version,
        )
        assert compliance.has_required_consents(session, subject_id) is True

        stored_consents = (
            session.query(ConsentRecord)
            .filter(ConsentRecord.subject_id == subject_id)
            .order_by(ConsentRecord.id.asc())
            .all()
        )

    assert len(stored_consents) == 2
    assert all(consent.user_agent == "pytest-consent" for consent in stored_consents)


def test_record_audit_event_redacts_sensitive_metadata_before_persisting():
    clear_persistent_state()
    request = _build_request(
        headers={
            "x-api-key": "api-key-in-clear",
            "user-agent": "pytest-audit",
        }
    )

    with SessionLocal() as session:
        event = compliance.record_audit_event(
            db=session,
            request=request,
            event="scan.created",
            subject_id="subject-audit-1",
            metadata={"authorization": "Bearer secret", "note": "safe"},
        )
        reloaded = session.query(AuditEvent).filter(AuditEvent.id == event.id).one()

    assert '"authorization": "<redacted>"' in reloaded.metadata_json
    assert '"note": "safe"' in reloaded.metadata_json
    assert reloaded.actor.startswith("api_key:sha256:")


def test_anonymize_scan_for_export_masks_url_host_and_email_like_targets():
    scan = Scan(
        id=1,
        target="https://example.org/private/path",
        scan_type="full",
        status="completed",
        created_at=datetime(2026, 4, 24, tzinfo=timezone.utc),
        completed_at=datetime(2026, 4, 24, 1, 0, tzinfo=timezone.utc),
        data_classification="internal",
    )

    url_payload = compliance.anonymize_scan_for_export(scan)

    assert url_payload["target"] == "https://exa***"

    email_scan = Scan(
        id=2,
        target="security-team@example.org",
        scan_type="light",
        status="completed",
        created_at=datetime(2026, 4, 24, tzinfo=timezone.utc),
        completed_at=None,
        data_classification="public",
    )

    email_payload = compliance.anonymize_scan_for_export(email_scan)

    assert email_payload["target"] == "example.org"
