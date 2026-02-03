from fastapi.testclient import TestClient

import app


def test_security_headers_present(monkeypatch):
    monkeypatch.setattr(app.settings, "security_headers_enabled", True)
    monkeypatch.setattr(app.settings, "require_https", False)

    with TestClient(app.app) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert response.headers["Permissions-Policy"] == "geolocation=(), microphone=(), camera=()"
    assert response.headers["Content-Security-Policy"] == app.settings.csp_policy
    assert response.headers["Cross-Origin-Opener-Policy"] == "same-origin"
    assert response.headers["Cross-Origin-Resource-Policy"] == "same-origin"


def test_hsts_header_when_https_required(monkeypatch):
    monkeypatch.setattr(app.settings, "security_headers_enabled", True)
    monkeypatch.setattr(app.settings, "require_https", True)

    with TestClient(app.app) as client:
        response = client.get("/", headers={"x-forwarded-proto": "https"})

    assert response.status_code == 200
    assert response.headers["Strict-Transport-Security"] == f"max-age={app.settings.hsts_max_age}"
