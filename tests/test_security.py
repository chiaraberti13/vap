import secrets
from types import SimpleNamespace

import pytest

import security


def test_hash_and_verify_api_key_with_plain_key(monkeypatch):
    monkeypatch.setattr(
        security,
        "settings",
        SimpleNamespace(api_key="super-secret", api_key_hash=""),
    )

    assert security.verify_api_key("super-secret") is True
    assert security.verify_api_key("wrong") is False


def test_hash_and_verify_api_key_with_hash(monkeypatch):
    api_key_hash = security.hash_api_key("my-key")
    monkeypatch.setattr(
        security,
        "settings",
        SimpleNamespace(api_key="", api_key_hash=api_key_hash),
    )

    assert security.verify_api_key("my-key") is True
    assert security.verify_api_key("other") is False


def test_redact_api_key_returns_hash_prefix():
    redacted = security.redact_api_key("topsecret")

    assert redacted.startswith("sha256:")
    assert "topsecret" not in redacted


def test_csrf_token_validation_roundtrip():
    token = security.generate_csrf_token()

    security.validate_csrf_token(token, token)


@pytest.mark.parametrize("token,cookie_token", [("", "x"), ("x", ""), ("x", "y")])
def test_csrf_token_validation_fails_for_mismatch(token, cookie_token):
    with pytest.raises(ValueError):
        security.validate_csrf_token(token, cookie_token)


def test_access_token_roundtrip(monkeypatch):
    monkeypatch.setattr(
        security,
        "settings",
        SimpleNamespace(
            jwt_secret=secrets.token_urlsafe(32),
            jwt_algorithm="HS256",
            jwt_exp_minutes=5,
            jwt_issuer="vap",
            jwt_audience="vap-users",
            api_key="",
            api_key_hash="",
        ),
    )

    token = security.create_access_token("tester")
    decoded = security.decode_access_token(token)

    assert decoded["sub"] == "tester"
