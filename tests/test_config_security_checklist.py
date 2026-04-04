from types import SimpleNamespace

import config


def test_build_startup_security_checklist_returns_empty_outside_production(monkeypatch):
    monkeypatch.setattr(config, "settings", SimpleNamespace(app_env="development"))
    assert config.build_startup_security_checklist() == []


def test_build_startup_security_checklist_returns_expected_findings(monkeypatch):
    monkeypatch.setattr(
        config,
        "settings",
        SimpleNamespace(
            app_env="production",
            csrf_secret="",
            jwt_secret="",
            api_key="",
            api_key_hash="",
            require_https=False,
            host="0.0.0.0",
        ),
    )

    checks = config.build_startup_security_checklist()
    codes = {check["code"] for check in checks}

    assert len(checks) == 5
    assert "jwt_secret_missing" in codes
    assert "csrf_secret_missing" in codes
    assert "api_key_missing" in codes
    assert "https_not_enforced" in codes
    assert "host_exposed" in codes


def test_build_startup_security_checklist_skips_passing_controls(monkeypatch):
    monkeypatch.setattr(
        config,
        "settings",
        SimpleNamespace(
            app_env="production",
            csrf_secret="csrf",
            jwt_secret="jwt",
            api_key_hash="sha256:test",
            api_key="",
            require_https=True,
            host="127.0.0.1",
        ),
    )

    assert config.build_startup_security_checklist() == []
