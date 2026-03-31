from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from requests import RequestException

import scanner_engine


class DummyScanner:
    def __init__(self, enable_live_scans: bool):
        self.enable_live_scans = enable_live_scans

    def run(self, target: str):
        return {
            "tool": "dummy",
            "status": "completed",
            "findings": [{"id": target}],
        }


class TimeoutScanner:
    def __init__(self, enable_live_scans: bool):
        self.enable_live_scans = enable_live_scans

    def run(self, _target: str):
        raise TimeoutError("tempo scaduto")


class InvalidScanner:
    def __init__(self, enable_live_scans: bool):
        self.enable_live_scans = enable_live_scans

    def run(self, _target: str):
        raise ValueError("input non valido")


class CrashScanner:
    def __init__(self, enable_live_scans: bool):
        self.enable_live_scans = enable_live_scans

    def run(self, _target: str):
        raise RuntimeError("boom")


def test_collect_findings_applies_max_limit(monkeypatch):
    monkeypatch.setattr(scanner_engine, "settings", SimpleNamespace(max_findings=2, enable_live_scans=False))
    findings = scanner_engine._collect_findings(
        [{"findings": [{"id": 1}, {"id": 2}]}, {"findings": [{"id": 3}]}]
    )
    assert findings == [
        {"id": 1, "found_by": "Active Testing"},
        {"id": 2, "found_by": "Active Testing"},
    ]


def test_run_scanner_success(monkeypatch):
    monkeypatch.setattr(scanner_engine, "settings", SimpleNamespace(enable_live_scans=True, max_findings=100))
    result = scanner_engine._run_scanner(DummyScanner, "example.com")
    assert result["status"] == "completed"
    assert result["findings"]


@pytest.mark.parametrize(
    "scanner_cls,error_type,expected_message",
    [
        (TimeoutScanner, "timeout", "tempo scaduto"),
        (InvalidScanner, "validation", "input non valido"),
        (CrashScanner, "unexpected", "scanner runtime error"),
    ],
)
def test_run_scanner_error_mapping(monkeypatch, scanner_cls, error_type, expected_message):
    monkeypatch.setattr(scanner_engine, "settings", SimpleNamespace(enable_live_scans=False, max_findings=100))
    result = scanner_engine._run_scanner(scanner_cls, "example.com")
    assert result["status"] == "error"
    assert result["error_type"] == error_type
    assert result["message"] == expected_message


def test_get_scanner_classes_and_single_scanner(monkeypatch):
    monkeypatch.setattr(scanner_engine, "SCANNERS_MAP", {"dummy": DummyScanner})

    full = scanner_engine.get_scanner_classes("full")
    only = scanner_engine.get_scanner_classes("dummy")
    assert full == [DummyScanner]
    assert only == [DummyScanner]

    result = scanner_engine.run_single_scanner("dummy", "target")
    assert result["status"] == "completed"

    with pytest.raises(scanner_engine.ScanValidationError):
        scanner_engine.get_scanner_classes("missing")

    with pytest.raises(scanner_engine.ScanValidationError):
        scanner_engine.run_single_scanner("missing", "target")


def test_run_scan_nmap_path(monkeypatch):
    monkeypatch.setattr(scanner_engine, "SCANNERS_MAP", {"nmap": DummyScanner})
    monkeypatch.setattr(
        scanner_engine,
        "settings",
        SimpleNamespace(enable_live_scans=False, max_findings=10, max_concurrent_scanners=1),
    )
    monkeypatch.setattr(scanner_engine, "validate_nmap_target", lambda target: f"validated-{target}")
    monkeypatch.setattr(scanner_engine, "enrich_findings", lambda findings: [{"enriched": True, **f} for f in findings])

    result = scanner_engine.run_scan("127.0.0.1", "nmap")
    assert result.target == "validated-127.0.0.1"
    assert result.status == "completed"
    assert result.findings[0]["enriched"] is True


def test_serialize_findings_and_cli_parser(monkeypatch, tmp_path):
    payload = scanner_engine.serialize_findings([{"x": 1}])
    assert json.loads(payload) == [{"x": 1}]

    output_file = tmp_path / "result.json"
    monkeypatch.setattr(
        scanner_engine,
        "run_scan",
        lambda **kwargs: scanner_engine.ScanResult(
            target=kwargs["target"],
            scan_type=kwargs["scan_type"],
            status="completed",
            started_at=scanner_engine.datetime.now(scanner_engine.timezone.utc),
            completed_at=scanner_engine.datetime.now(scanner_engine.timezone.utc),
            findings=[{"ok": True}],
            metadata={"tests_performed": 1},
        ),
    )

    monkeypatch.setattr(
        "sys.argv",
        ["scanner_engine.py", "--target", "example.com", "--scan-type", "full", "--output", str(output_file)],
    )
    assert scanner_engine.main() == 0
    assert output_file.exists()


def test_main_returns_2_for_validation_error(monkeypatch):
    monkeypatch.setattr(scanner_engine, "run_scan", lambda **_kwargs: (_ for _ in ()).throw(scanner_engine.ScanValidationError("bad")))
    monkeypatch.setattr("sys.argv", ["scanner_engine.py", "--target", "bad-target"])
    assert scanner_engine.main() == 2


def test_run_scan_full_uses_validate_target(monkeypatch):
    monkeypatch.setattr(scanner_engine, "SCANNERS_MAP", {"nmap": DummyScanner})
    monkeypatch.setattr(
        scanner_engine,
        "settings",
        SimpleNamespace(enable_live_scans=False, max_findings=10, max_concurrent_scanners=2),
    )
    monkeypatch.setattr(scanner_engine, "validate_target", lambda target: f"ok-{target}")
    monkeypatch.setattr(scanner_engine, "enrich_findings", lambda findings: findings)
    monkeypatch.setattr(
        scanner_engine,
        "detect_target_redirect",
        lambda _target: {"validated_target": "ok-example.com", "redirect_from": "http://example.com"},
    )

    result = scanner_engine.run_scan("example.com", "full")
    assert result.target == "ok-example.com"
    assert result.scan_type == "full"
    assert result.metadata["redirect_from"] == "http://example.com"


def test_validate_nmap_target_rejects_bad_range_octet():
    with pytest.raises(scanner_engine.ScanValidationError):
        scanner_engine.validate_nmap_target("192.168.1.10-999")


def test_validate_nmap_target_rejects_bad_cidr():
    with pytest.raises(scanner_engine.ScanValidationError):
        scanner_engine.validate_nmap_target("10.0.0.0/99")


def test_compute_scan_stats_collects_counters():
    results = [
        {"findings": [{"id": 1}], "tests_performed": 5, "http_requests_total": 9, "avg_response_time_ms": 100},
        {"findings": [{"id": 2}], "http_requests_total": 3, "avg_response_time_ms": 50},
    ]
    findings = [
        {"evidence_url": "https://example.com/a", "parameters": ["q"], "method": "GET"},
        {"affected_url": "https://example.com/b", "parameters": {"id": "1"}},
    ]
    stats = scanner_engine._compute_scan_stats(results, findings)
    assert stats["tests_performed"] == 6
    assert stats["urls_spidered"] == 2
    assert stats["injection_points"] == 2
    assert stats["http_requests_total"] == 12
    assert stats["avg_response_time_ms"] == 75.0


def test_detect_target_redirect_handles_request_exception(monkeypatch):
    monkeypatch.setattr(
        scanner_engine.requests,
        "get",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RequestException("no network")),
    )
    result = scanner_engine.detect_target_redirect("example.com")
    assert result["validated_target"] == "example.com"
    assert result["redirect_from"] == ""
