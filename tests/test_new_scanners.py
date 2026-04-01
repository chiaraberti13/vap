from __future__ import annotations

from scanners.arjun_scanner import ArjunScanner
from scanners.testssl_scanner import TestsslScanner
from scanners.theharvester_scanner import TheHarvesterScanner
from scanners.wafw00f_scanner import Wafw00fScanner

import scanner_engine


def test_new_scanners_registered_in_map():
    assert "wafw00f" in scanner_engine.SCANNERS_MAP
    assert "testssl" in scanner_engine.SCANNERS_MAP
    assert "theharvester" in scanner_engine.SCANNERS_MAP
    assert "arjun" in scanner_engine.SCANNERS_MAP


def test_wafw00f_extract_findings():
    scanner = Wafw00fScanner(enable_live_scans=False)
    findings = scanner._extract_findings({"detected_wafs": ["Cloudflare"]})
    assert findings
    assert "Cloudflare" in findings[0]["title"]


def test_testssl_extract_findings():
    scanner = TestsslScanner(enable_live_scans=False)
    findings = scanner._extract_findings([{"id": "TLSv1", "severity": "high", "finding": "Protocollo debole"}])
    assert findings
    assert findings[0]["severity"] == "high"


def test_theharvester_extract_findings():
    scanner = TheHarvesterScanner(enable_live_scans=False)
    findings = scanner._extract_findings(
        {"emails": ["a@example.com"], "hosts": ["api.example.com"], "ips": ["1.1.1.1"]}
    )
    assert findings
    assert "OSINT" in findings[0]["title"]


def test_arjun_extract_findings():
    scanner = ArjunScanner(enable_live_scans=False)
    findings = scanner._extract_findings({"params": ["id", "q"]}, "https://example.com")
    assert findings
    assert findings[0]["parameters"] == ["id", "q"]
