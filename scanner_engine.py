#!/usr/bin/env python3
"""Scan orchestration engine."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from config import settings
from scanners import (
    NucleiScanner,
    NmapScanner,
    WhatWebScanner,
    SubfinderScanner,
    NiktoScanner,
)


TARGET_REGEX = re.compile(r"^(https?://)?([a-zA-Z0-9.-]+|\d{1,3}(?:\.\d{1,3}){3})(:\d{1,5})?(/.*)?$")


@dataclass
class ScanResult:
    target: str
    scan_type: str
    status: str
    started_at: datetime
    completed_at: datetime
    findings: List[Dict[str, Any]]


class ScanValidationError(ValueError):
    pass


def validate_target(target: str) -> str:
    if not target or len(target) > 255:
        raise ScanValidationError("Target non valido o troppo lungo.")

    target = target.strip()
    if not TARGET_REGEX.match(target):
        raise ScanValidationError("Formato target non valido. Usa URL o IP.")

    parsed = urlparse(target if target.startswith("http") else f"http://{target}")
    if not parsed.hostname:
        raise ScanValidationError("Hostname non valido.")

    return target


def _collect_findings(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for result in results:
        findings.extend(result.get("findings", []))
    return findings[: settings.max_findings]


def run_scan(target: str, scan_type: str) -> ScanResult:
    validated_target = validate_target(target)
    scan_type = scan_type.lower().strip()

    scanners_map = {
        "nuclei": NucleiScanner,
        "nmap": NmapScanner,
        "whatweb": WhatWebScanner,
        "subfinder": SubfinderScanner,
        "nikto": NiktoScanner,
    }

    if scan_type == "full":
        scanner_classes = list(scanners_map.values())
    elif scan_type in scanners_map:
        scanner_classes = [scanners_map[scan_type]]
    else:
        raise ScanValidationError("Tipo di scansione non supportato.")

    started_at = datetime.utcnow()
    results: List[Dict[str, Any]] = []

    for scanner_cls in scanner_classes:
        scanner = scanner_cls(enable_live_scans=settings.enable_live_scans)
        results.append(scanner.run(validated_target))

    findings = _collect_findings(results)
    completed_at = datetime.utcnow()

    return ScanResult(
        target=validated_target,
        scan_type=scan_type,
        status="completed",
        started_at=started_at,
        completed_at=completed_at,
        findings=findings,
    )


def serialize_findings(findings: List[Dict[str, Any]]) -> str:
    return json.dumps(findings, ensure_ascii=False, indent=2)
