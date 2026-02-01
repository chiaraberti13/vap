#!/usr/bin/env python3
"""Scan orchestration engine."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from ipaddress import ip_address
import re
import sys
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
    hostname = parsed.hostname
    if re.fullmatch(r"\d+(?:\.\d+){3}", hostname):
        try:
            ip_address(hostname)
        except ValueError as exc:
            raise ScanValidationError("IP non valido.") from exc

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

    started_at = datetime.now(timezone.utc)
    results: List[Dict[str, Any]] = []

    for scanner_cls in scanner_classes:
        scanner = scanner_cls(enable_live_scans=settings.enable_live_scans)
        results.append(scanner.run(validated_target))

    findings = _collect_findings(results)
    completed_at = datetime.now(timezone.utc)

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


def _build_cli_parser() -> "argparse.ArgumentParser":
    import argparse

    parser = argparse.ArgumentParser(description="Esegui una scansione di sicurezza.")
    parser.add_argument("--target", required=True, help="Target della scansione (URL o IP).")
    parser.add_argument(
        "--scan-type",
        default="full",
        choices=["full", "nuclei", "nmap", "whatweb", "subfinder", "nikto"],
        help="Tipo di scansione da eseguire.",
    )
    parser.add_argument(
        "--output",
        help="Percorso file JSON dove salvare i risultati. Se omesso, stampa su stdout.",
    )
    return parser


def main() -> int:
    parser = _build_cli_parser()
    args = parser.parse_args()

    try:
        scan_result = run_scan(target=args.target, scan_type=args.scan_type)
    except ScanValidationError as exc:
        print(f"Errore: {exc}", file=sys.stderr)
        return 2

    payload = {
        "target": scan_result.target,
        "scan_type": scan_result.scan_type,
        "status": scan_result.status,
        "started_at": scan_result.started_at.isoformat(),
        "completed_at": scan_result.completed_at.isoformat(),
        "findings": scan_result.findings,
    }
    serialized = json.dumps(payload, ensure_ascii=False, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as outfile:
            outfile.write(serialized)
    else:
        print(serialized)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
