#!/usr/bin/env python3
"""Scan orchestration engine."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from ipaddress import ip_address, ip_network
import re
import sys
from typing import Any, Dict, List
from urllib.parse import urlparse

import bleach
import requests
import validators

from config import settings
from enrichment_engine import enrich_findings
from scanners import (
    NucleiScanner,
    NmapScanner,
    WhatWebScanner,
    SubfinderScanner,
    NiktoScanner,
    DirsearchScanner,
    SqlmapScanner,
    XsstrikeScanner,
    ZapScanner,
    BurpScanner,
    WapitiScanner,
    CommixScanner,
    AcunetixScanner,
    NessusScanner,
)


IPV4_OCTET_REGEX = r"(?:25[0-5]|2[0-4]\d|1?\d{1,2})"
IPV4_ADDRESS_REGEX = rf"{IPV4_OCTET_REGEX}(?:\.{IPV4_OCTET_REGEX}){{3}}"
TARGET_REGEX = re.compile(
    rf"^(https?://)?([a-zA-Z0-9.-]+|{IPV4_ADDRESS_REGEX})(:\d{{1,5}})?(/.*)?$"
)



SCANNERS_MAP = {
    "nuclei": NucleiScanner,
    "nmap": NmapScanner,
    "whatweb": WhatWebScanner,
    "subfinder": SubfinderScanner,
    "nikto": NiktoScanner,
    "dirsearch": DirsearchScanner,
    "sqlmap": SqlmapScanner,
    "xsstrike": XsstrikeScanner,
    "zap": ZapScanner,
    "burp": BurpScanner,
    "wapiti": WapitiScanner,
    "commix": CommixScanner,
    "acunetix": AcunetixScanner,
    "nessus": NessusScanner,
}
SCAN_TYPE_CHOICES = ["full", *SCANNERS_MAP.keys()]

@dataclass
class ScanResult:
    target: str
    scan_type: str
    status: str
    started_at: datetime
    completed_at: datetime
    findings: List[Dict[str, Any]]
    metadata: Dict[str, Any]


class ScanValidationError(ValueError):
    pass


def validate_target(target: str) -> str:
    if not target or len(target) > 255:
        raise ScanValidationError("Target non valido o troppo lungo.")

    target = bleach.clean(target, tags=[], attributes={}, strip=True).strip()
    if not TARGET_REGEX.match(target):
        raise ScanValidationError("Formato target non valido. Usa URL o IP.")

    parsed = urlparse(target if target.startswith("http") else f"http://{target}")
    if not parsed.hostname:
        raise ScanValidationError("Hostname non valido.")
    hostname = parsed.hostname
    if not (validators.domain(hostname) or validators.ipv4(hostname)):
        raise ScanValidationError("Hostname non valido.")
    if re.fullmatch(r"\d+(?:\.\d+){3}", hostname):
        try:
            ip_address(hostname)
        except ValueError as exc:
            raise ScanValidationError("IP non valido.") from exc

    return target


def detect_target_redirect(target: str) -> Dict[str, str]:
    """Detect HTTP->HTTPS redirect and keep traceability metadata."""
    parsed = urlparse(target if target.startswith("http") else f"http://{target}")
    if not parsed.hostname:
        return {"validated_target": target}

    original_target = target
    normalized_target = target if target.startswith("http") else f"http://{target}"
    redirect_from = ""

    try:
        response = requests.get(
            normalized_target,
            timeout=5,
            allow_redirects=True,
            headers={"User-Agent": "VAP-Redirect-Detector/1.0"},
        )
        final_url = response.url or normalized_target
        if (
            normalized_target.startswith("http://")
            and final_url.startswith("https://")
            and final_url != normalized_target
        ):
            redirect_from = normalized_target
            validated_target = final_url
        else:
            validated_target = original_target
    except requests.RequestException:
        validated_target = original_target

    return {"validated_target": validated_target, "redirect_from": redirect_from}


def validate_nmap_target(target: str) -> str:
    if not target or len(target) > 255:
        raise ScanValidationError("Target non valido o troppo lungo.")

    target = bleach.clean(target, tags=[], attributes={}, strip=True).strip()
    if " " in target:
        raise ScanValidationError("Il target Nmap non deve contenere spazi.")

    if "://" in target:
        parsed = urlparse(target)
        if not parsed.hostname:
            raise ScanValidationError("Hostname non valido.")
        if not (validators.domain(parsed.hostname) or validators.ipv4(parsed.hostname)):
            raise ScanValidationError("Hostname non valido.")
        if re.fullmatch(r"\d+(?:\.\d+){3}", parsed.hostname):
            try:
                ip_address(parsed.hostname)
            except ValueError as exc:
                raise ScanValidationError("IP non valido.") from exc
        return parsed.hostname

    if "/" in target:
        try:
            ip_network(target, strict=False)
        except ValueError as exc:
            raise ScanValidationError("CIDR non valido.") from exc
        return target

    if "-" in target:
        start, end = target.split("-", maxsplit=1)
        start = start.strip()
        end = end.strip()
        try:
            start_ip = ip_address(start)
        except ValueError as exc:
            raise ScanValidationError("IP iniziale non valido.") from exc

        if "." not in end:
            start_octets = start.split(".")
            if len(start_octets) != 4:
                raise ScanValidationError("Formato range IP non valido.")
            try:
                end_octet = int(end)
            except ValueError as exc:
                raise ScanValidationError("Ottetto finale range non valido.") from exc
            if not 0 <= end_octet <= 255:
                raise ScanValidationError("Ottetto finale range non valido.")
            end_ip = ip_address(".".join(start_octets[:3] + [str(end_octet)]))
        else:
            try:
                end_ip = ip_address(end)
            except ValueError as exc:
                raise ScanValidationError("IP finale non valido.") from exc

        if int(end_ip) < int(start_ip):
            raise ScanValidationError("Range IP non valido: fine < inizio.")
        return target

    if not TARGET_REGEX.match(target):
        raise ScanValidationError("Formato target non valido. Usa URL o IP.")

    parsed = urlparse(f"http://{target}")
    if not parsed.hostname:
        raise ScanValidationError("Hostname non valido.")
    hostname = parsed.hostname
    if not (validators.domain(hostname) or validators.ipv4(hostname)):
        raise ScanValidationError("Hostname non valido.")
    if re.fullmatch(r"\d+(?:\.\d+){3}", hostname):
        try:
            ip_address(hostname)
        except ValueError as exc:
            raise ScanValidationError("IP non valido.") from exc

    return target


def _collect_findings(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for result in results:
        tool_name = result.get("tool", "")
        for finding in result.get("findings", []):
            if tool_name and not finding.get("tool"):
                finding = dict(finding)
                finding["tool"] = tool_name
            finding.setdefault("found_by", f"{tool_name.title()} – Active Testing" if tool_name else "Active Testing")
            findings.append(finding)
    return findings[: settings.max_findings]


def _compute_scan_stats(results: List[Dict[str, Any]], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    tests_performed = 0
    urls: set[str] = set()
    injection_points = 0
    http_requests_total = 0
    response_times: List[float] = []

    for result in results:
        result_findings = result.get("findings", [])
        tests_performed += int(result.get("tests_performed") or len(result_findings))
        http_requests_total += int(result.get("http_requests_total") or 0)

        avg_ms = result.get("avg_response_time_ms")
        if isinstance(avg_ms, (int, float)) and avg_ms >= 0:
            response_times.append(float(avg_ms))

    for finding in findings:
        evidence_url = finding.get("evidence_url") or finding.get("url") or finding.get("affected_url")
        if isinstance(evidence_url, str) and evidence_url:
            urls.add(evidence_url)

        method = finding.get("method")
        parameters = finding.get("parameters")
        if method and not isinstance(method, str):
            finding["method"] = str(method)
        if parameters and not isinstance(parameters, (list, dict, str)):
            finding["parameters"] = str(parameters)

        if isinstance(parameters, list):
            injection_points += len(parameters)
        elif isinstance(parameters, dict):
            injection_points += len(parameters.keys())
        elif isinstance(parameters, str) and parameters.strip():
            injection_points += 1

    avg_response_time_ms = round(sum(response_times) / len(response_times), 2) if response_times else None
    if not http_requests_total:
        http_requests_total = tests_performed

    return {
        "tests_performed": tests_performed,
        "urls_spidered": len(urls),
        "injection_points": injection_points,
        "http_requests_total": http_requests_total,
        "avg_response_time_ms": avg_response_time_ms,
    }


def _scanner_label(scanner_cls: type) -> str:
    return scanner_cls.__name__.replace("Scanner", "").lower()


def _run_scanner(scanner_cls: type, target: str) -> Dict[str, Any]:
    scanner = scanner_cls(enable_live_scans=settings.enable_live_scans)
    try:
        return scanner.run(target)
    except TimeoutError as exc:
        return {
            "tool": _scanner_label(scanner_cls),
            "status": "error",
            "error_type": "timeout",
            "message": str(exc),
            "findings": [],
        }
    except ValueError as exc:
        return {
            "tool": _scanner_label(scanner_cls),
            "status": "error",
            "error_type": "validation",
            "message": str(exc),
            "findings": [],
        }
    except Exception:
        return {
            "tool": _scanner_label(scanner_cls),
            "status": "error",
            "error_type": "unexpected",
            "message": "scanner runtime error",
            "findings": [],
        }


def get_scanner_classes(scan_type: str) -> List[type]:
    scan_type = scan_type.lower().strip()
    if scan_type == "full":
        return list(SCANNERS_MAP.values())
    if scan_type in SCANNERS_MAP:
        return [SCANNERS_MAP[scan_type]]
    raise ScanValidationError("Tipo di scansione non supportato.")


def run_single_scanner(scanner_name: str, target: str) -> Dict[str, Any]:
    scanner_cls = SCANNERS_MAP.get(scanner_name.lower().strip())
    if not scanner_cls:
        raise ScanValidationError("Scanner non supportato.")
    return _run_scanner(scanner_cls, target)


def run_scan(target: str, scan_type: str) -> ScanResult:
    scan_type = scan_type.lower().strip()
    scanner_classes = get_scanner_classes(scan_type)

    if scan_type == "nmap":
        validated_target = validate_nmap_target(target)
        redirect_from = ""
    else:
        validated_target = validate_target(target)
        redirect_data = detect_target_redirect(validated_target)
        validated_target = redirect_data["validated_target"]
        redirect_from = redirect_data["redirect_from"]

    started_at = datetime.now(timezone.utc)
    results: List[Dict[str, Any]] = []

    max_workers = max(1, min(len(scanner_classes), settings.max_concurrent_scanners))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(_run_scanner, scanner_cls, validated_target): scanner_cls
            for scanner_cls in scanner_classes
        }
        for future in as_completed(future_map):
            results.append(future.result())

    findings = _collect_findings(results)
    findings = enrich_findings(findings)
    metadata = _compute_scan_stats(results, findings)
    metadata["redirect_from"] = redirect_from
    completed_at = datetime.now(timezone.utc)

    return ScanResult(
        target=validated_target,
        scan_type=scan_type,
        status="completed",
        started_at=started_at,
        completed_at=completed_at,
        findings=findings,
        metadata=metadata,
    )


def serialize_findings(findings: List[Dict[str, Any]]) -> str:
    return json.dumps(findings, ensure_ascii=False, indent=2)


def _build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Esegui una scansione di sicurezza.")
    parser.add_argument("--target", required=True, help="Target della scansione (URL o IP).")
    parser.add_argument(
        "--scan-type",
        default="full",
        choices=SCAN_TYPE_CHOICES,
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
        "metadata": scan_result.metadata,
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
