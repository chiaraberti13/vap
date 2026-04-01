"""httpx scanner wrapper."""
from __future__ import annotations

from dataclasses import dataclass
import json
import shutil
import subprocess
from typing import Any, Dict, List

from config import settings


@dataclass
class HttpxScanner:
    enable_live_scans: bool = False

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "httpx",
                "status": "simulated",
                "findings": [
                    {
                        "tool": "httpx",
                        "title": "Configurazione header HTTP da rivedere",
                        "severity": "low",
                        "description": "httpx ha rilevato header di sicurezza mancanti o incompleti.",
                        "recommendation": "Aggiungere header di sicurezza (CSP, HSTS, X-Frame-Options).",
                        "found_by": "httpx – Passive Detection",
                    }
                ],
            }

        if not shutil.which("httpx"):
            return {
                "tool": "httpx",
                "status": "skipped",
                "message": "Tool httpx non installato.",
                "findings": [],
            }

        command = ["httpx", "-u", target, "-json"]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=settings.scan_timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return {
                "tool": "httpx",
                "status": "timeout",
                "message": "Timeout durante l'esecuzione di httpx.",
                "findings": [],
            }

        payload = self._parse_json_lines(completed.stdout)
        findings = self._extract_findings(payload)
        return {
            "tool": "httpx",
            "status": "executed" if completed.returncode == 0 else "completed_with_warnings",
            "findings": findings[: settings.max_findings],
            "urls_spidered": len(payload),
        }

    def _parse_json_lines(self, raw: str) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                items.append(parsed)
        return items

    def _extract_findings(self, payload: Any) -> List[Dict[str, Any]]:
        if not isinstance(payload, list):
            return []

        findings: List[Dict[str, Any]] = []
        for row in payload:
            if not isinstance(row, dict):
                continue
            url = str(row.get("url") or "").strip()
            status_code = row.get("status_code")
            tech = row.get("tech") if isinstance(row.get("tech"), list) else []
            headers = row.get("header") if isinstance(row.get("header"), dict) else {}
            if not url:
                continue

            missing_headers = [
                h for h in ["content-security-policy", "strict-transport-security", "x-frame-options"]
                if h not in {str(k).lower() for k in headers.keys()}
            ]
            if missing_headers:
                findings.append(
                    {
                        "tool": "httpx",
                        "title": f"Header di sicurezza mancanti su {url}",
                        "severity": "low",
                        "description": (
                            f"Status {status_code}. Header mancanti: {', '.join(missing_headers)}."
                        ),
                        "evidence_url": url,
                        "recommendation": "Configurare gli header HTTP security baseline raccomandati da OWASP.",
                        "found_by": "httpx – Passive Detection",
                        "tags": ["headers", "hardening"],
                    }
                )

            if tech:
                findings.append(
                    {
                        "tool": "httpx",
                        "title": "Tecnologie web fingerprinted",
                        "severity": "info",
                        "description": f"Tecnologie rilevate: {', '.join(map(str, tech[:10]))}",
                        "evidence_url": url,
                        "recommendation": "Mantenere aggiornati framework e componenti esposti.",
                        "found_by": "httpx – Passive Detection",
                        "tags": ["fingerprinting", "technology"],
                    }
                )
        return findings
