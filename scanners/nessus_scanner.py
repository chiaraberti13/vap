"""Nessus API scanner wrapper (optional)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

import requests

from config import settings


SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
}


@dataclass
class NessusScanner:
    enable_live_scans: bool = False

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "nessus",
                "status": "simulated",
                "findings": [
                    {
                        "title": "Possibile configurazione non sicura",
                        "severity": "low",
                        "description": "Simulazione: servizio con configurazione debole.",
                        "recommendation": "Applicare hardening e aggiornamenti di sicurezza.",
                        "cwe": ["CWE-16"],
                        "tags": ["owasp-a05", "nessus"],
                    }
                ],
            }

        if not settings.nessus_api_base_url or not settings.nessus_api_key:
            return {
                "tool": "nessus",
                "status": "skipped",
                "message": "API Nessus non configurata.",
                "findings": [],
            }

        try:
            findings = self._fetch_findings(target)
        except requests.RequestException as exc:
            return {
                "tool": "nessus",
                "status": "error",
                "message": f"Errore API Nessus: {exc}",
                "findings": [],
            }

        return {
            "tool": "nessus",
            "status": "executed",
            "findings": findings,
        }

    def _fetch_findings(self, target: str) -> List[Dict[str, Any]]:
        url = f"{settings.nessus_api_base_url.rstrip('/')}{settings.nessus_vulnerabilities_endpoint}"
        headers = {"X-ApiKeys": settings.nessus_api_key}
        response = requests.get(
            url,
            headers=headers,
            params={"target": target},
            timeout=settings.nessus_timeout_seconds,
        )
        response.raise_for_status()
        payload = response.json()
        vulnerabilities = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []

        findings: List[Dict[str, Any]] = []
        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue
            severity = SEVERITY_MAP.get(str(vuln.get("severity", "")).lower(), "info")
            findings.append(
                {
                    "title": vuln.get("plugin_name", "Vulnerabilità Nessus"),
                    "severity": severity,
                    "description": vuln.get("description", ""),
                    "recommendation": vuln.get("solution", ""),
                    "host": vuln.get("host", ""),
                    "port": vuln.get("port", ""),
                    "cve": vuln.get("cve", []) if isinstance(vuln.get("cve"), list) else [],
                    "tags": ["nessus"],
                }
            )
        return findings
