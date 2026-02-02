"""Acunetix API scanner wrapper (optional)."""
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
class AcunetixScanner:
    enable_live_scans: bool = False

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "acunetix",
                "status": "simulated",
                "findings": [
                    {
                        "title": "Possibile componente vulnerabile",
                        "severity": "medium",
                        "description": "Simulazione: libreria con CVE nota.",
                        "recommendation": "Aggiornare le dipendenze e applicare patch.",
                        "cwe": ["CWE-1104"],
                        "tags": ["owasp-a06", "acunetix"],
                    }
                ],
            }

        if not settings.acunetix_api_base_url or not settings.acunetix_api_key:
            return {
                "tool": "acunetix",
                "status": "skipped",
                "message": "API Acunetix non configurata.",
                "findings": [],
            }

        try:
            findings = self._fetch_findings(target)
        except requests.RequestException as exc:
            return {
                "tool": "acunetix",
                "status": "error",
                "message": f"Errore API Acunetix: {exc}",
                "findings": [],
            }

        return {
            "tool": "acunetix",
            "status": "executed",
            "findings": findings,
        }

    def _fetch_findings(self, target: str) -> List[Dict[str, Any]]:
        url = f"{settings.acunetix_api_base_url.rstrip('/')}{settings.acunetix_vulnerabilities_endpoint}"
        headers = {"X-Auth": settings.acunetix_api_key}
        response = requests.get(
            url,
            headers=headers,
            params={"q": target},
            timeout=settings.acunetix_timeout_seconds,
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
                    "title": vuln.get("name", "Vulnerabilità Acunetix"),
                    "severity": severity,
                    "description": vuln.get("description", ""),
                    "recommendation": vuln.get("remediation", ""),
                    "host": vuln.get("host", ""),
                    "path": vuln.get("path", ""),
                    "cve": vuln.get("cve", []) if isinstance(vuln.get("cve"), list) else [],
                    "tags": ["acunetix"],
                }
            )
        return findings
