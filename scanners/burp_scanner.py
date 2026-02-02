"""Burp Suite REST API scanner wrapper."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

import requests

from config import settings


RISK_MAPPING = {
    "info": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


@dataclass
class BurpScanner:
    enable_live_scans: bool = False

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "burp",
                "status": "simulated",
                "findings": [
                    {
                        "title": "Possibile directory traversal",
                        "severity": "medium",
                        "description": "Simulazione: endpoint con path traversal.",
                        "recommendation": "Normalizzare i path e limitare l'accesso ai filesystem.",
                        "cwe": ["CWE-22"],
                        "tags": ["owasp-a01", "burp"],
                    }
                ],
            }

        if not settings.burp_api_base_url or not settings.burp_api_key:
            return {
                "tool": "burp",
                "status": "skipped",
                "message": "API Burp non configurata.",
                "findings": [],
            }

        try:
            scan_id = self._start_scan(target)
            findings = self._fetch_issues(scan_id)
        except requests.RequestException as exc:
            return {
                "tool": "burp",
                "status": "error",
                "message": f"Errore API Burp: {exc}",
                "findings": [],
            }

        return {
            "tool": "burp",
            "status": "executed",
            "findings": findings,
        }

    def _headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {settings.burp_api_key}"}

    def _start_scan(self, target: str) -> str:
        response = requests.post(
            f"{settings.burp_api_base_url.rstrip('/')}{settings.burp_api_scan_endpoint}",
            json={"urls": [target]},
            headers=self._headers(),
            timeout=settings.burp_timeout_seconds,
        )
        response.raise_for_status()
        payload = response.json()
        scan_id = payload.get("scan_id") or payload.get("id") or ""
        if not scan_id:
            raise requests.RequestException("Scan ID non restituito da Burp.")
        return str(scan_id)

    def _fetch_issues(self, scan_id: str) -> List[Dict[str, Any]]:
        url = f"{settings.burp_api_base_url.rstrip('/')}{settings.burp_api_issues_endpoint}"
        response = requests.get(
            url.format(scan_id=scan_id),
            headers=self._headers(),
            timeout=settings.burp_timeout_seconds,
        )
        response.raise_for_status()
        payload = response.json()
        issues = payload.get("issues", []) if isinstance(payload, dict) else []

        findings: List[Dict[str, Any]] = []
        for issue in issues:
            if not isinstance(issue, dict):
                continue
            severity = RISK_MAPPING.get(str(issue.get("severity", "")).lower(), "info")
            findings.append(
                {
                    "title": issue.get("name", "Issue Burp"),
                    "severity": severity,
                    "description": issue.get("description", ""),
                    "recommendation": issue.get("remediation", ""),
                    "host": issue.get("host", ""),
                    "path": issue.get("path", ""),
                    "cwe": [str(issue.get("cwe"))] if issue.get("cwe") else [],
                    "tags": ["burp"],
                }
            )
        return findings
