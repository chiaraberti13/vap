"""OWASP ZAP scanner wrapper."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

import requests

from config import settings


RISK_MAPPING = {
    "Informational": "info",
    "Low": "low",
    "Medium": "medium",
    "High": "high",
}


@dataclass
class ZapScanner:
    enable_live_scans: bool = False

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "zap",
                "status": "simulated",
                "findings": [
                    {
                        "title": "Header di sicurezza mancanti",
                        "severity": "low",
                        "description": "Simulazione: header CSP/X-Frame-Options non configurati.",
                        "recommendation": "Aggiungere header CSP, X-Frame-Options, X-Content-Type-Options.",
                        "cwe": ["CWE-16"],
                        "tags": ["owasp-a05", "headers"],
                    }
                ],
            }

        if not settings.zap_api_base_url:
            return {
                "tool": "zap",
                "status": "skipped",
                "message": "API OWASP ZAP non configurata.",
                "findings": [],
            }

        try:
            findings = self._fetch_alerts(target)
        except requests.RequestException as exc:
            return {
                "tool": "zap",
                "status": "error",
                "message": f"Errore API ZAP: {exc}",
                "findings": [],
            }

        return {
            "tool": "zap",
            "status": "executed",
            "findings": findings,
        }

    def _fetch_alerts(self, target: str) -> List[Dict[str, Any]]:
        params = {
            "baseurl": target,
            "start": 0,
            "count": settings.zap_max_alerts,
        }
        if settings.zap_api_key:
            params["apikey"] = settings.zap_api_key

        response = requests.get(
            f"{settings.zap_api_base_url.rstrip('/')}/JSON/core/view/alerts/",
            params=params,
            timeout=settings.zap_timeout_seconds,
        )
        response.raise_for_status()
        payload = response.json()
        alerts = payload.get("alerts", []) if isinstance(payload, dict) else []

        findings: List[Dict[str, Any]] = []
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            severity = RISK_MAPPING.get(alert.get("risk"), "info")
            findings.append(
                {
                    "title": alert.get("alert", "Alert ZAP"),
                    "severity": severity,
                    "description": alert.get("desc", ""),
                    "recommendation": alert.get("solution", ""),
                    "evidence": alert.get("evidence", ""),
                    "cwe": [str(alert.get("cweid"))] if alert.get("cweid") else [],
                    "references": [alert.get("reference")] if alert.get("reference") else [],
                    "tags": ["zap"],
                }
            )
        return findings
