"""Nuclei scanner wrapper."""
from __future__ import annotations

from dataclasses import dataclass
import json
import shlex
import shutil
import subprocess
from typing import Any, Dict, List, Optional

from config import settings


SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


@dataclass
class NucleiScanner:
    enable_live_scans: bool = False

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "nuclei",
                "status": "simulated",
                "findings": [
                    {
                        "title": "Possibile esposizione di endpoint",
                        "severity": "medium",
                        "description": "Simulazione: verifica endpoints pubblici non protetti.",
                        "recommendation": "Limitare l'accesso con autenticazione e WAF.",
                    }
                ],
            }

        if not shutil.which("nuclei"):
            return {
                "tool": "nuclei",
                "status": "skipped",
                "message": "Tool nuclei non installato.",
                "findings": [],
            }

        update_result = self._update_templates()
        if update_result:
            return update_result

        severity_filter = self._normalize_severities(settings.nuclei_severities)
        command = self._build_command(target)

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
                "tool": "nuclei",
                "status": "error",
                "message": "Timeout durante l'esecuzione di nuclei.",
                "findings": [],
            }

        findings = self._parse_findings(completed.stdout, severity_filter)
        message = completed.stderr.strip() if completed.stderr else ""
        status = "executed" if completed.returncode == 0 else "error"
        if completed.returncode != 0 and not message:
            message = "Errore durante l'esecuzione di nuclei."

        return {
            "tool": "nuclei",
            "status": status,
            "message": message,
            "findings": findings,
        }

    def _update_templates(self) -> Optional[Dict[str, Any]]:
        if not settings.nuclei_update_templates:
            return None

        try:
            completed = subprocess.run(
                ["nuclei", "-update-templates"],
                capture_output=True,
                text=True,
                timeout=settings.scan_timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return {
                "tool": "nuclei",
                "status": "error",
                "message": "Timeout durante l'aggiornamento dei template nuclei.",
                "findings": [],
            }

        if completed.returncode != 0:
            message = completed.stderr.strip() if completed.stderr else "Errore update template nuclei."
            return {
                "tool": "nuclei",
                "status": "error",
                "message": message,
                "findings": [],
            }
        return None

    def _build_command(self, target: str) -> List[str]:
        command = [
            "nuclei",
            "-u",
            target,
            "-json",
            "-rl",
            str(settings.nuclei_rate_limit),
            "-timeout",
            str(settings.nuclei_timeout_seconds),
        ]

        templates = [item.strip() for item in settings.nuclei_templates.split(",") if item.strip()]
        if templates:
            command.extend(["-t", ",".join(templates)])

        if settings.nuclei_additional_args:
            command.extend(shlex.split(settings.nuclei_additional_args))

        return command

    def _normalize_severities(self, value: str) -> List[str]:
        if not value:
            return list(SEVERITY_ORDER)
        raw = [item.strip().lower() for item in value.split(",") if item.strip()]
        ordered = [sev for sev in SEVERITY_ORDER if sev in raw]
        return ordered or list(SEVERITY_ORDER)

    def _parse_findings(self, stdout: str, severity_filter: List[str]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = payload.get("info", {}) if isinstance(payload, dict) else {}
            severity = str(info.get("severity", "info")).lower()
            if severity not in severity_filter:
                continue

            classification = info.get("classification", {}) if isinstance(info, dict) else {}
            cve_ids = classification.get("cve-id") or []
            if isinstance(cve_ids, str):
                cve_ids = [cve_ids]
            cwe_ids = classification.get("cwe-id") or []
            if isinstance(cwe_ids, str):
                cwe_ids = [cwe_ids]

            references = info.get("reference") or []
            if isinstance(references, str):
                references = [references]

            finding = {
                "title": info.get("name") or payload.get("template-id", "Finding Nuclei"),
                "severity": severity,
                "description": info.get("description", ""),
                "recommendation": info.get("remediation", ""),
                "host": payload.get("host"),
                "matched_at": payload.get("matched-at"),
                "template_id": payload.get("template-id"),
                "matcher": payload.get("matcher-name"),
                "cve": cve_ids,
                "cwe": cwe_ids,
                "cvss_score": classification.get("cvss-score"),
                "cvss_metrics": classification.get("cvss-metrics"),
                "references": references,
                "tags": info.get("tags", []),
                "timestamp": payload.get("timestamp"),
            }
            findings.append(finding)

        return findings
