"""testssl.sh scanner wrapper."""
from __future__ import annotations

from dataclasses import dataclass
import json
import shutil
import subprocess
from tempfile import NamedTemporaryFile
from typing import Any, Dict, List

from config import settings


@dataclass
class TestsslScanner:
    enable_live_scans: bool = False

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "testssl",
                "status": "simulated",
                "findings": [
                    {
                        "tool": "testssl",
                        "title": "Configurazione TLS da verificare",
                        "severity": "medium",
                        "description": (
                            "testssl.sh ha rilevato impostazioni TLS potenzialmente deboli sul target."
                        ),
                        "recommendation": "Disabilitare protocolli obsoleti e abilitare cipher suite robuste.",
                        "found_by": "testssl.sh – Active Testing",
                    }
                ],
            }

        binary = shutil.which("testssl.sh") or shutil.which("testssl")
        if not binary:
            return {
                "tool": "testssl",
                "status": "skipped",
                "message": "Tool testssl.sh non installato.",
                "findings": [],
            }

        with NamedTemporaryFile(mode="w+", suffix=".json") as output_file:
            command = [binary, "--jsonfile", output_file.name, target]
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
                    "tool": "testssl",
                    "status": "timeout",
                    "message": "Timeout durante l'esecuzione di testssl.sh.",
                    "findings": [],
                }

            payload = self._load_json_output(output_file.name)
            findings = self._extract_findings(payload)
            return {
                "tool": "testssl",
                "status": "executed" if completed.returncode == 0 else "completed_with_warnings",
                "findings": findings[: settings.max_findings],
            }

    def _load_json_output(self, output_path: str) -> Any:
        try:
            with open(output_path, "r", encoding="utf-8") as handle:
                raw = handle.read().strip()
        except OSError:
            return []
        if not raw:
            return []
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return []

    def _extract_findings(self, payload: Any) -> List[Dict[str, Any]]:
        if not isinstance(payload, list):
            return []
        findings: List[Dict[str, Any]] = []
        for row in payload:
            if not isinstance(row, dict):
                continue
            severity = str(row.get("severity", "")).lower()
            if severity not in {"critical", "high", "medium", "low"}:
                continue
            finding_text = str(row.get("finding") or "Misconfiguration TLS rilevata")
            finding_id = str(row.get("id") or "")
            findings.append(
                {
                    "tool": "testssl",
                    "title": f"TLS issue: {finding_id or 'generic'}",
                    "severity": "high" if severity == "critical" else severity,
                    "description": finding_text,
                    "recommendation": "Applicare hardening TLS secondo OWASP TLS Cheat Sheet.",
                    "found_by": "testssl.sh – Active Testing",
                    "tags": ["tls", "ssl", "crypto"],
                }
            )
        return findings
