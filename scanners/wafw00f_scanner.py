"""wafw00f scanner wrapper."""
from __future__ import annotations

from dataclasses import dataclass
import json
import shutil
import subprocess
from tempfile import NamedTemporaryFile
from typing import Any, Dict, List

from config import settings


@dataclass
class Wafw00fScanner:
    enable_live_scans: bool = False

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "wafw00f",
                "status": "simulated",
                "findings": [
                    {
                        "tool": "wafw00f",
                        "title": "WAF rilevato in front-end",
                        "severity": "info",
                        "description": "wafw00f ha identificato un Web Application Firewall davanti al target.",
                        "recommendation": (
                            "Verificare la configurazione del WAF, regole custom e modalità di blocco."
                        ),
                        "found_by": "wafw00f – Passive Detection",
                    }
                ],
            }

        if not shutil.which("wafw00f"):
            return {
                "tool": "wafw00f",
                "status": "skipped",
                "message": "Tool wafw00f non installato.",
                "findings": [],
            }

        with NamedTemporaryFile(mode="w+", suffix=".json") as output_file:
            command = ["wafw00f", target, "-o", output_file.name]
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
                    "tool": "wafw00f",
                    "status": "timeout",
                    "message": "Timeout durante l'esecuzione di wafw00f.",
                    "findings": [],
                }

            payload = self._load_json_output(output_file.name)
            findings = self._extract_findings(payload)
            return {
                "tool": "wafw00f",
                "status": "executed" if completed.returncode == 0 else "completed_with_warnings",
                "findings": findings[: settings.max_findings],
            }

    def _load_json_output(self, output_path: str) -> Any:
        try:
            with open(output_path, "r", encoding="utf-8") as handle:
                raw = handle.read().strip()
        except OSError:
            return {}
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}

    def _extract_findings(self, payload: Any) -> List[Dict[str, Any]]:
        if not isinstance(payload, dict):
            return []
        detections = payload.get("detected_wafs")
        if not isinstance(detections, list):
            detections = []
        findings: List[Dict[str, Any]] = []
        for waf_name in detections:
            if not isinstance(waf_name, str) or not waf_name.strip():
                continue
            findings.append(
                {
                    "tool": "wafw00f",
                    "title": f"WAF rilevato: {waf_name}",
                    "severity": "info",
                    "description": f"Fingerprint del WAF identificato: {waf_name}.",
                    "recommendation": "Convalidare le regole di protezione e monitorare possibili bypass.",
                    "found_by": "wafw00f – Passive Detection",
                    "tags": ["waf", "fingerprinting"],
                }
            )
        return findings
