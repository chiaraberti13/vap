"""Wapiti scanner wrapper."""
from __future__ import annotations

from dataclasses import dataclass
import json
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List

from config import settings


@dataclass
class WapitiScanner:
    enable_live_scans: bool = False

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "wapiti",
                "status": "simulated",
                "findings": [
                    {
                        "title": "Possibile configurazione debole",
                        "severity": "low",
                        "description": "Simulazione: pagina con potenziale esposizione di dati.",
                        "recommendation": "Rivedere i permessi e nascondere informazioni sensibili.",
                        "cwe": ["CWE-200"],
                        "tags": ["owasp-a02", "wapiti"],
                    }
                ],
            }

        if not shutil.which(settings.wapiti_path):
            return {
                "tool": "wapiti",
                "status": "skipped",
                "message": "Tool Wapiti non installato.",
                "findings": [],
            }

        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = f"{tmp_dir}/wapiti.json"
            command = [
                settings.wapiti_path,
                "-u",
                target,
                "-f",
                "json",
                "-o",
                output_path,
            ]
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
                    "tool": "wapiti",
                    "status": "error",
                    "message": "Timeout durante l'esecuzione di Wapiti.",
                    "findings": [],
                }

            if completed.returncode != 0:
                message = completed.stderr.strip() if completed.stderr else "Errore durante Wapiti."
                return {
                    "tool": "wapiti",
                    "status": "error",
                    "message": message,
                    "findings": [],
                }

            try:
                with open(output_path, "r", encoding="utf-8") as handle:
                    payload = json.load(handle)
            except (OSError, json.JSONDecodeError):
                return {
                    "tool": "wapiti",
                    "status": "error",
                    "message": "Output Wapiti non valido.",
                    "findings": [],
                }

        findings: List[Dict[str, Any]] = []
        vulnerabilities = payload.get("vulnerabilities", {}) if isinstance(payload, dict) else {}
        for vuln_type, items in vulnerabilities.items():
            if not isinstance(items, list):
                continue
            for item in items:
                if not isinstance(item, dict):
                    continue
                findings.append(
                    {
                        "title": f"{vuln_type.title()} rilevata da Wapiti",
                        "severity": "medium",
                        "description": item.get("info", ""),
                        "recommendation": "Mitigare la vulnerabilità seguendo le best practice.",
                        "host": item.get("host", ""),
                        "path": item.get("path", ""),
                        "parameter": item.get("parameter", ""),
                        "tags": ["wapiti", vuln_type],
                    }
                )
        return {
            "tool": "wapiti",
            "status": "executed",
            "findings": findings,
        }
