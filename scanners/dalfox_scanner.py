"""DalFox scanner wrapper."""
from __future__ import annotations

from dataclasses import dataclass
import json
import shutil
import subprocess
from tempfile import NamedTemporaryFile
from typing import Any, Dict, List

from config import settings


@dataclass
class DalfoxScanner:
    enable_live_scans: bool = False

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "dalfox",
                "status": "simulated",
                "findings": [
                    {
                        "tool": "dalfox",
                        "title": "Possibile vulnerabilità XSS identificata",
                        "severity": "high",
                        "description": "DalFox ha rilevato vettori XSS potenzialmente sfruttabili.",
                        "recommendation": "Applicare escaping contestuale e Content Security Policy robusta.",
                        "found_by": "DalFox – Active Testing",
                    }
                ],
            }

        if not shutil.which("dalfox"):
            return {
                "tool": "dalfox",
                "status": "skipped",
                "message": "Tool DalFox non installato.",
                "findings": [],
            }

        with NamedTemporaryFile(mode="w+", suffix=".json") as output_file:
            command = ["dalfox", "url", target, "--format", "json", "--output", output_file.name]
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
                    "tool": "dalfox",
                    "status": "timeout",
                    "message": "Timeout durante l'esecuzione di DalFox.",
                    "findings": [],
                }

            payload = self._load_json_output(output_file.name)
            findings = self._extract_findings(payload)
            return {
                "tool": "dalfox",
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
            evidence = str(row.get("evidence") or row.get("payload") or "").strip()
            if not evidence:
                continue
            param = str(row.get("param") or row.get("parameter") or "").strip()
            findings.append(
                {
                    "tool": "dalfox",
                    "title": "Cross-Site Scripting (XSS) rilevato",
                    "severity": "high",
                    "description": "DalFox ha identificato un possibile vettore XSS riflesso o DOM-based.",
                    "evidence": evidence,
                    "method": str(row.get("method") or "GET"),
                    "parameters": [param] if param else [],
                    "recommendation": "Validare input, applicare escaping output e CSP strict.",
                    "found_by": "DalFox – Active Testing",
                    "tags": ["xss", "injection"],
                }
            )
        return findings
