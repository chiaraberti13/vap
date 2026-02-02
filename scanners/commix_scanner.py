"""Commix scanner wrapper."""
from __future__ import annotations

from dataclasses import dataclass
import re
import shlex
import shutil
import subprocess
from typing import Any, Dict, List

from config import settings


COMMIX_VULN_REGEX = re.compile(r"vulnerable|command injection", re.IGNORECASE)


@dataclass
class CommixScanner:
    enable_live_scans: bool = False

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "commix",
                "status": "simulated",
                "findings": [
                    {
                        "title": "Possibile command injection",
                        "severity": "high",
                        "description": "Simulazione: parametro esposto a command injection.",
                        "recommendation": "Eseguire escaping e usare allowlist per input utente.",
                        "cwe": ["CWE-77"],
                        "tags": ["owasp-a03", "command-injection"],
                    }
                ],
            }

        if not shutil.which(settings.commix_path):
            return {
                "tool": "commix",
                "status": "skipped",
                "message": "Tool commix non installato.",
                "findings": [],
            }

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
                "tool": "commix",
                "status": "error",
                "message": "Timeout durante l'esecuzione di commix.",
                "findings": [],
            }

        findings = self._parse_findings(completed.stdout)
        message = completed.stderr.strip() if completed.stderr else ""
        status = "executed" if completed.returncode == 0 else "error"
        if completed.returncode != 0 and not message:
            message = "Errore durante l'esecuzione di commix."

        return {
            "tool": "commix",
            "status": status,
            "message": message,
            "findings": findings,
        }

    def _build_command(self, target: str) -> List[str]:
        command = [settings.commix_path, "--url", target, "--batch"]
        if settings.commix_additional_args:
            command.extend(shlex.split(settings.commix_additional_args))
        return command

    def _parse_findings(self, stdout: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if COMMIX_VULN_REGEX.search(stdout or ""):
            findings.append(
                {
                    "title": "Possibile command injection",
                    "severity": "high",
                    "description": "Commix ha individuato un possibile punto di command injection.",
                    "recommendation": "Sanitizzare input e disabilitare shell execution diretta.",
                    "cwe": ["CWE-77"],
                    "tags": ["owasp-a03", "command-injection"],
                }
            )
        return findings
