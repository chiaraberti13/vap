"""XSStrike scanner wrapper."""
from __future__ import annotations

from dataclasses import dataclass
import re
import shlex
import shutil
import subprocess
from typing import Any, Dict, List

from config import settings


XSS_VULN_REGEX = re.compile(r"vulnerable|xss", re.IGNORECASE)


@dataclass
class XsstrikeScanner:
    enable_live_scans: bool = False

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "xsstrike",
                "status": "simulated",
                "findings": [
                    {
                        "title": "Possibile XSS riflesso",
                        "severity": "medium",
                        "description": "Simulazione: parametri riflessi senza escaping.",
                        "recommendation": "Applicare escaping output e CSP rigorosa.",
                        "cwe": ["CWE-79"],
                        "tags": ["owasp-a03", "xss"],
                    }
                ],
            }

        if not shutil.which(settings.xsstrike_path):
            return {
                "tool": "xsstrike",
                "status": "skipped",
                "message": "Tool XSStrike non installato.",
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
                "tool": "xsstrike",
                "status": "error",
                "message": "Timeout durante l'esecuzione di XSStrike.",
                "findings": [],
            }

        findings = self._parse_findings(completed.stdout)
        message = completed.stderr.strip() if completed.stderr else ""
        status = "executed" if completed.returncode == 0 else "error"
        if completed.returncode != 0 and not message:
            message = "Errore durante l'esecuzione di XSStrike."

        return {
            "tool": "xsstrike",
            "status": status,
            "message": message,
            "findings": findings,
        }

    def _build_command(self, target: str) -> List[str]:
        command = [settings.xsstrike_path, "-u", target]
        if settings.xsstrike_crawl:
            command.append("--crawl")
        if settings.xsstrike_additional_args:
            command.extend(shlex.split(settings.xsstrike_additional_args))
        return command

    def _parse_findings(self, stdout: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if not stdout:
            return findings
        if XSS_VULN_REGEX.search(stdout):
            findings.append(
                {
                    "title": "Possibile XSS rilevata",
                    "severity": "medium",
                    "description": "XSStrike ha identificato un possibile vettore XSS.",
                    "recommendation": "Applicare escaping output e validazione input lato server.",
                    "cwe": ["CWE-79"],
                    "tags": ["owasp-a03", "xss"],
                }
            )
        return findings
