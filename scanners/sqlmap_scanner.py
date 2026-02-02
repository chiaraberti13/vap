"""SQLMap scanner wrapper."""
from __future__ import annotations

from dataclasses import dataclass
import re
import shlex
import shutil
import subprocess
from typing import Any, Dict, List

from config import settings


SQLMAP_PARAM_REGEX = re.compile(r"parameter '([^']+)' is vulnerable", re.IGNORECASE)


@dataclass
class SqlmapScanner:
    enable_live_scans: bool = False

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "sqlmap",
                "status": "simulated",
                "findings": [
                    {
                        "title": "Possibile SQL Injection",
                        "severity": "high",
                        "description": "Simulazione: input potenzialmente vulnerabile a SQL injection.",
                        "recommendation": "Usare query parametrizzate e validare tutti gli input.",
                        "cwe": ["CWE-89"],
                        "tags": ["owasp-a03", "sql-injection"],
                    }
                ],
            }

        if not shutil.which(settings.sqlmap_path):
            return {
                "tool": "sqlmap",
                "status": "skipped",
                "message": "Tool sqlmap non installato.",
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
                "tool": "sqlmap",
                "status": "error",
                "message": "Timeout durante l'esecuzione di sqlmap.",
                "findings": [],
            }

        findings = self._parse_findings(completed.stdout)
        message = completed.stderr.strip() if completed.stderr else ""
        status = "executed" if completed.returncode == 0 else "error"
        if completed.returncode != 0 and not message:
            message = "Errore durante l'esecuzione di sqlmap."

        return {
            "tool": "sqlmap",
            "status": status,
            "message": message,
            "findings": findings,
        }

    def _build_command(self, target: str) -> List[str]:
        command = [
            settings.sqlmap_path,
            "-u",
            target,
            "--batch",
            "--level",
            str(settings.sqlmap_level),
            "--risk",
            str(settings.sqlmap_risk),
            "--crawl",
            str(settings.sqlmap_crawl_depth),
        ]
        if settings.sqlmap_forms:
            command.append("--forms")
        if settings.sqlmap_additional_args:
            command.extend(shlex.split(settings.sqlmap_additional_args))
        return command

    def _parse_findings(self, stdout: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for line in stdout.splitlines():
            match = SQLMAP_PARAM_REGEX.search(line)
            if not match:
                continue
            parameter = match.group(1)
            findings.append(
                {
                    "title": f"SQL Injection su parametro {parameter}",
                    "severity": "high",
                    "description": "SQLMap ha individuato un possibile vettore di SQL injection.",
                    "recommendation": "Usare query parametrizzate e disabilitare l'output di errori SQL.",
                    "parameter": parameter,
                    "cwe": ["CWE-89"],
                    "tags": ["owasp-a03", "sql-injection"],
                }
            )
        return findings
