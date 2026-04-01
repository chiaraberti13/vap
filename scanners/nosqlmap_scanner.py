"""NoSQLMap scanner wrapper."""
from __future__ import annotations

from dataclasses import dataclass
import subprocess
from typing import Any, Dict, List

from config import settings


@dataclass
class NosqlmapScanner:
    enable_live_scans: bool = False

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "nosqlmap",
                "status": "simulated",
                "findings": [
                    {
                        "tool": "nosqlmap",
                        "title": "Possibile superficie NoSQL injection",
                        "severity": "high",
                        "description": "NoSQLMap suggerisce possibili vettori d'injection lato datastore NoSQL.",
                        "recommendation": "Applicare query parametrizzate e validazione rigorosa input.",
                        "found_by": "NoSQLMap – Active Testing",
                    }
                ],
            }

        command = ["nosqlmap", "-u", target]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=settings.scan_timeout_seconds,
                check=False,
            )
        except FileNotFoundError:
            return {
                "tool": "nosqlmap",
                "status": "skipped",
                "message": "Tool NoSQLMap non installato.",
                "findings": [],
            }
        except subprocess.TimeoutExpired:
            return {
                "tool": "nosqlmap",
                "status": "timeout",
                "message": "Timeout durante l'esecuzione di NoSQLMap.",
                "findings": [],
            }

        findings = self._extract_findings(completed.stdout)
        return {
            "tool": "nosqlmap",
            "status": "executed" if completed.returncode == 0 else "completed_with_warnings",
            "findings": findings[: settings.max_findings],
        }

    def _extract_findings(self, output: str) -> List[Dict[str, Any]]:
        text = (output or "").lower()
        if not text:
            return []

        indicators = ["inject", "vulnerable", "mongodb", "couchdb", "redis"]
        if not any(token in text for token in indicators):
            return []

        severity = "high" if "vulnerable" in text or "inject" in text else "medium"
        return [
            {
                "tool": "nosqlmap",
                "title": "Potenziale NoSQL Injection rilevata",
                "severity": severity,
                "description": "NoSQLMap ha identificato indicatori coerenti con tentativi di NoSQL injection.",
                "evidence": output[:500],
                "recommendation": "Usare query sicure, type checks, rate limiting e monitoring anomalo.",
                "found_by": "NoSQLMap – Active Testing",
                "tags": ["nosql", "injection"],
            }
        ]
