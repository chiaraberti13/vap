"""Nikto scanner wrapper."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict
import shutil


@dataclass
class NiktoScanner:
    enable_live_scans: bool = False

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "nikto",
                "status": "simulated",
                "findings": [
                    {
                        "title": "Configurazione HTTP potenzialmente debole",
                        "severity": "medium",
                        "description": "Simulazione: header di sicurezza mancanti.",
                        "recommendation": "Implementare CSP, HSTS e X-Frame-Options.",
                    }
                ],
            }

        if not shutil.which("nikto"):
            return {
                "tool": "nikto",
                "status": "skipped",
                "message": "Tool nikto non installato.",
                "findings": [],
            }

        return {
            "tool": "nikto",
            "status": "executed",
            "message": "Esecuzione live non implementata in questa versione.",
            "findings": [],
        }
