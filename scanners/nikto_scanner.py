"""Nikto scanner wrapper."""
from __future__ import annotations

from dataclasses import dataclass
import json
import shutil
import subprocess
from typing import Any, Dict, List

from config import settings


SENSITIVE_PATH_HINTS = (
    ".git",
    ".env",
    ".bak",
    ".backup",
    ".old",
    ".swp",
    ".zip",
    ".tar.gz",
    ".sql",
)


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

        command = ["nikto", "-h", target, "-Format", "json"]
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
                "tool": "nikto",
                "status": "timeout",
                "message": "Timeout durante l'esecuzione di Nikto.",
                "findings": [],
            }

        output = completed.stdout.strip()
        if not output:
            message = completed.stderr.strip() or "Output Nikto vuoto."
            return {
                "tool": "nikto",
                "status": "error",
                "message": message,
                "findings": [],
            }

        payload = self._parse_json_output(output)
        if payload is None:
            return {
                "tool": "nikto",
                "status": "error",
                "message": "Impossibile interpretare l'output JSON di Nikto.",
                "findings": [],
            }

        items = self._extract_vulnerabilities(payload)
        findings = [self._build_finding(item) for item in items]
        findings = [item for item in findings if item]

        status = "executed" if completed.returncode == 0 else "completed_with_warnings"
        return {
            "tool": "nikto",
            "status": status,
            "target": target,
            "findings": findings[: settings.max_findings],
        }

    def _parse_json_output(self, output: str) -> Dict[str, Any] | None:
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            start = output.find("{")
            end = output.rfind("}")
            if start == -1 or end == -1:
                return None
            try:
                return json.loads(output[start : end + 1])
            except json.JSONDecodeError:
                return None

    def _extract_vulnerabilities(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        if "vulnerabilities" in payload:
            return payload.get("vulnerabilities", [])
        if "scan" in payload and isinstance(payload["scan"], dict):
            scan_payload = payload["scan"]
            if "vulnerabilities" in scan_payload:
                return scan_payload.get("vulnerabilities", [])
        if "vuln" in payload:
            return payload.get("vuln", [])

        for value in payload.values():
            if isinstance(value, list) and value and isinstance(value[0], dict):
                return value
        return []

    def _build_finding(self, item: Dict[str, Any]) -> Dict[str, Any] | None:
        message = item.get("msg") or item.get("message") or item.get("description")
        if not message:
            return None

        uri = item.get("uri") or item.get("path") or ""
        method = item.get("method") or "GET"
        references = item.get("references") or item.get("ref") or []
        if isinstance(references, str):
            references = [references]

        severity = self._classify_severity(message, uri)
        title = self._title_from_message(message, uri)

        description = f"{message}"
        if uri:
            description = f"{description} (Endpoint: {method} {uri})"
        if references:
            description = f"{description}. Riferimenti: {', '.join(references)}"

        return {
            "title": title,
            "severity": severity,
            "description": description,
            "recommendation": self._recommendation_for_item(message, uri),
        }

    def _classify_severity(self, message: str, uri: str) -> str:
        message_lower = message.lower()
        uri_lower = uri.lower()

        if "path traversal" in message_lower or "../" in message_lower:
            return "high"
        if "directory listing" in message_lower or "directory indexing" in message_lower:
            return "medium"
        if any(hint in uri_lower for hint in SENSITIVE_PATH_HINTS):
            return "high"
        if "ssl" in message_lower or "tls" in message_lower or "certificate" in message_lower:
            return "medium"
        if "x-frame-options" in message_lower or "content-security-policy" in message_lower:
            return "medium"
        if "missing" in message_lower and "header" in message_lower:
            return "low"
        return "low"

    def _title_from_message(self, message: str, uri: str) -> str:
        message_lower = message.lower()
        uri_lower = uri.lower()
        if "path traversal" in message_lower:
            return "Possibile path traversal rilevato"
        if "directory listing" in message_lower or "directory indexing" in message_lower:
            return "Directory listing abilitata"
        if any(hint in uri_lower for hint in SENSITIVE_PATH_HINTS):
            return "File sensibile esposto"
        if "ssl" in message_lower or "tls" in message_lower:
            return "Configurazione SSL/TLS potenzialmente debole"
        return "Vulnerabilità web rilevata"

    def _recommendation_for_item(self, message: str, uri: str) -> str:
        message_lower = message.lower()
        uri_lower = uri.lower()
        if "path traversal" in message_lower or "../" in message_lower:
            return "Validare gli input e limitare l'accesso ai percorsi del filesystem."
        if "directory listing" in message_lower or "directory indexing" in message_lower:
            return "Disabilitare l'indicizzazione directory sul web server."
        if any(hint in uri_lower for hint in SENSITIVE_PATH_HINTS):
            return "Rimuovere i file sensibili dall'area web o proteggerli con access control."
        if "ssl" in message_lower or "tls" in message_lower:
            return "Aggiornare cipher suite e abilitare solo TLS 1.2+."
        if "header" in message_lower:
            return "Configurare header di sicurezza (CSP, HSTS, X-Frame-Options)."
        return "Applicare patch e hardening secondo le best practice OWASP."
