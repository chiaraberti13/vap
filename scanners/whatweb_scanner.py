"""WhatWeb scanner wrapper."""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
import shutil
import subprocess
from typing import Any, Dict, Iterable, List, Optional, Tuple

from config import settings


CMS_TECH = {
    "wordpress",
    "joomla",
    "drupal",
    "magento",
    "typo3",
    "ghost",
    "shopify",
    "prestashop",
    "opencart",
}
FRAMEWORK_TECH = {
    "django",
    "flask",
    "laravel",
    "rails",
    "ruby on rails",
    "spring",
    "express",
    "asp.net",
    "asp.net mvc",
    "next.js",
    "nuxt.js",
}
JS_LIB_TECH = {
    "jquery",
    "react",
    "angular",
    "vue",
    "bootstrap",
    "lodash",
    "moment.js",
}
WAF_CDN_TECH = {
    "cloudflare": "CDN/WAF",
    "akamai": "CDN",
    "fastly": "CDN",
    "sucuri": "WAF",
    "imperva": "WAF",
    "incapsula": "WAF",
    "aws cloudfront": "CDN",
    "cloudfront": "CDN",
    "azure front door": "CDN",
}
SENSITIVE_HEADERS = {
    "server": "Espone dettagli sul server web.",
    "x-powered-by": "Espone tecnologia applicativa.",
    "x-aspnet-version": "Espone versione ASP.NET.",
    "x-aspnetmvc-version": "Espone versione ASP.NET MVC.",
    "x-generator": "Espone generatore del sito.",
}
VERSION_PATTERN = re.compile(r"\d+(?:\.\d+){0,3}")
CVE_DATABASE = {
    "jquery": [
        {
            "max_version": "3.4.1",
            "cves": ["CVE-2020-11022", "CVE-2020-11023"],
            "severity": "medium",
            "description": "XSS in jQuery < 3.5.0.",
        }
    ]
}


@dataclass
class WhatWebScanner:
    enable_live_scans: bool = False

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "whatweb",
                "status": "simulated",
                "findings": [
                    {
                        "title": "Tecnologia web identificata",
                        "severity": "info",
                        "description": "Simulazione: stack tecnologico rilevato.",
                        "recommendation": "Aggiornare componenti e ridurre banner.",
                    }
                ],
            }

        if not shutil.which("whatweb"):
            return {
                "tool": "whatweb",
                "status": "skipped",
                "message": "Tool whatweb non installato.",
                "findings": [],
            }

        command = ["whatweb", "--color=never", "--log-json=-", target]
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
                "tool": "whatweb",
                "status": "error",
                "message": "Timeout durante l'esecuzione di WhatWeb.",
                "findings": [],
            }

        findings = self._parse_output(completed.stdout)
        message = completed.stderr.strip() if completed.stderr else ""
        status = "executed" if completed.returncode == 0 else "error"
        if completed.returncode != 0 and not message:
            message = "Errore durante l'esecuzione di WhatWeb."

        return {
            "tool": "whatweb",
            "status": status,
            "message": message,
            "findings": findings,
        }

    def _parse_output(self, stdout: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue

            if not isinstance(payload, dict):
                continue

            plugins = payload.get("plugins", {}) if isinstance(payload.get("plugins"), dict) else {}
            headers = payload.get("headers", {}) if isinstance(payload.get("headers"), dict) else {}

            technologies = self._extract_technologies(plugins)
            if technologies:
                findings.append(
                    {
                        "title": "Tecnologie rilevate (WhatWeb)",
                        "severity": "info",
                        "description": self._format_tech_summary(technologies),
                        "recommendation": (
                            "Verificare versioni, disabilitare banner e aggiornare i componenti obsoleti."
                        ),
                        "technologies": technologies,
                    }
                )

            findings.extend(self._build_cve_findings(technologies))
            findings.extend(self._build_sensitive_header_findings(headers))
            waf_findings = self._build_waf_cdn_findings(plugins, headers)
            if waf_findings:
                findings.append(waf_findings)

        return findings

    def _extract_technologies(self, plugins: Dict[str, Any]) -> List[Dict[str, Any]]:
        technologies: List[Dict[str, Any]] = []
        for name, details in plugins.items():
            if not isinstance(details, dict):
                continue
            category = self._categorize_plugin(name)
            versions = self._extract_versions(details)
            technologies.append(
                {
                    "name": name,
                    "category": category or "other",
                    "versions": versions,
                }
            )
        return technologies

    def _categorize_plugin(self, name: str) -> Optional[str]:
        normalized = name.strip().lower()
        if normalized in CMS_TECH:
            return "cms"
        if normalized in FRAMEWORK_TECH:
            return "framework"
        if normalized in JS_LIB_TECH:
            return "js_library"
        return None

    def _extract_versions(self, details: Dict[str, Any]) -> List[str]:
        versions: List[str] = []
        for raw in self._normalize_values(details.get("version")):
            versions.extend(self._find_version_candidates(raw))
        for raw in self._normalize_values(details.get("string")):
            versions.extend(self._find_version_candidates(raw))
        return sorted({version for version in versions if version})

    def _find_version_candidates(self, raw: str) -> List[str]:
        if not raw:
            return []
        return VERSION_PATTERN.findall(str(raw))

    def _normalize_values(self, value: Any) -> Iterable[str]:
        if value is None:
            return []
        if isinstance(value, list):
            return [str(item) for item in value]
        return [str(value)]

    def _format_tech_summary(self, technologies: List[Dict[str, Any]]) -> str:
        grouped: Dict[str, List[str]] = {"cms": [], "framework": [], "js_library": [], "other": []}
        for tech in technologies:
            name = tech.get("name", "Sconosciuto")
            versions = ", ".join(tech.get("versions") or [])
            label = f"{name} ({versions})" if versions else name
            category = tech.get("category", "other")
            grouped.setdefault(category, []).append(label)

        parts = []
        if grouped["cms"]:
            parts.append(f"CMS: {', '.join(sorted(grouped['cms']))}")
        if grouped["framework"]:
            parts.append(f"Framework: {', '.join(sorted(grouped['framework']))}")
        if grouped["js_library"]:
            parts.append(f"Librerie JS: {', '.join(sorted(grouped['js_library']))}")
        if grouped["other"]:
            parts.append(f"Altre tecnologie: {', '.join(sorted(grouped['other']))}")
        return " | ".join(parts) if parts else "Nessuna tecnologia rilevata."

    def _build_cve_findings(self, technologies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for tech in technologies:
            name = str(tech.get("name", "")).lower()
            versions = tech.get("versions") or []
            if not versions:
                continue
            for version in versions:
                for entry in self._lookup_cves(name, version):
                    findings.append(
                        {
                            "title": f"CVE correlate per {tech.get('name')} {version}",
                            "severity": entry["severity"],
                            "description": entry["description"],
                            "recommendation": (
                                "Aggiornare alla versione più recente e verificare patch ufficiali."
                            ),
                            "cve": entry["cves"],
                            "technology": tech.get("name"),
                            "version": version,
                            "source": "local-cve-db",
                        }
                    )
        return findings

    def _lookup_cves(self, tech_name: str, version: str) -> List[Dict[str, Any]]:
        entries = CVE_DATABASE.get(tech_name, [])
        if not entries:
            return []
        parsed_version = self._parse_version(version)
        if parsed_version is None:
            return []
        matched: List[Dict[str, Any]] = []
        for entry in entries:
            max_version = self._parse_version(entry.get("max_version", ""))
            if max_version and self._version_lte(parsed_version, max_version):
                matched.append(entry)
        return matched

    def _parse_version(self, raw: str) -> Optional[Tuple[int, ...]]:
        if not raw:
            return None
        segments = VERSION_PATTERN.findall(raw)
        if not segments:
            return None
        version = segments[0]
        try:
            return tuple(int(part) for part in version.split("."))
        except ValueError:
            return None

    def _version_lte(self, left: Tuple[int, ...], right: Tuple[int, ...]) -> bool:
        max_len = max(len(left), len(right))
        padded_left = left + (0,) * (max_len - len(left))
        padded_right = right + (0,) * (max_len - len(right))
        return padded_left <= padded_right

    def _build_sensitive_header_findings(self, headers: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        exposed: List[str] = []
        for key, value in headers.items():
            normalized = str(key).lower()
            if normalized in SENSITIVE_HEADERS:
                exposed.append(f"{key}: {value}")

        if exposed:
            findings.append(
                {
                    "title": "Header HTTP sensibili esposti",
                    "severity": "low",
                    "description": (
                        "Sono stati rilevati header che possono esporre dettagli tecnologici: "
                        f"{'; '.join(exposed)}"
                    ),
                    "recommendation": "Rimuovere o mascherare gli header non necessari.",
                    "headers": exposed,
                }
            )

        return findings

    def _build_waf_cdn_findings(
        self, plugins: Dict[str, Any], headers: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        detected: List[str] = []
        for name in plugins.keys():
            normalized = name.lower()
            if normalized in WAF_CDN_TECH:
                detected.append(f"{name} ({WAF_CDN_TECH[normalized]})")

        header_keys = {key.lower(): value for key, value in headers.items()}
        if "cf-ray" in header_keys or "cf-cache-status" in header_keys:
            detected.append("Cloudflare (CDN/WAF)")
        if "x-akamai-transformed" in header_keys:
            detected.append("Akamai (CDN)")

        if not detected:
            return None

        unique = sorted(set(detected))
        return {
            "title": "Fingerprinting WAF/CDN",
            "severity": "info",
            "description": f"Servizi di protezione o CDN rilevati: {', '.join(unique)}.",
            "recommendation": (
                "Verificare la configurazione WAF/CDN e assicurarsi che le policy siano aggiornate."
            ),
            "waf_cdn": unique,
        }
