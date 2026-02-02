"""Subfinder scanner wrapper."""
from __future__ import annotations

from dataclasses import dataclass
import json
import shutil
import socket
import subprocess
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import requests

from config import settings


TAKEOVER_SIGNATURES = {
    "s3.amazonaws.com": "Amazon S3",
    "s3-website": "Amazon S3 Website",
    "cloudfront.net": "Amazon CloudFront",
    "herokuapp.com": "Heroku",
    "github.io": "GitHub Pages",
    "azurewebsites.net": "Azure App Service",
    "trafficmanager.net": "Azure Traffic Manager",
    "cloudapp.net": "Azure CloudApp",
    "pantheonsite.io": "Pantheon",
    "surge.sh": "Surge",
    "fastly.net": "Fastly",
    "readme.io": "Readme",
}


@dataclass
class SubfinderScanner:
    enable_live_scans: bool = False

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "subfinder",
                "status": "simulated",
                "findings": [
                    {
                        "title": "Sottodomini individuati",
                        "severity": "info",
                        "description": "Simulazione: elenco di sottodomini pubblici.",
                        "recommendation": "Revisionare DNS e rimuovere asset non necessari.",
                    }
                ],
            }

        domain = self._normalize_domain(target)
        sources: Dict[str, Any] = {"subfinder": 0, "securitytrails": 0, "virustotal": 0, "shodan": 0}
        errors: List[str] = []
        subdomains: Set[str] = set()

        if shutil.which("subfinder"):
            found, error = self._run_subfinder(domain)
            subdomains.update(found)
            sources["subfinder"] = len(found)
            if error:
                errors.append(error)
        else:
            errors.append("Tool subfinder non installato: uso solo integrazioni API.")

        external_subdomains, external_errors = self._collect_external_subdomains(domain)
        for key, value in external_subdomains.items():
            subdomains.update(value)
            sources[key] = len(value)
        errors.extend(external_errors)

        if not subdomains:
            return {
                "tool": "subfinder",
                "status": "completed_with_warnings" if errors else "executed",
                "target": domain,
                "message": "Nessun sottodominio rilevato.",
                "errors": errors,
                "findings": [],
            }

        resolved, unresolved = self._resolve_subdomains(sorted(subdomains))
        takeover_candidates = self._detect_takeovers(unresolved)

        findings = [
            {
                "title": "Sottodomini individuati",
                "severity": "info",
                "description": (
                    f"Trovati {len(subdomains)} sottodomini per {domain}. "
                    f"Risolti: {len(resolved)} | Non risolti: {len(unresolved)}."
                ),
                "recommendation": "Verificare la necessità degli asset esposti e consolidare i DNS.",
            }
        ]

        if unresolved:
            findings.append(
                {
                    "title": "Sottodomini non risolti",
                    "severity": "low",
                    "description": "Alcuni sottodomini non risolvono correttamente.",
                    "recommendation": "Rimuovere record obsoleti o correggere la configurazione DNS.",
                }
            )

        if takeover_candidates:
            findings.append(
                {
                    "title": "Potenziali takeover di sottodominio",
                    "severity": "high",
                    "description": (
                        "Rilevati record CNAME verso provider noti senza risoluzione attiva."
                    ),
                    "recommendation": "Verificare la proprietà del servizio o rimuovere i record CNAME.",
                }
            )

        if errors:
            findings.append(
                {
                    "title": "Avvisi integrazione Subfinder/API",
                    "severity": "low",
                    "description": "Alcune fonti non hanno risposto correttamente.",
                    "recommendation": "Verificare le API key e ripetere la scansione.",
                }
            )

        status = "executed" if not errors else "completed_with_warnings"
        return {
            "tool": "subfinder",
            "status": status,
            "target": domain,
            "sources": sources,
            "errors": errors,
            "subdomains": sorted(subdomains),
            "resolved": resolved,
            "unresolved": unresolved,
            "takeover_candidates": takeover_candidates,
            "export_targets": sorted(resolved.keys()),
            "findings": findings,
        }

    def _normalize_domain(self, target: str) -> str:
        if "://" in target:
            parsed = urlparse(target)
            return parsed.hostname or target
        return target.split("/")[0]

    def _run_subfinder(self, domain: str) -> Tuple[Set[str], Optional[str]]:
        command = ["subfinder", "-d", domain, "-json"]
        if settings.subfinder_sources:
            command.extend(["-sources", settings.subfinder_sources])
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=settings.scan_timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return set(), "Timeout durante l'esecuzione di Subfinder."

        if completed.returncode != 0 and not completed.stdout:
            return set(), (completed.stderr.strip() or "Errore durante Subfinder.")

        subdomains = set()
        for line in completed.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = payload.get("host") or payload.get("hostname")
            if host:
                subdomains.add(host.lower())
        return subdomains, None

    def _collect_external_subdomains(self, domain: str) -> Tuple[Dict[str, Set[str]], List[str]]:
        results: Dict[str, Set[str]] = {"securitytrails": set(), "virustotal": set(), "shodan": set()}
        errors: List[str] = []

        if settings.securitytrails_api_key:
            subdomains, error = self._query_securitytrails(domain)
            results["securitytrails"] = subdomains
            if error:
                errors.append(error)

        if settings.virustotal_api_key:
            subdomains, error = self._query_virustotal(domain)
            results["virustotal"] = subdomains
            if error:
                errors.append(error)

        if settings.shodan_api_key:
            subdomains, error = self._query_shodan(domain)
            results["shodan"] = subdomains
            if error:
                errors.append(error)

        return results, errors

    def _query_securitytrails(self, domain: str) -> Tuple[Set[str], Optional[str]]:
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        headers = {"APIKEY": settings.securitytrails_api_key}
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            payload = response.json()
        except requests.RequestException as exc:
            return set(), f"SecurityTrails: {exc}"
        except ValueError:
            return set(), "SecurityTrails: risposta JSON non valida."

        subdomains = {
            f"{sub}.{domain}".lower()
            for sub in payload.get("subdomains", [])
            if isinstance(sub, str)
        }
        return subdomains, None

    def _query_virustotal(self, domain: str) -> Tuple[Set[str], Optional[str]]:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=200"
        headers = {"x-apikey": settings.virustotal_api_key}
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            payload = response.json()
        except requests.RequestException as exc:
            return set(), f"VirusTotal: {exc}"
        except ValueError:
            return set(), "VirusTotal: risposta JSON non valida."

        subdomains = {
            item.get("id", "").lower()
            for item in payload.get("data", [])
            if isinstance(item, dict) and item.get("id")
        }
        return subdomains, None

    def _query_shodan(self, domain: str) -> Tuple[Set[str], Optional[str]]:
        url = f"https://api.shodan.io/dns/domain/{domain}?key={settings.shodan_api_key}"
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            payload = response.json()
        except requests.RequestException as exc:
            return set(), f"Shodan: {exc}"
        except ValueError:
            return set(), "Shodan: risposta JSON non valida."

        subdomains = {
            f"{sub}.{domain}".lower()
            for sub in payload.get("subdomains", [])
            if isinstance(sub, str)
        }
        return subdomains, None

    def _resolve_subdomains(self, subdomains: List[str]) -> Tuple[Dict[str, List[str]], List[str]]:
        socket.setdefaulttimeout(3)
        limit = settings.subfinder_resolve_limit
        resolved: Dict[str, List[str]] = {}
        unresolved: List[str] = []

        for subdomain in subdomains[:limit]:
            try:
                _, _, addresses = socket.gethostbyname_ex(subdomain)
                if addresses:
                    resolved[subdomain] = addresses
                else:
                    unresolved.append(subdomain)
            except socket.gaierror:
                unresolved.append(subdomain)

        return resolved, unresolved

    def _detect_takeovers(self, unresolved: List[str]) -> List[Dict[str, str]]:
        candidates: List[Dict[str, str]] = []
        for subdomain in unresolved:
            cname = self._lookup_cname(subdomain)
            if not cname:
                continue
            provider = self._match_takeover_provider(cname)
            if provider:
                candidates.append(
                    {
                        "subdomain": subdomain,
                        "cname": cname,
                        "provider": provider,
                    }
                )
        return candidates

    def _lookup_cname(self, hostname: str) -> Optional[str]:
        if shutil.which("dig"):
            try:
                output = subprocess.run(
                    ["dig", "+short", "CNAME", hostname],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                ).stdout
            except subprocess.TimeoutExpired:
                return None
            cname = output.strip().splitlines()
            return cname[0].strip().rstrip(".") if cname else None

        if shutil.which("nslookup"):
            try:
                output = subprocess.run(
                    ["nslookup", "-type=CNAME", hostname],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                ).stdout
            except subprocess.TimeoutExpired:
                return None
            for line in output.splitlines():
                if "canonical name" in line:
                    return line.split("=", maxsplit=1)[-1].strip().rstrip(".")

        return None

    def _match_takeover_provider(self, cname: str) -> Optional[str]:
        cname_lower = cname.lower()
        for signature, provider in TAKEOVER_SIGNATURES.items():
            if signature in cname_lower:
                return provider
        return None
