"""Enrichment e correlazione delle vulnerabilità."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
import shutil
import subprocess
from typing import Any, Dict, Iterable, List, Tuple

import requests

from config import settings
from false_positive_model import FalsePositiveModel, build_features


MITRE_CWE_MAPPING: Dict[str, List[Dict[str, Any]]] = {
    "CWE-79": [
        {
            "technique_id": "T1189",
            "technique_name": "Drive-by Compromise",
            "tactics": ["Initial Access"],
        }
    ],
    "CWE-89": [
        {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactics": ["Initial Access"],
        }
    ],
    "CWE-77": [
        {
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "tactics": ["Execution"],
        }
    ],
    "CWE-22": [
        {
            "technique_id": "T1006",
            "technique_name": "Direct Volume Access",
            "tactics": ["Defense Evasion"],
        }
    ],
}

KEYWORD_MITRE_MAPPING: List[Tuple[re.Pattern[str], Dict[str, Any]]] = [
    (
        re.compile(r"sql\s*injection", re.IGNORECASE),
        {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactics": ["Initial Access"],
        },
    ),
    (
        re.compile(r"xss|cross-site", re.IGNORECASE),
        {
            "technique_id": "T1189",
            "technique_name": "Drive-by Compromise",
            "tactics": ["Initial Access"],
        },
    ),
    (
        re.compile(r"command injection", re.IGNORECASE),
        {
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "tactics": ["Execution"],
        },
    ),
]


@dataclass
class EnrichmentSummary:
    nvd_hits: int = 0
    exploitdb_hits: int = 0


def enrich_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    enriched = [dict(item) for item in findings]
    summary = EnrichmentSummary()

    _apply_cve_enrichment(enriched, summary)
    _apply_mitre_mapping(enriched)
    _apply_false_positive_model(enriched)
    _apply_correlation(enriched)

    for item in enriched:
        item.setdefault("enrichment_summary", {})
        item["enrichment_summary"].update(
            {"nvd_hits": summary.nvd_hits, "exploitdb_hits": summary.exploitdb_hits}
        )

    return enriched


def _apply_cve_enrichment(findings: List[Dict[str, Any]], summary: EnrichmentSummary) -> None:
    cves = sorted({cve for cve in _extract_cves(findings)})
    if not cves:
        return

    nvd_payload = _fetch_nvd_metadata(cves)
    exploitdb_payload = _fetch_exploitdb_metadata(cves)

    for finding in findings:
        finding_cves = [cve for cve in finding.get("cve", []) if isinstance(cve, str)]
        nvd_items = [nvd_payload[cve] for cve in finding_cves if cve in nvd_payload]
        exploit_items = [exploitdb_payload[cve] for cve in finding_cves if cve in exploitdb_payload]

        if nvd_items:
            summary.nvd_hits += 1
            finding.setdefault("nvd", []).extend(nvd_items)
        if exploit_items:
            summary.exploitdb_hits += 1
            finding.setdefault("exploitdb", []).extend(exploit_items)

        if nvd_items or exploit_items:
            finding["cve_verified"] = True
        elif finding_cves:
            finding["cve_verified"] = False


def _extract_cves(findings: Iterable[Dict[str, Any]]) -> List[str]:
    cves: List[str] = []
    for finding in findings:
        for cve in finding.get("cve", []) or []:
            if isinstance(cve, str) and cve.startswith("CVE-"):
                cves.append(cve)
    return cves


def _fetch_nvd_metadata(cves: List[str]) -> Dict[str, Dict[str, Any]]:
    if not settings.enable_live_scans or not settings.nvd_api_key:
        return {}

    results: Dict[str, Dict[str, Any]] = {}
    for cve in cves[: settings.nvd_max_cves]:
        try:
            response = requests.get(
                settings.nvd_api_base_url,
                params={"cveId": cve},
                headers={"apiKey": settings.nvd_api_key},
                timeout=settings.nvd_timeout_seconds,
            )
            response.raise_for_status()
        except requests.RequestException:
            continue

        payload = response.json()
        vulnerabilities = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
        if not vulnerabilities:
            continue
        cve_item = vulnerabilities[0].get("cve", {}) if isinstance(vulnerabilities[0], dict) else {}
        descriptions = cve_item.get("descriptions", []) if isinstance(cve_item, dict) else []
        description = next(
            (desc.get("value") for desc in descriptions if desc.get("lang") == "en"),
            "",
        )

        metrics = cve_item.get("metrics", {}) if isinstance(cve_item, dict) else {}
        cvss_score = None
        cvss_vector = None
        if metrics:
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(key)
                if metric_list:
                    metric = metric_list[0]
                    data = metric.get("cvssData", {}) if isinstance(metric, dict) else {}
                    cvss_score = data.get("baseScore")
                    cvss_vector = data.get("vectorString")
                    break

        results[cve] = {
            "cve": cve,
            "description": description,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "source": "NVD",
        }
    return results


def _fetch_exploitdb_metadata(cves: List[str]) -> Dict[str, Dict[str, Any]]:
    if not settings.enable_live_scans:
        return {}
    if not shutil.which(settings.exploitdb_searchsploit_path):
        return {}

    results: Dict[str, Dict[str, Any]] = {}
    for cve in cves[: settings.exploitdb_max_cves]:
        try:
            completed = subprocess.run(
                [settings.exploitdb_searchsploit_path, "--cve", cve, "-j"],
                capture_output=True,
                text=True,
                timeout=settings.exploitdb_timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            continue

        if completed.returncode != 0:
            continue

        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError:
            continue

        results_list = payload.get("RESULTS_EXPLOIT", []) if isinstance(payload, dict) else []
        if not results_list:
            continue
        results[cve] = {
            "cve": cve,
            "exploits": results_list,
            "source": "ExploitDB",
        }
    return results


def _apply_mitre_mapping(findings: List[Dict[str, Any]]) -> None:
    for finding in findings:
        techniques = []
        cwe_list = [str(cwe).upper() for cwe in finding.get("cwe", []) if cwe]
        for cwe in cwe_list:
            techniques.extend(MITRE_CWE_MAPPING.get(cwe, []))

        title = str(finding.get("title", ""))
        description = str(finding.get("description", ""))
        for pattern, technique in KEYWORD_MITRE_MAPPING:
            if pattern.search(title) or pattern.search(description):
                techniques.append(technique)

        if techniques:
            unique = {(tech["technique_id"], tech["technique_name"]): tech for tech in techniques}
            finding["mitre_attack"] = list(unique.values())


def _apply_false_positive_model(findings: List[Dict[str, Any]]) -> None:
    model = FalsePositiveModel()
    for finding in findings:
        features = build_features(finding)
        score = model.predict_proba(features)
        label = "basso" if score < settings.false_positive_medium_threshold else "medio"
        if score >= settings.false_positive_high_threshold:
            label = "alto"

        finding["false_positive_score"] = round(score, 2)
        finding["false_positive_label"] = label
        finding["confidence"] = round(1 - score, 2)
        finding["false_positive_model"] = {
            "version": model.version,
            "top_factors": model.top_factors(features),
        }


def _apply_correlation(findings: List[Dict[str, Any]]) -> None:
    groups: Dict[str, Dict[str, Any]] = {}
    for finding in findings:
        key = _correlation_key(finding)
        if key not in groups:
            groups[key] = {
                "id": hashlib.sha256(key.encode("utf-8")).hexdigest()[:8],
                "tools": set(),
                "count": 0,
            }
        groups[key]["count"] += 1
        tool = finding.get("tool")
        if tool:
            groups[key]["tools"].add(tool)

    for finding in findings:
        key = _correlation_key(finding)
        group = groups[key]
        finding["correlation_id"] = group["id"]
        finding["related_findings"] = group["count"]
        finding["related_tools"] = sorted(group["tools"])


def _correlation_key(finding: Dict[str, Any]) -> str:
    title = str(finding.get("title", "")).strip().lower()
    host = str(finding.get("host", "")).strip().lower()
    path = str(finding.get("path", "")).strip().lower()
    cves = ",".join(sorted([str(cve) for cve in finding.get("cve", []) if cve]))
    cwes = ",".join(sorted([str(cwe) for cwe in finding.get("cwe", []) if cwe]))
    return f"{title}|{host}|{path}|{cves}|{cwes}"
