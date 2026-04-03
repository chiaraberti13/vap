from report_generator import (
    _ensure_list,
    _is_technology_finding,
    _normalize_cve_details,
    _normalize_technologies,
    _owasp_classification_lines,
    _scan_parameters_rows,
    _scan_type_label,
    _technology_category_icon,
    _sorted_scan_coverage,
)


def test_owasp_classification_lines_includes_all_versions_with_fallbacks():
    lines = _owasp_classification_lines(None, None, None, ["owasp-a03"])

    assert lines == [
        "OWASP 2017: Non classificato",
        "OWASP 2021: owasp-a03",
        "OWASP 2025: Non classificato",
    ]


def test_owasp_classification_lines_prefers_explicit_values():
    lines = _owasp_classification_lines(
        "A1:2017 - Injection",
        "A03:2021 - Injection",
        "A03:2025 - Injection",
        ["owasp-a03"],
    )

    assert lines == [
        "OWASP 2017: A1:2017 - Injection",
        "OWASP 2021: A03:2021 - Injection",
        "OWASP 2025: A03:2025 - Injection",
    ]


def test_technology_category_icon_defaults_and_known_mapping():
    assert _technology_category_icon("Web Server") == "🖥️"
    assert _technology_category_icon("Unknown Category") == "🔧"


def test_is_technology_finding_matches_whatweb_tool_or_title():
    assert _is_technology_finding({"tool": "WhatWeb"}) is True
    assert _is_technology_finding({"title": "Tecnologie rilevate"}) is True
    assert _is_technology_finding({"title": "Generic issue", "tags": ["technology"]}) is True
    assert _is_technology_finding({"title": "Generic issue", "tool": "nikto"}) is False



def test_sorted_scan_coverage_orders_ports_and_deduplicates_tests():
    coverage = {
        "Categoria Web": ["Nikto headers", "Nikto headers", ""],
        "Porta 443": ["TLS check", "HTTP security headers"],
        "Porta 80": ["Redirect probe"],
    }

    assert _sorted_scan_coverage(coverage) == [
        ("Porta 80", ["Redirect probe"]),
        ("Porta 443", ["HTTP security headers", "TLS check"]),
        ("Categoria Web", ["Nikto headers"]),
    ]


def test_scan_parameters_rows_prioritizes_required_fields_and_enumerate_flags():
    params = {
        "authentication": "token",
        "detection_mode": "passive",
        "enumerate_plugins": True,
        "enumerate_users": False,
    }

    assert _scan_parameters_rows("https://target.local", "wordpress", params) == [
        ("target", "https://target.local"),
        ("scan_type", "wordpress"),
        ("authentication", "token"),
        ("detection_mode", "passive"),
        ("enumerate_plugins", "True"),
        ("enumerate_users", "False"),
    ]


def test_scan_type_label_includes_profile_details():
    assert _scan_type_label("light") == "Light (surface checks only)"
    assert _scan_type_label("wordpress") == "WordPress – Passive/Targeted"
    assert _scan_type_label("nmap") == "Nmap – Network/Port Enumeration"


def test_scan_type_label_falls_back_to_raw_value_for_unknown_types():
    assert _scan_type_label("custom-scan") == "custom-scan"


def test_ensure_list_normalizes_scalars_and_sequences():
    assert _ensure_list(None) == []
    assert _ensure_list("value") == ["value"]
    assert _ensure_list(("a", "b")) == ["a", "b"]


def test_normalize_cve_details_accepts_list_payloads():
    details = _normalize_cve_details([
        {"cve": "CVE-2024-0001", "cvss": 9.8},
        {"id": "CVE-2024-0002", "summary": "test"},
        "invalid",
    ])

    assert details == {
        "CVE-2024-0001": {"cve": "CVE-2024-0001", "cvss": 9.8},
        "CVE-2024-0002": {"id": "CVE-2024-0002", "summary": "test"},
    }


def test_normalize_technologies_filters_non_dict_entries():
    normalized = _normalize_technologies([
        {"software": "nginx", "version": "1.26", "category": "Web Server"},
        "noise",
        123,
    ])

    assert normalized == [{"software": "nginx", "version": "1.26", "category": "Web Server"}]
