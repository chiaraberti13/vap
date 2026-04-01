from report_generator import (
    _is_technology_finding,
    _owasp_classification_lines,
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
