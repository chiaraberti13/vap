from report_generator import _owasp_classification_lines


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
