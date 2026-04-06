from pathlib import Path


SCAN_CATALOG_JS = Path(__file__).resolve().parents[1] / "static/js/scan-catalog.js"


def test_scan_catalog_frontend_escapes_dynamic_html_content():
    content = SCAN_CATALOG_JS.read_text(encoding="utf-8")

    assert "function escapeHtml" in content
    assert ".replace(/&/g, \"&amp;\")" in content
    assert "const displayName = escapeHtml(entry.display_name);" in content
    assert "const learningObjective = escapeHtml(entry.learning_objective);" in content
    assert "const owaspTags = escapeHtml(((entry.owasp_tags || []).slice(0, 2)).join(\", \"));" in content


def test_scan_catalog_compare_button_binding_is_fail_closed():
    content = SCAN_CATALOG_JS.read_text(encoding="utf-8")

    assert "if (!compareButton)" in content
    assert "cardsNode.appendChild(card);" in content
    assert "return;" in content
