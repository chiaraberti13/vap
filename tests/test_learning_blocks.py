"""Test dei blocchi didattici per finding nel dettaglio scansione."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import _build_confidence_rubric_for_finding, _build_learning_blocks_for_finding


def test_learning_blocks_use_impact_and_recommendation_when_present() -> None:
    finding = {
        "title": "SQL Injection su parametro id",
        "severity": "high",
        "impact": "L'attaccante può leggere dati sensibili dal database.",
        "recommendation": "Usare query parametrizzate e validazione server-side.",
    }

    blocks = _build_learning_blocks_for_finding(finding)

    assert "SQL Injection su parametro id" in blocks["junior_explanation"]
    assert blocks["business_risk"] == finding["impact"]
    assert blocks["manual_verification"] == finding["recommendation"]
    assert "OWASP Top 10" in blocks["next_skill"]


def test_learning_blocks_fallbacks_for_missing_fields() -> None:
    finding = {
        "title": "Header informativo mancante",
        "severity": "unexpected",
    }

    blocks = _build_learning_blocks_for_finding(finding)

    assert "Header informativo mancante" in blocks["junior_explanation"]
    assert "segnale informativo" in blocks["business_risk"]
    assert "verifica manuale controllata" in blocks["manual_verification"]
    assert "severità info" in blocks["next_skill"]


def test_confidence_rubric_confirmed_when_finding_is_confirmed() -> None:
    rubric = _build_confidence_rubric_for_finding({"confirmed": True, "confidence": 0.2})

    assert rubric["level"] == "confirmed"
    assert rubric["label"] == "Confirmed"


def test_confidence_rubric_needs_validation_when_false_positive_risk_is_high() -> None:
    rubric = _build_confidence_rubric_for_finding(
        {"confirmed": False, "confidence": 0.75, "false_positive_label": "alto"}
    )

    assert rubric["level"] == "needs-validation"
    assert rubric["label"] == "Needs validation"
