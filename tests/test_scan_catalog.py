"""Test di coerenza tra catalogo didattico e tipi di scansione runtime."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app
from app import SCAN_TYPES
from scan_catalog import SCAN_CATALOG, get_tool_descriptions
from scanner_engine import PROFILE_SCANNERS_MAP, SCAN_TYPE_CHOICES, SCANNERS_MAP


def test_every_scanner_module_has_a_description() -> None:
    """Ogni modulo scanner (anche le varianti di profilo) deve avere una descrizione."""
    descriptions = get_tool_descriptions()
    module_ids = set(SCANNERS_MAP) | set(PROFILE_SCANNERS_MAP)
    missing = sorted(module_ids - set(descriptions))
    assert not missing, f"Descrizione mancante per moduli: {', '.join(missing)}"
    assert all(descriptions[module_id].strip() for module_id in module_ids)


def test_scan_modules_for_scan_type_include_descriptions() -> None:
    """Il selettore moduli del wizard espone label e descrizione per ogni modulo."""
    for scan_type in ("full", "light", "wordpress"):
        modules = app._scan_modules_for_scan_type(scan_type)
        assert modules, f"Nessun modulo per {scan_type}"
        for module in modules:
            assert module["id"] and module["label"]
            assert module["description"].strip()


def test_app_scan_types_have_catalog_metadata() -> None:
    """Ogni scan_type esposto in app.py deve essere presente nel catalogo."""
    catalog_ids = set(SCAN_CATALOG.keys())
    missing = sorted(set(SCAN_TYPES) - catalog_ids)
    assert not missing, f"Metadati mancanti per scan types app: {', '.join(missing)}"


def test_engine_scan_type_choices_have_catalog_metadata() -> None:
    """Ogni scelta valida a runtime deve avere metadati didattici associati."""
    catalog_ids = set(SCAN_CATALOG.keys())
    missing = sorted(set(SCAN_TYPE_CHOICES) - catalog_ids)
    assert not missing, f"Metadati mancanti per scan types engine: {', '.join(missing)}"


def test_top_tools_have_dedicated_learning_copy() -> None:
    """I tool core devono avere copywriting didattico specifico e non generico."""
    expected_markers = {
        "nuclei": "template",
        "nmap": "superficie di attacco",
        "zap": "OWASP",
        "sqlmap": "SQL Injection",
        "wpscan": "WordPress",
    }

    for scan_id, marker in expected_markers.items():
        entry = SCAN_CATALOG[scan_id]
        assert marker.lower() in entry.learning_objective.lower()
        assert entry.expected_duration != "10-45 min"
