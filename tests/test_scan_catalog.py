"""Test di coerenza tra catalogo didattico e tipi di scansione runtime."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import SCAN_TYPES
from scan_catalog import SCAN_CATALOG
from scanner_engine import SCAN_TYPE_CHOICES


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
