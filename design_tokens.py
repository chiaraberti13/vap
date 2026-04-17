"""Shared design tokens used by both UI and PDF rendering layers."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class DesignTokenPalette:
    brand_dark: str
    brand_blue: str
    primary: str
    secondary: str
    danger: str
    success: str
    light_bg: str
    section_bg: str
    border: str
    text_dark: str
    text_muted: str
    row_alt: str


PALETTE = DesignTokenPalette(
    brand_dark="#1a2e4a",
    brand_blue="#2563eb",
    primary="#667eea",
    secondary="#764ba2",
    danger="#dc3545",
    success="#28a745",
    light_bg="#f8fafc",
    section_bg="#f1f5f9",
    border="#d1d5db",
    text_dark="#111827",
    text_muted="#6b7280",
    row_alt="#f9fafb",
)

TYPOGRAPHY: Dict[str, str] = {
    "font-family-base": "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
    "font-size-xs": "0.75rem",
    "font-size-sm": "0.875rem",
    "font-size-base": "1rem",
    "font-size-lg": "1.125rem",
    "font-size-xl": "1.5rem",
    "font-size-2xl": "2rem",
    "line-height-tight": "1.2",
    "line-height-normal": "1.5",
    "line-height-relaxed": "1.65",
}

SPACING: Dict[str, str] = {
    "space-1": "0.25rem",
    "space-2": "0.5rem",
    "space-3": "0.75rem",
    "space-4": "1rem",
    "space-6": "1.5rem",
    "space-8": "2rem",
}

SEVERITY_COLORS_HEX: Dict[str, str] = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#2563eb",
    "info": "#6b7280",
}

SEVERITY_BG_HEX: Dict[str, str] = {
    "critical": "#fef2f2",
    "high": "#fff7ed",
    "medium": "#fffbeb",
    "low": "#eff6ff",
    "info": "#f9fafb",
}


def css_root_variables() -> Dict[str, str]:
    """Return CSS variable mapping built from shared tokens."""
    palette_vars = {
        "primary-color": PALETTE.primary,
        "secondary-color": PALETTE.secondary,
        "danger-color": PALETTE.danger,
        "success-color": PALETTE.success,
        "brand-dark": PALETTE.brand_dark,
        "brand-blue": PALETTE.brand_blue,
        "light-bg": PALETTE.light_bg,
        "section-bg": PALETTE.section_bg,
        "border-color": PALETTE.border,
        "text-dark": PALETTE.text_dark,
        "text-muted": PALETTE.text_muted,
        "row-alt": PALETTE.row_alt,
    }
    return {**palette_vars, **TYPOGRAPHY, **SPACING}
