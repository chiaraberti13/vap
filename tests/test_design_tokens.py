from design_tokens import PALETTE, SEVERITY_BG_HEX, SEVERITY_COLORS_HEX, css_root_variables
from report_generator import (
    BORDER_COLOR,
    BRAND_BLUE,
    BRAND_DARK,
    LIGHT_BG,
    ROW_ALT,
    SECTION_BG,
    SEVERITY_BG,
    SEVERITY_COLORS,
    TEXT_DARK,
    TEXT_MUTED,
)


def _hex(reportlab_color) -> str:
    return reportlab_color.hexval().lower().replace('0x', '#')


def test_css_root_variables_contains_shared_typography_spacing_and_palette() -> None:
    vars_map = css_root_variables()

    assert vars_map["primary-color"] == PALETTE.primary
    assert vars_map["font-family-base"].startswith("'Inter'")
    assert vars_map["space-8"] == "2rem"


def test_report_generator_uses_shared_palette_tokens() -> None:
    assert _hex(BRAND_DARK) == PALETTE.brand_dark
    assert _hex(BRAND_BLUE) == PALETTE.brand_blue
    assert _hex(LIGHT_BG) == PALETTE.light_bg
    assert _hex(BORDER_COLOR) == PALETTE.border
    assert _hex(TEXT_DARK) == PALETTE.text_dark
    assert _hex(TEXT_MUTED) == PALETTE.text_muted
    assert _hex(SECTION_BG) == PALETTE.section_bg
    assert _hex(ROW_ALT) == PALETTE.row_alt


def test_report_generator_severity_colors_are_loaded_from_tokens() -> None:
    assert {key: _hex(color) for key, color in SEVERITY_COLORS.items()} == SEVERITY_COLORS_HEX
    assert {key: _hex(color) for key, color in SEVERITY_BG.items()} == SEVERITY_BG_HEX
