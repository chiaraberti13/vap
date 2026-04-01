#!/usr/bin/env python3
"""PDF report generator – professional Pentest-Tools-style layout."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from html import escape as html_escape
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    KeepTogether,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie

from config import settings

# ── Palette ────────────────────────────────────────────────────────────────────
BRAND_DARK   = colors.HexColor("#1a2e4a")
BRAND_BLUE   = colors.HexColor("#2563eb")
LIGHT_BG     = colors.HexColor("#f8fafc")
BORDER_COLOR = colors.HexColor("#d1d5db")
TEXT_DARK    = colors.HexColor("#111827")
TEXT_MUTED   = colors.HexColor("#6b7280")
SECTION_BG   = colors.HexColor("#f1f5f9")
ROW_ALT      = colors.HexColor("#f9fafb")

SEVERITY_COLORS: Dict[str, colors.Color] = {
    "critical": colors.HexColor("#dc2626"),
    "high":     colors.HexColor("#ea580c"),
    "medium":   colors.HexColor("#d97706"),
    "low":      colors.HexColor("#2563eb"),
    "info":     colors.HexColor("#6b7280"),
}
SEVERITY_BG: Dict[str, colors.Color] = {
    "critical": colors.HexColor("#fef2f2"),
    "high":     colors.HexColor("#fff7ed"),
    "medium":   colors.HexColor("#fffbeb"),
    "low":      colors.HexColor("#eff6ff"),
    "info":     colors.HexColor("#f9fafb"),
}

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

OWASP_TOP10_2021 = [
    "A01:2021 - Broken Access Control",
    "A02:2021 - Cryptographic Failures",
    "A03:2021 - Injection",
    "A04:2021 - Insecure Design",
    "A05:2021 - Security Misconfiguration",
    "A06:2021 - Vulnerable and Outdated Components",
    "A07:2021 - Identification and Authentication Failures",
    "A08:2021 - Software and Data Integrity Failures",
    "A09:2021 - Security Logging and Monitoring Failures",
    "A10:2021 - Server-Side Request Forgery",
]
OWASP_TOP10_2017 = [
    "A1:2017 - Injection",
    "A2:2017 - Broken Authentication",
    "A3:2017 - Sensitive Data Exposure",
    "A4:2017 - XML External Entities (XXE)",
    "A5:2017 - Broken Access Control",
    "A6:2017 - Security Misconfiguration",
    "A7:2017 - Cross-Site Scripting (XSS)",
    "A8:2017 - Insecure Deserialization",
    "A9:2017 - Using Components with Known Vulnerabilities",
    "A10:2017 - Insufficient Logging & Monitoring",
]
OWASP_TOP10_2025 = [
    "A01:2025 - Broken Access Control",
    "A02:2025 - Cryptographic Failures",
    "A03:2025 - Injection",
    "A04:2025 - Insecure Design",
    "A05:2025 - Security Misconfiguration",
    "A06:2025 - Vulnerable Components",
    "A07:2025 - Identification and Authentication Failures",
    "A08:2025 - Software and Data Integrity Failures",
    "A09:2025 - Security Logging and Monitoring Failures",
    "A10:2025 - Server-Side Request Forgery",
]

PAGE_W, PAGE_H = A4
L_MARGIN = R_MARGIN = 1.5 * cm
T_MARGIN = 2.0 * cm
B_MARGIN = 1.6 * cm
CONTENT_W = PAGE_W - L_MARGIN - R_MARGIN  # ~18 cm


# ── Document template ─────────────────────────────────────────────────────────
class ReportDocTemplate(BaseDocTemplate):
    def __init__(self, filename: str, *, target: str) -> None:
        super().__init__(
            filename,
            pagesize=A4,
            leftMargin=L_MARGIN,
            rightMargin=R_MARGIN,
            topMargin=T_MARGIN,
            bottomMargin=B_MARGIN,
        )
        self.target = target
        frame = Frame(
            L_MARGIN, B_MARGIN,
            CONTENT_W, PAGE_H - T_MARGIN - B_MARGIN,
            id="main",
        )
        self.addPageTemplates(
            [PageTemplate(id="report", frames=[frame], onPage=self._chrome)]
        )

    def _chrome(self, canvas, doc) -> None:
        canvas.saveState()
        w, h = doc.pagesize
        bar_h = 1.4 * cm

        # ── Top blue band ──────────────────────────────────────────────
        canvas.setFillColor(BRAND_DARK)
        canvas.rect(0, h - bar_h, w, bar_h, stroke=0, fill=1)

        # VAP icon badge (restyling)
        ix, iy = L_MARGIN, h - bar_h + 0.22 * cm
        canvas.setFillColor(BRAND_BLUE)
        canvas.roundRect(ix, iy, 0.9 * cm, 0.9 * cm, 3, stroke=0, fill=1)
        canvas.setStrokeColor(colors.white)
        canvas.setLineWidth(1.0)
        canvas.line(ix + 0.2 * cm, iy + 0.65 * cm, ix + 0.45 * cm, iy + 0.35 * cm)
        canvas.line(ix + 0.45 * cm, iy + 0.35 * cm, ix + 0.7 * cm, iy + 0.7 * cm)
        canvas.setFont("Helvetica-Bold", 7)
        canvas.setFillColor(colors.white)
        canvas.drawCentredString(ix + 0.45 * cm, iy + 0.08 * cm, "VAP")

        canvas.setFont("Helvetica-Bold", 10)
        canvas.setFillColor(colors.white)
        canvas.drawString(ix + 1.1 * cm, h - bar_h + 0.48 * cm,
                          "Vulnerability Assessment Platform")

        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#94a3b8"))
        canvas.drawRightString(w - R_MARGIN, h - bar_h + 0.48 * cm,
                               f"Target: {self.target}")

        # ── Footer ────────────────────────────────────────────────────
        canvas.setStrokeColor(BORDER_COLOR)
        canvas.setLineWidth(0.5)
        canvas.line(L_MARGIN, B_MARGIN - 0.25 * cm,
                    w - R_MARGIN, B_MARGIN - 0.25 * cm)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(TEXT_MUTED)
        canvas.drawCentredString(w / 2, 0.55 * cm, f"Pagina {doc.page}")

        canvas.restoreState()


# ── Utility helpers ───────────────────────────────────────────────────────────
def _severity_counts(findings: List[Dict[str, Any]]) -> Counter:
    return Counter(str(f.get("severity", "info")).lower() for f in findings)


def _risk_label(counts: Counter) -> str:
    for sev in SEVERITY_ORDER:
        if counts.get(sev, 0) > 0:
            return sev.upper()
    return "INFO"


def _parse_cvss(value: Any) -> Optional[float]:
    try:
        v = float(value)
        return v if 0.0 <= v <= 10.0 else None
    except (TypeError, ValueError):
        return None


def _cvss_rating(score: float) -> str:
    if score == 0:
        return "NONE"
    if score <= 3.9:
        return "LOW"
    if score <= 6.9:
        return "MEDIUM"
    if score <= 8.9:
        return "HIGH"
    return "CRITICAL"


def _color_hex(c: colors.Color) -> str:
    return "#{:02x}{:02x}{:02x}".format(
        int(c.red * 255), int(c.green * 255), int(c.blue * 255)
    )


def _scan_type_label(scan_type: str) -> str:
    labels = {
        "light": "Light (surface checks only)",
        "deep": "Deep (active + passive)",
        "wordpress": "WordPress – Passive/Targeted",
        "full": "Full (all enabled scanners)",
    }
    normalized = str(scan_type).strip().lower()
    return labels.get(normalized, normalized or "unknown")


def _report_title(scan_type: str) -> str:
    titles = {
        "wordpress": "WordPress Scanner with WPScan Report",
        "light": "Light Website Vulnerability Scanner Report",
        "deep": "Deep Website Vulnerability Scanner Report",
        "full": "Full Website Vulnerability Scanner Report",
    }
    normalized = str(scan_type).strip().lower()
    return titles.get(normalized, "Website Vulnerability Scanner Report")


def _build_styles() -> Any:
    ss = getSampleStyleSheet()

    def _add(**kw: Any) -> None:
        if kw["name"] not in ss:
            ss.add(ParagraphStyle(**kw))

    _add(name="ReportTitle",   parent=ss["Title"],    fontSize=22, textColor=TEXT_DARK, spaceAfter=4)
    _add(name="SectionHeader", parent=ss["Heading2"], fontSize=13, textColor=BRAND_DARK,
         spaceBefore=14, spaceAfter=6, fontName="Helvetica-Bold")
    _add(name="SubHeader",     parent=ss["Heading3"], fontSize=10, textColor=BRAND_DARK,
         spaceBefore=8, spaceAfter=4, fontName="Helvetica-Bold")
    _add(name="Body",          parent=ss["BodyText"], fontSize=9,  textColor=TEXT_DARK,  spaceAfter=4, leading=13)
    _add(name="BodyMuted",     parent=ss["BodyText"], fontSize=8,  textColor=TEXT_MUTED, spaceAfter=3, leading=12)
    _add(name="LabelKey",      parent=ss["BodyText"], fontSize=8,  textColor=TEXT_MUTED, fontName="Helvetica-Bold", spaceAfter=2)
    _add(name="LabelVal",      parent=ss["BodyText"], fontSize=8,  textColor=TEXT_DARK,  spaceAfter=2)
    _add(name="FindingTitle",  parent=ss["BodyText"], fontSize=10, textColor=BRAND_BLUE, fontName="Helvetica-Bold", spaceAfter=2)
    _add(name="SmallBold",     parent=ss["BodyText"], fontSize=8,  textColor=TEXT_DARK,  fontName="Helvetica-Bold", spaceAfter=2)
    _add(name="Small",         parent=ss["BodyText"], fontSize=8,  textColor=TEXT_DARK,  spaceAfter=2, leading=11)
    _add(name="SmallMuted",    parent=ss["BodyText"], fontSize=8,  textColor=TEXT_MUTED, spaceAfter=2, leading=11)
    _add(name="TableHeader",   parent=ss["BodyText"], fontSize=8,  textColor=TEXT_DARK,  fontName="Helvetica-Bold")
    _add(name="TableCell",     parent=ss["BodyText"], fontSize=8,  textColor=TEXT_DARK,  leading=11)
    _add(name="TargetURL",     parent=ss["BodyText"], fontSize=11, textColor=BRAND_BLUE, fontName="Helvetica-Bold", spaceAfter=4)
    return ss


# ── Badge helper ──────────────────────────────────────────────────────────────
def _badge(text: str, bg: colors.Color, ss: Any, text_color: colors.Color = colors.white,
           col_w: float = 2.8 * cm) -> Table:
    tbl = Table(
        [[Paragraph(f'<b>{html_escape(text)}</b>', ss["SmallBold"])]],
        colWidths=[col_w],
    )
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("TEXTCOLOR",  (0, 0), (-1, -1), text_color),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
    ]))
    return tbl


# ── Summary section ───────────────────────────────────────────────────────────
def _build_summary(
    counts: Counter,
    risk_label: str,
    target: str,
    scan_type: str,
    start_time: Optional[datetime],
    end_time: Optional[datetime],
    total_findings: int,
    tests_performed: Optional[int],
    ss: Any,
) -> Table:
    """Three-column summary card: risk level | risk ratings | scan info."""

    sev_key = risk_label.lower()
    badge_color = SEVERITY_COLORS.get(sev_key, SEVERITY_COLORS["info"])
    risk_bg = SEVERITY_BG.get(sev_key, LIGHT_BG)

    # ── Panel 1: Overall risk level ──────────────────────────────────
    risk_badge = _badge(risk_label, badge_color, ss, col_w=3 * cm)
    panel1 = Table(
        [
            [Paragraph("Overall risk level:", ss["BodyMuted"])],
            [risk_badge],
        ],
        colWidths=[4.5 * cm],
    )
    panel1.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), risk_bg),
        ("BOX",           (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
        ("ALIGN",         (0, 0), (-1, -1), "LEFT"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))

    # ── Panel 2: Risk ratings ─────────────────────────────────────────
    rating_rows: List[List[Any]] = [
        [Paragraph("Risk ratings:", ss["BodyMuted"]), Paragraph("", ss["BodyMuted"])],
    ]
    max_count = max([counts.get(s, 0) for s in SEVERITY_ORDER] + [1])
    bar_track_w = 2.8  # cm
    for sev in SEVERITY_ORDER:
        cnt = counts.get(sev, 0)
        c = SEVERITY_COLORS[sev]
        fill_ratio = cnt / max_count if max_count else 0
        fill_w = bar_track_w * fill_ratio
        empty_w = max(0.0, bar_track_w - fill_w)
        if fill_w <= 0:
            fill_w = 0.001
        if empty_w <= 0:
            empty_w = 0.001
        bar_fill = Table(
            [["", ""]],
            colWidths=[fill_w * cm, empty_w * cm],
            rowHeights=[0.22 * cm],
        )
        bar_fill.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), c),
            ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#e5e7eb")),
            ("BOX",        (0, 0), (-1, -1), 0.25, BORDER_COLOR),
            ("LEFTPADDING",   (0, 0), (-1, -1), 0),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
            ("TOPPADDING",    (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]))
        row_inner = Table(
            [[Paragraph(sev.title(), ss["Small"]), bar_fill]],
            colWidths=[1.0 * cm, bar_track_w * cm],
        )
        row_inner.setStyle(TableStyle([
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ("LEFTPADDING",   (0, 0), (-1, -1), 0),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ]))
        cnt_para = Paragraph(
            f'<b><font color="{_color_hex(c)}">{cnt}</font></b>',
            ss["Body"],
        )
        rating_rows.append([row_inner, cnt_para])

    panel2 = Table(rating_rows, colWidths=[3.5 * cm, 1 * cm])
    panel2.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), colors.white),
        ("BOX",           (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("SPAN",          (0, 0), (1, 0)),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))

    # ── Panel 3: Scan information ─────────────────────────────────────
    fmt = "%b %d, %Y / %H:%M UTC"
    start_str = start_time.strftime(fmt) if start_time else "—"
    end_str   = end_time.strftime(fmt)   if end_time   else "—"
    if start_time and end_time:
        # Normalize to UTC-aware to handle offset-naive datetimes from SQLite
        if start_time.tzinfo is None:
            start_time = start_time.replace(tzinfo=timezone.utc)
        if end_time.tzinfo is None:
            end_time = end_time.replace(tzinfo=timezone.utc)
        secs = int((end_time - start_time).total_seconds())
        duration_str = f"{secs} sec"
    else:
        duration_str = "—"

    info_rows: List[Tuple[str, str]] = [
        ("Start time:",    start_str),
        ("Finish time:",   end_str),
        ("Scan duration:", duration_str),
        ("Scan type:",     _scan_type_label(scan_type)),
        ("Findings:",      str(total_findings)),
        ("Tests performed:", str(tests_performed) if tests_performed is not None else "—"),
        ("Scan status:",   "Completed"),
    ]
    info_data: List[List[Any]] = [
        [Paragraph("Scan information:", ss["BodyMuted"]), Paragraph("", ss["BodyMuted"])],
    ]
    for k, v in info_rows:
        info_data.append([Paragraph(k, ss["LabelKey"]), Paragraph(v, ss["LabelVal"])])

    # last row: status badge
    status_badge = _badge("Finished", colors.HexColor("#16a34a"), ss, col_w=2.2 * cm)
    info_data[-1][1] = status_badge

    panel3 = Table(info_data, colWidths=[3.0 * cm, 5.5 * cm])
    panel3.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), colors.white),
        ("BOX",           (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("SPAN",          (0, 0), (1, 0)),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))

    # Outer 3-column layout (gaps via padding)
    outer = Table(
        [[panel1, panel2, panel3]],
        colWidths=[4.5 * cm, 4.7 * cm, 8.8 * cm],
        spaceAfter=12,
    )
    outer.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (1, 0), 6),
        ("RIGHTPADDING",  (1, 0), (1, 0), 6),
    ]))
    return outer


# ── Finding card ──────────────────────────────────────────────────────────────
def _build_finding_card(finding: Dict[str, Any], ss: Any) -> List[Any]:
    """Return a list of flowables that form a finding card."""
    sev = str(finding.get("severity", "info")).lower()
    if sev not in SEVERITY_COLORS:
        sev = "info"
    sev_color = SEVERITY_COLORS[sev]
    sev_bg    = SEVERITY_BG.get(sev, LIGHT_BG)
    sev_hex   = _color_hex(sev_color)

    title_str   = html_escape(str(finding.get("title", "Finding")))
    confirmed   = finding.get("confirmed", True)
    status_lbl  = "CONFIRMED" if confirmed else "UNCONFIRMED"
    status_bg   = colors.HexColor("#16a34a") if confirmed else TEXT_MUTED

    port      = str(finding.get("port", ""))
    protocol  = str(finding.get("protocol", "tcp"))
    url_raw   = str(finding.get("url", finding.get("host", "")) or "")
    url_str   = html_escape(url_raw)
    evidence  = html_escape(str(finding.get("evidence", "") or ""))
    desc      = html_escape(str(finding.get("description", "") or ""))
    rec       = html_escape(str(finding.get("recommendation", "") or ""))
    references = list(finding.get("references") or [])
    cwe_list  = list(finding.get("cwe") or [])
    tags      = list(finding.get("tags") or [])
    owasp_tags = [str(t) for t in tags if "owasp" in str(t).lower()]
    cvss_score = finding.get("cvss_score")
    cve_list  = list(finding.get("cve") or [])
    found_by = html_escape(str(finding.get("found_by", "") or ""))
    method = html_escape(str(finding.get("method", "") or ""))
    parameters = finding.get("parameters")
    parameters_str = ", ".join(str(p) for p in parameters) if isinstance(parameters, list) else str(parameters or "")
    parameters_str = html_escape(parameters_str)
    owasp_2017 = finding.get("owasp_2017")
    owasp_2021 = finding.get("owasp_2021")
    owasp_2025 = finding.get("owasp_2025")
    epss_score = finding.get("epss_score")
    epss_percentile = finding.get("epss_percentile")
    cisa_kev = finding.get("cisa_kev")

    STRIP_W   = 0.35 * cm
    INNER_W   = CONTENT_W - STRIP_W

    # ── Title row (severity background) ───────────────────────────────
    status_badge = _badge(status_lbl, status_bg, ss, col_w=2.8 * cm)

    sev_badge = _badge(sev.upper(), sev_color, ss, col_w=2.0 * cm)

    finding_title_icon = "⚑"
    title_left = Paragraph(
        f'<font size="11" color="{sev_hex}">{finding_title_icon}</font> '
        f'<b><font color="#2563eb">{title_str}</font></b>',
        ss["FindingTitle"],
    )
    title_row = Table(
        [[title_left, sev_badge, status_badge]],
        colWidths=[INNER_W - 5.2 * cm, 2.2 * cm, 3.0 * cm],
    )
    title_row.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), sev_bg),
        ("LINEBELOW",     (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("ALIGN",         (0, 0), (0, 0), "LEFT"),
        ("ALIGN",         (1, 0), (1, 0), "RIGHT"),
        ("ALIGN",         (2, 0), (2, 0), "RIGHT"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
    ]))

    # ── Body rows ─────────────────────────────────────────────────────
    body_rows: List[List[Any]] = []

    if port:
        body_rows.append([
            Paragraph(f'<font color="#6b7280">port {port}/{protocol}</font>',
                      ss["SmallMuted"]),
        ])

    # URL / Evidence table
    if url_str or evidence:
        ev_table = Table(
            [
                [Paragraph("URL", ss["TableHeader"]),
                 Paragraph("Method", ss["TableHeader"]),
                 Paragraph("Parameters", ss["TableHeader"]),
                 Paragraph("Evidence", ss["TableHeader"])],
                [Paragraph(url_str or "—", ss["TableCell"]),
                 Paragraph(method or "—", ss["TableCell"]),
                 Paragraph(parameters_str or "—", ss["TableCell"]),
                 Paragraph(evidence or "—", ss["TableCell"])],
            ],
            colWidths=[INNER_W * 0.28 - 16, INNER_W * 0.12, INNER_W * 0.2, INNER_W * 0.4 - 16],
        )
        ev_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), SECTION_BG),
            ("LINEBELOW",     (0, 0), (-1, 0), 0.5, BORDER_COLOR),
            ("BOX",           (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("LINEAFTER",     (0, 0), (0, -1), 0.5, BORDER_COLOR),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        body_rows.append([Spacer(1, 4)])
        body_rows.append([ev_table])

    # Details section header
    body_rows.append([Spacer(1, 6)])
    body_rows.append([Paragraph("<b>▼ Details</b>", ss["SmallBold"])])
    body_rows.append([Spacer(1, 2)])

    if desc:
        body_rows.append([Paragraph("<b>Risk description:</b>", ss["SmallBold"])])
        body_rows.append([Paragraph(desc, ss["Small"])])

    if rec:
        body_rows.append([Paragraph("<b>Recommendation:</b>", ss["SmallBold"])])
        body_rows.append([Paragraph(rec, ss["Small"])])
    if found_by:
        body_rows.append([Paragraph("<b>Found by:</b>", ss["SmallBold"])])
        body_rows.append([Paragraph(found_by, ss["Small"])])

    if references:
        refs_joined = "<br/>".join(
            f'<font color="#2563eb">{html_escape(str(r))}</font>'
            for r in references[:4]
        )
        body_rows.append([Paragraph("<b>References:</b>", ss["SmallBold"])])
        body_rows.append([Paragraph(refs_joined, ss["Small"])])

    # Classification
    classify_lines: List[str] = []
    if cve_list:
        classify_lines.append("CVE: " + " | ".join(str(c) for c in cve_list[:5]))
    if cwe_list:
        classify_lines.append("CWE: " + " | ".join(str(c) for c in cwe_list[:3]))
    if owasp_2017:
        classify_lines.append(f"OWASP 2017: {owasp_2017}")
    if owasp_2021 or owasp_tags:
        classify_lines.append(f"OWASP 2021: {owasp_2021 or ' | '.join(str(t) for t in owasp_tags[:3])}")
    if owasp_2025:
        classify_lines.append(f"OWASP 2025: {owasp_2025}")
    if cisa_kev is not None:
        classify_lines.append(f"CISA KEV: {bool(cisa_kev)}")
    if cvss_score is not None:
        classify_lines.append(f"CVSS v3.1 Score: {cvss_score}")
    if epss_score is not None:
        classify_lines.append(f"EPSS score: {epss_score}")
    if epss_percentile is not None:
        classify_lines.append(f"EPSS percentile: {epss_percentile}")

    if classify_lines:
        body_rows.append([Paragraph("<b>Classification:</b>", ss["SmallBold"])])
        for line in classify_lines:
            body_rows.append([Paragraph(html_escape(line), ss["Small"])])

    if cve_list:
        cve_rows = [[
            Paragraph("CVE", ss["TableHeader"]),
            Paragraph("CVSS", ss["TableHeader"]),
            Paragraph("EPSS score", ss["TableHeader"]),
            Paragraph("EPSS percentile", ss["TableHeader"]),
            Paragraph("Summary", ss["TableHeader"]),
        ]]
        cve_details = finding.get("cve_details") or {}
        for cve in cve_list[:8]:
            details = cve_details.get(str(cve), {})
            summary = str(details.get("summary", "—"))
            fixed_in = details.get("fixed_in_version")
            if fixed_in:
                summary += f" | Fixed in version: {fixed_in}"
            cve_rows.append([
                Paragraph(html_escape(str(cve)), ss["TableCell"]),
                Paragraph(html_escape(str(details.get("cvss", cvss_score or "—"))), ss["TableCell"]),
                Paragraph(html_escape(str(details.get("epss_score", epss_score or "—"))), ss["TableCell"]),
                Paragraph(html_escape(str(details.get("epss_percentile", epss_percentile or "—"))), ss["TableCell"]),
                Paragraph(html_escape(summary), ss["TableCell"]),
            ])
        cve_table = Table(cve_rows, colWidths=[2.4 * cm, 1.2 * cm, 1.8 * cm, 2.0 * cm, INNER_W - 7.4 * cm - 16])
        cve_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), SECTION_BG),
            ("BOX", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, ROW_ALT]),
        ]))
        body_rows.append([Spacer(1, 4)])
        body_rows.append([Paragraph("<b>CVE details:</b>", ss["SmallBold"])])
        body_rows.append([cve_table])

    technologies = finding.get("technologies") or []
    if technologies:
        tech_rows = [[Paragraph("Software", ss["TableHeader"]), Paragraph("Version", ss["TableHeader"]), Paragraph("Category", ss["TableHeader"])]]
        for tech in technologies[:20]:
            tech_rows.append([
                Paragraph(html_escape(str(tech.get("software", "—"))), ss["TableCell"]),
                Paragraph(html_escape(str(tech.get("version", "—"))), ss["TableCell"]),
                Paragraph(html_escape(str(tech.get("category", "—"))), ss["TableCell"]),
            ])
        tech_table = Table(tech_rows, colWidths=[(INNER_W - 16) * 0.4, (INNER_W - 16) * 0.2, (INNER_W - 16) * 0.4])
        tech_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), SECTION_BG),
            ("BOX", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, ROW_ALT]),
        ]))
        body_rows.append([Spacer(1, 4)])
        body_rows.append([Paragraph("<b>Detected technologies:</b>", ss["SmallBold"])])
        body_rows.append([tech_table])

    body_rows.append([Spacer(1, 4)])

    # Wrap body rows in a padded table
    body_tbl = Table(
        body_rows,
        colWidths=[INNER_W - 16],
    )
    body_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), colors.white),
        ("TOPPADDING",    (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))

    # Outer card: left color strip | content
    card = Table(
        [["", title_row], ["", body_tbl]],
        colWidths=[STRIP_W, INNER_W],
    )
    card.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (0, -1), sev_color),
        ("BACKGROUND",    (1, 0), (1, -1), colors.white),
        ("BOX",           (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))

    return [KeepTogether([card]), Spacer(1, 10)]


# ── Severity chart ────────────────────────────────────────────────────────────
def _build_charts(counts: Counter) -> Drawing:
    drawing = Drawing(CONTENT_W, 190)

    # Pie chart
    pie = Pie()
    pie.x = 10
    pie.y = 15
    pie.width = 160
    pie.height = 160
    pie.data = [max(counts.get(s, 0), 0) for s in SEVERITY_ORDER]
    pie.labels = [s.title() for s in SEVERITY_ORDER]
    pie.slices.strokeWidth = 0.5
    for i, sev in enumerate(SEVERITY_ORDER):
        pie.slices[i].fillColor = SEVERITY_COLORS[sev]
    drawing.add(pie)

    # Bar chart
    bar = VerticalBarChart()
    bar.x = 210
    bar.y = 20
    bar.height = 140
    bar.width = 220
    bar.data = [[counts.get(s, 0) for s in SEVERITY_ORDER]]
    bar.categoryAxis.categoryNames = [s.title() for s in SEVERITY_ORDER]
    bar.valueAxis.valueMin = 0
    max_val = max(bar.data[0]) if bar.data[0] else 1
    bar.valueAxis.valueStep = max(1, max_val // 5)
    for i, sev in enumerate(SEVERITY_ORDER):
        bar.bars[0, i].fillColor = SEVERITY_COLORS[sev]
    drawing.add(bar)

    return drawing


# ── OWASP mapping ─────────────────────────────────────────────────────────────
def _map_owasp(findings: List[Dict[str, Any]], field_name: str = "owasp_2021") -> Counter:
    mapping: Counter = Counter()
    for finding in findings:
        mapped_value = finding.get(field_name)
        if mapped_value:
            mapping[str(mapped_value)] += 1
            continue
        tags = [str(t).lower() for t in (finding.get("tags") or []) if t]
        owasp_tag = next((t for t in tags if t.startswith("owasp")), "")
        if owasp_tag:
            mapping[owasp_tag.upper()] += 1
            continue
        cwe_list = [str(c).lower() for c in (finding.get("cwe") or []) if c]
        if any(c.startswith("cwe-79") or c.startswith("cwe-89") for c in cwe_list):
            mapping["A03:2021 - Injection"] += 1
        elif any(c.startswith("cwe-306") for c in cwe_list):
            mapping["A01:2021 - Broken Access Control"] += 1
        elif any(c.startswith("cwe-200") for c in cwe_list):
            mapping["A02:2021 - Cryptographic Failures"] += 1
        else:
            mapping["Non classificato"] += 1
    return mapping


# ── Main entry point ──────────────────────────────────────────────────────────
def generate_report(
    scan_id: int,
    target: str,
    scan_type: str,
    findings: List[Dict[str, Any]],
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    redirect_from: Optional[str] = None,
    tests_performed: Optional[int] = None,
    scan_parameters: Optional[Dict[str, Any]] = None,
    scan_coverage: Optional[Dict[str, List[str]]] = None,
    scan_stats: Optional[Dict[str, Any]] = None,
) -> Path:
    generated_at = datetime.now(timezone.utc)
    safe_scan = "".join(ch if ch.isalnum() else "_" for ch in (scan_type or "scan")).strip("_")
    safe_target = "".join(ch if ch.isalnum() else "_" for ch in (target or "target")).strip("_")
    report_name = f"{safe_scan}-{safe_target}-{generated_at.strftime('%Y%m%d-%H%M')}.pdf"
    report_path = settings.reports_dir / report_name

    doc = ReportDocTemplate(str(report_path), target=target)
    ss  = _build_styles()

    counts     = _severity_counts(findings)
    risk_level = _risk_label(counts)

    # Sort findings: critical first
    sev_rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    sorted_findings = sorted(
        findings,
        key=lambda f: sev_rank.get(str(f.get("severity", "info")).lower(), 4),
    )

    story: List[Any] = []

    # ── Cover / title ──────────────────────────────────────────────────
    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph(_report_title(scan_type), ss["ReportTitle"]))
    story.append(Spacer(1, 6))

    scan_type_notes = {
        "light": "Light scan did not check for SQLi, XSS, Command Injection, XXE and other deep active checks.",
        "wordpress": "WordPress scan focuses on WP core/themes/plugins and may not fully cover custom application logic.",
    }
    note = scan_type_notes.get(str(scan_type).lower())
    if note:
        banner = Table(
            [[Paragraph(f"<b>Scan type notice:</b> {html_escape(note)}", ss["Small"])]],
            colWidths=[CONTENT_W],
        )
        banner.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#ffedd5")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#fb923c")),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(Spacer(1, 6))
        story.append(banner)

    # Target URL highlighted card
    target_rows: List[List[Any]] = [[
        Paragraph(
            f'✓ <font color="#2563eb"><b>{html_escape(target)}</b></font>',
            ss["TargetURL"],
        )
    ]]
    if redirect_from:
        target_rows.append([
            Paragraph(
                f'<font color="#6b7280">Target added due to a redirect from {html_escape(redirect_from)}</font>',
                ss["BodyMuted"],
            )
        ])

    target_card = Table(target_rows, colWidths=[CONTENT_W])
    target_card.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f0f9ff")),
        ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#93c5fd")),
        ("LINEBEFORE", (0, 0), (0, -1), 2.5, BRAND_BLUE),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(target_card)
    story.append(Spacer(1, 4))
    story.append(
        Paragraph(
            f'<font color="#6b7280">Report generated: '
            f'{generated_at.strftime("%b %d, %Y / %H:%M UTC")}  ·  '
            f'Scan type: {html_escape(_scan_type_label(scan_type))}</font>',
            ss["BodyMuted"],
        )
    )
    story.append(Spacer(1, 14))

    # ── Summary ────────────────────────────────────────────────────────
    story.append(Paragraph("Summary", ss["SectionHeader"]))
    story.append(
        _build_summary(
            counts, risk_level, target, scan_type,
            start_time, end_time, len(findings), tests_performed, ss,
        )
    )

    # ── Severity chart ─────────────────────────────────────────────────
    if any(counts.values()):
        story.append(Paragraph("Severity Overview", ss["SectionHeader"]))
        story.append(_build_charts(counts))
        story.append(Spacer(1, 8))

    # ── OWASP mapping ──────────────────────────────────────────────────
    owasp_sets = [
        ("OWASP Top 10 Mapping (2021)", OWASP_TOP10_2021, "owasp_2021"),
        ("OWASP Top 10 Mapping (2017)", OWASP_TOP10_2017, "owasp_2017"),
        ("OWASP Top 10 Mapping (2025)", OWASP_TOP10_2025, "owasp_2025"),
    ]
    for section_title, owasp_categories, field_name in owasp_sets:
        owasp_counts = _map_owasp(findings, field_name=field_name)
        if not owasp_counts:
            continue
        story.append(Paragraph(section_title, ss["SectionHeader"]))
        owasp_rows = [
            [Paragraph("Category", ss["TableHeader"]),
             Paragraph("Count", ss["TableHeader"])],
        ]
        for entry in owasp_categories:
            cnt = owasp_counts.get(entry, 0)
            owasp_rows.append([
                Paragraph(entry, ss["TableCell"]),
                Paragraph(str(cnt), ss["TableCell"]),
            ])
        if "Non classificato" in owasp_counts:
            owasp_rows.append([
                Paragraph("Non classificato", ss["TableCell"]),
                Paragraph(str(owasp_counts["Non classificato"]), ss["TableCell"]),
            ])
        owasp_tbl = Table(owasp_rows, colWidths=[14 * cm, 4 * cm])
        owasp_style = [
            ("BACKGROUND",    (0, 0), (-1, 0),  SECTION_BG),
            ("LINEBELOW",     (0, 0), (-1, 0),  0.5, BORDER_COLOR),
            ("BOX",           (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("LINEAFTER",     (0, 0), (0, -1),  0.5, BORDER_COLOR),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, ROW_ALT]),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN",         (1, 0), (1, -1),  "CENTER"),
        ]
        owasp_tbl.setStyle(TableStyle(owasp_style))
        story.append(owasp_tbl)
        story.append(Spacer(1, 12))

    # ── Findings ───────────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("Findings", ss["SectionHeader"]))
    story.append(Spacer(1, 4))

    if not sorted_findings:
        story.append(Paragraph("No findings detected.", ss["Body"]))
    else:
        for finding in sorted_findings:
            story.extend(_build_finding_card(finding, ss))

    if scan_coverage:
        story.append(PageBreak())
        story.append(Paragraph("Scan coverage information", ss["SectionHeader"]))
        for coverage_key, tests in scan_coverage.items():
            story.append(Paragraph(f"<b>{html_escape(str(coverage_key))}</b>", ss["SmallBold"]))
            for test_name in tests:
                story.append(Paragraph(f"✓ {html_escape(str(test_name))}", ss["Small"]))

    if scan_parameters:
        story.append(Spacer(1, 8))
        story.append(Paragraph("Scan parameters", ss["SectionHeader"]))
        params_rows = [[Paragraph("Parameter", ss["TableHeader"]), Paragraph("Value", ss["TableHeader"])]]
        for key, value in scan_parameters.items():
            params_rows.append([Paragraph(html_escape(str(key)), ss["TableCell"]), Paragraph(html_escape(str(value)), ss["TableCell"])])
        params_table = Table(params_rows, colWidths=[5.0 * cm, CONTENT_W - 5.0 * cm])
        params_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), SECTION_BG),
            ("BOX", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ]))
        story.append(params_table)

    if scan_stats:
        story.append(Spacer(1, 8))
        story.append(Paragraph("Scan stats", ss["SectionHeader"]))
        stats_rows = [[Paragraph("Metric", ss["TableHeader"]), Paragraph("Value", ss["TableHeader"])]]
        labels = {
            "urls_spidered": "URLs spidered",
            "unique_injection_points": "Unique injection points",
            "total_http_requests": "Total HTTP requests",
            "average_response_time": "Average response time",
        }
        for key, label in labels.items():
            stats_rows.append([Paragraph(label, ss["TableCell"]), Paragraph(html_escape(str(scan_stats.get(key, "—"))), ss["TableCell"])])
        stats_table = Table(stats_rows, colWidths=[6.0 * cm, CONTENT_W - 6.0 * cm])
        stats_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), SECTION_BG),
            ("BOX", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ]))
        story.append(stats_table)

    doc.build(story)
    return report_path
