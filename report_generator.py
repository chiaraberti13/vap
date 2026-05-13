#!/usr/bin/env python3
"""PDF report generator – minimal, professional, technical layout."""
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
    HRFlowable,
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

from config import settings
from design_tokens import PALETTE, SEVERITY_BG_HEX, SEVERITY_COLORS_HEX
from security import redact_sensitive_data

# ── Palette ────────────────────────────────────────────────────────────────────
BRAND_DARK   = colors.HexColor(PALETTE.brand_dark)
BRAND_BLUE   = colors.HexColor(PALETTE.brand_blue)
LIGHT_BG     = colors.HexColor(PALETTE.light_bg)
BORDER_COLOR = colors.HexColor(PALETTE.border)
TEXT_DARK    = colors.HexColor(PALETTE.text_dark)
TEXT_MUTED   = colors.HexColor(PALETTE.text_muted)
SECTION_BG   = colors.HexColor(PALETTE.section_bg)
ROW_ALT      = colors.HexColor(PALETTE.row_alt)

# Accent strip on left of finding cards — 3 px wide rule
ACCENT_W = colors.HexColor("#94a3b8")

SEVERITY_COLORS: Dict[str, colors.Color] = {
    severity: colors.HexColor(color_hex)
    for severity, color_hex in SEVERITY_COLORS_HEX.items()
}
SEVERITY_BG: Dict[str, colors.Color] = {
    severity: colors.HexColor(color_hex)
    for severity, color_hex in SEVERITY_BG_HEX.items()
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
L_MARGIN = R_MARGIN = 1.8 * cm
T_MARGIN = 2.0 * cm
B_MARGIN = 1.8 * cm
CONTENT_W = PAGE_W - L_MARGIN - R_MARGIN  # ~17.4 cm


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
        self.generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
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
        bar_h = 1.2 * cm

        # ── Top header bar ────────────────────────────────────────────
        canvas.setFillColor(BRAND_DARK)
        canvas.rect(0, h - bar_h, w, bar_h, stroke=0, fill=1)

        # Left accent line in brand blue
        canvas.setFillColor(BRAND_BLUE)
        canvas.rect(0, h - bar_h, 0.22 * cm, bar_h, stroke=0, fill=1)

        # Product name — left
        canvas.setFont("Helvetica-Bold", 9)
        canvas.setFillColor(colors.white)
        canvas.drawString(L_MARGIN, h - bar_h + 0.42 * cm, "VAP")

        canvas.setFont("Helvetica", 9)
        canvas.setFillColor(colors.HexColor("#94a3b8"))
        canvas.drawString(L_MARGIN + 0.9 * cm, h - bar_h + 0.42 * cm,
                          "Vulnerability Assessment Platform")

        # Target — right
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#94a3b8"))
        canvas.drawRightString(w - R_MARGIN, h - bar_h + 0.42 * cm,
                               f"Target: {self.target}")

        # ── Footer ────────────────────────────────────────────────────
        canvas.setStrokeColor(colors.HexColor("#e2e8f0"))
        canvas.setLineWidth(0.4)
        canvas.line(L_MARGIN, B_MARGIN - 0.3 * cm, w - R_MARGIN, B_MARGIN - 0.3 * cm)

        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(TEXT_MUTED)
        canvas.drawString(L_MARGIN, 0.6 * cm, "CONFIDENTIAL")
        canvas.drawCentredString(w / 2, 0.6 * cm, f"Page {doc.page}")
        canvas.drawRightString(w - R_MARGIN, 0.6 * cm, self.generated_at)

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


def _format_epss_score(value: Any) -> str:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return "-"
    if parsed < 0:
        return "-"
    return f"{parsed:.6f}".rstrip("0").rstrip(".")


def _format_epss_percentile(value: Any) -> str:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return "-"
    if parsed < 0:
        return "-"
    if parsed <= 1:
        parsed *= 100
    if parsed > 100:
        return "-"
    return f"{parsed:.2f}%"


def _build_executive_kpi_strip(counts: Counter, total_findings: int, risk_level: str, ss):
    critical_high = counts.get("critical", 0) + counts.get("high", 0)
    kpi_rows = [
        [Paragraph("Executive Summary", ss["TableHeader"])],
        [Paragraph(
            (
                f"<b>Risk level:</b> {html_escape(risk_level)}"
                f"&nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;"
                f"<b>Total findings:</b> {total_findings}"
                f"&nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;"
                f"<b>Critical + High:</b> {critical_high}"
            ),
            ss["Body"],
        )],
    ]
    kpi_table = Table(kpi_rows, colWidths=[CONTENT_W])
    kpi_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), SECTION_BG),
        ("BACKGROUND", (0, 1), (-1, -1), colors.white),
        ("LINEBEFORE",  (0, 0), (0, -1), 3, BRAND_BLUE),
        ("BOX",         (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("LINEBELOW",   (0, 0), (-1, 0),  0.5, BORDER_COLOR),
        ("LEFTPADDING",  (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING",   (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 8),
    ]))
    return kpi_table


def _build_severity_heatmap_table(counts: Counter, ss: Any) -> Table:
    """Severity distribution with exposure band classification."""
    thresholds = [
        ("critical", 1, 3),
        ("high",     3, 6),
        ("medium",   5, 10),
        ("low",      8, 20),
        ("info",    10, 30),
    ]

    def _band_for(severity: str, count: int) -> Tuple[str, colors.Color]:
        _, med_thr, high_thr = next(
            (e for e in thresholds if e[0] == severity), (severity, 1, 3)
        )
        if count <= 0:
            return ("None", colors.HexColor("#f8fafc"))
        if count < med_thr:
            return ("Low", colors.HexColor("#dcfce7"))
        if count < high_thr:
            return ("Medium", colors.HexColor("#fef3c7"))
        return ("High", colors.HexColor("#fee2e2"))

    rows: List[List[Any]] = [[
        Paragraph("Severity",       ss["TableHeader"]),
        Paragraph("Count",          ss["TableHeader"]),
        Paragraph("Exposure band",  ss["TableHeader"]),
    ]]
    row_backgrounds: List[colors.Color] = [SECTION_BG]

    for severity in SEVERITY_ORDER:
        count = counts.get(severity, 0)
        band_label, band_bg = _band_for(severity, count)
        rows.append([
            Paragraph(severity.upper(), ss["TableCell"]),
            Paragraph(str(count),       ss["TableCell"]),
            Paragraph(band_label,       ss["TableCell"]),
        ])
        row_backgrounds.append(band_bg)

    col_sev  = 4.8 * cm
    col_cnt  = 2.2 * cm
    col_band = CONTENT_W - col_sev - col_cnt
    table = Table(rows, colWidths=[col_sev, col_cnt, col_band])
    table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  SECTION_BG),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), row_backgrounds[1:]),
        ("BOX",           (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("LINEBELOW",     (0, 0), (-1, 0),  0.5, BORDER_COLOR),
        ("LINEAFTER",     (0, 0), (1, -1),  0.5, BORDER_COLOR),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("ALIGN",         (1, 0), (1, -1),  "CENTER"),
    ]))
    return table


def _build_remediation_roadmap(findings: List[Dict[str, Any]], ss: Any, *, limit: int = 5) -> Table:
    """Priority-ordered remediation roadmap for executive consumption."""
    if not findings:
        rows = [[Paragraph("Priority", ss["TableHeader"]), Paragraph("Action", ss["TableHeader"])]]
        rows.append([Paragraph("-", ss["TableCell"]), Paragraph("No remediation actions required.", ss["TableCell"])])
        table = Table(rows, colWidths=[2.5 * cm, CONTENT_W - 2.5 * cm])
        table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  SECTION_BG),
            ("BOX",           (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("LEFTPADDING",   (0, 0), (-1, -1), 10),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        return table

    sev_rank = {severity: idx for idx, severity in enumerate(SEVERITY_ORDER)}
    sorted_findings = sorted(
        findings,
        key=lambda f: (
            sev_rank.get(str(f.get("severity", "info")).lower(), len(SEVERITY_ORDER)),
            -(
                _parse_cvss(f.get("cvss_score") or f.get("cvss") or -1)
                if _parse_cvss(f.get("cvss_score") or f.get("cvss")) is not None
                else 1
            ),
            str(f.get("title", "")),
        ),
    )

    rows: List[List[Any]] = [[
        Paragraph("Priority", ss["TableHeader"]),
        Paragraph("Action",   ss["TableHeader"]),
    ]]
    for idx, finding in enumerate(sorted_findings[:limit], start=1):
        title = str(finding.get("title", "Untitled finding")).strip() or "Untitled finding"
        rec   = str(finding.get("recommendation", "")).strip() or \
                "Review finding details and define a mitigation plan."
        sev   = str(finding.get("severity", "info")).lower()
        label = f"P{idx}  {sev.upper()}"
        body  = f"<b>{html_escape(title)}</b><br/>{html_escape(rec)}"
        rows.append([
            Paragraph(label, ss["TableCellMono"]),
            Paragraph(body,  ss["TableCell"]),
        ])

    table = Table(rows, colWidths=[2.5 * cm, CONTENT_W - 2.5 * cm])
    table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  SECTION_BG),
        ("BOX",           (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("LINEAFTER",     (0, 0), (0, -1),  0.5, BORDER_COLOR),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, ROW_ALT]),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
        ("TOPPADDING",    (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))
    return table


def _format_cve_summary(details: Dict[str, Any], fallback_references: List[Any]) -> str:
    parts: List[str] = []

    summary_text = str(details.get("summary", "-")).strip() or "-"
    parts.append(summary_text)

    fixed_in = str(details.get("fixed_in_version", "") or "").strip()
    if fixed_in:
        parts.append(f"Fixed in: {fixed_in}")

    cve_refs = details.get("references") or []
    if not isinstance(cve_refs, list):
        cve_refs = [cve_refs]

    refs = [str(r).strip() for r in cve_refs if str(r).strip()]
    if not refs:
        refs = [str(r).strip() for r in fallback_references if str(r).strip()]

    if refs:
        parts.append("Refs: " + ", ".join(refs[:3]))

    return " | ".join(parts)


def _ensure_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _normalize_cve_details(raw_details: Any) -> Dict[str, Dict[str, Any]]:
    if isinstance(raw_details, dict):
        return {str(k): v for k, v in raw_details.items() if isinstance(v, dict)}

    if isinstance(raw_details, list):
        normalized: Dict[str, Dict[str, Any]] = {}
        for item in raw_details:
            if not isinstance(item, dict):
                continue
            cve_id = str(item.get("cve") or item.get("id") or "").strip()
            if cve_id:
                normalized[cve_id] = item
        return normalized

    return {}


def _normalize_technologies(raw_technologies: Any) -> List[Dict[str, Any]]:
    return [item for item in _ensure_list(raw_technologies) if isinstance(item, dict)]


def _color_hex(c: colors.Color) -> str:
    return "#{:02x}{:02x}{:02x}".format(
        int(c.red * 255), int(c.green * 255), int(c.blue * 255)
    )


def _resolve_found_by(finding: Dict[str, Any]) -> str:
    explicit = str(finding.get("found_by", "") or "").strip()
    if explicit:
        return explicit

    tool_name = str(finding.get("tool", "") or "").strip()
    if not tool_name:
        return "Active Testing"

    detection_mode = str(finding.get("detection_mode", "") or "").strip().lower()
    mode_labels = {
        "passive":    "Passive Detection",
        "aggressive": "Aggressive Detection",
        "active":     "Active Testing",
    }
    return f"{tool_name.title()} – {mode_labels.get(detection_mode, 'Active Testing')}"


def _is_technology_finding(finding: Dict[str, Any]) -> bool:
    title = str(finding.get("title", "") or "").lower()
    tool  = str(finding.get("tool", "") or "").lower()
    tags  = [str(t).lower() for t in (finding.get("tags") or []) if t]
    return (
        "whatweb" in tool
        or "tecnolog" in title
        or "technology" in title
        or any("whatweb" in tag or "technology" in tag for tag in tags)
    )


def _validation_steps_for_finding(finding: Dict[str, Any]) -> List[str]:
    raw_steps = finding.get("validation_steps")
    steps: List[str] = []

    if isinstance(raw_steps, list):
        steps = [str(s).strip() for s in raw_steps if str(s).strip()]
    elif isinstance(raw_steps, str) and raw_steps.strip():
        steps = [raw_steps.strip()]

    if steps:
        return steps[:5]

    fallbacks = [
        ("method",     "Re-run request with method"),
        ("url",        "Verify affected endpoint"),
        ("parameters", "Confirm affected parameters"),
    ]
    for field, prefix in fallbacks:
        value = finding.get(field)
        if isinstance(value, list):
            value = ", ".join(str(i).strip() for i in value if str(i).strip())
        value_text = str(value or "").strip()
        if value_text:
            steps.append(f"{prefix}: {value_text}")

    if finding.get("evidence"):
        steps.append("Cross-check scanner evidence and reproduce on staging before remediation.")
    if finding.get("recommendation"):
        steps.append("After remediation, run a focused re-scan to confirm closure.")

    return steps[:5]


def _scan_type_label(scan_type: str) -> str:
    labels = {
        "light":        "Light (surface checks only)",
        "deep":         "Deep (active + passive)",
        "wordpress":    "WordPress – Passive/Targeted",
        "full":         "Full (all enabled scanners)",
        "nuclei":       "Nuclei – CVE/Templates Focus",
        "nmap":         "Nmap – Network/Port Enumeration",
        "whatweb":      "WhatWeb – Technology Fingerprinting",
        "subfinder":    "Subfinder – Subdomain Enumeration",
        "nikto":        "Nikto – Web Server Misconfiguration Checks",
        "dirsearch":    "Dirsearch – Directory Bruteforce",
        "sqlmap":       "SQLMap – SQL Injection Testing",
        "xsstrike":     "XSStrike – XSS Testing",
        "zap":          "OWASP ZAP – Active/Passive Web Scan",
        "burp":         "Burp Suite – Web Vulnerability Scan",
        "wapiti":       "Wapiti – Web Application Audit",
        "commix":       "Commix – Command Injection Testing",
        "acunetix":     "Acunetix – Web Vulnerability Assessment",
        "nessus":       "Nessus – Infrastructure Vulnerability Scan",
        "wpscan":       "WPScan – WordPress Security Audit",
        "wafw00f":      "wafw00f – WAF Detection",
        "testssl":      "testssl.sh – TLS/SSL Audit",
        "theharvester": "theHarvester – OSINT Enumeration",
        "arjun":        "Arjun – Hidden Parameter Discovery",
        "dalfox":       "Dalfox – XSS Parameter Analysis",
        "httpx":        "httpx – HTTP Service Probing",
        "katana":       "Katana – Web Crawling/Discovery",
        "nosqlmap":     "NoSQLMap – NoSQL Injection Testing",
    }
    normalized = str(scan_type).strip().lower()
    return labels.get(normalized, normalized or "unknown")


def _report_title(scan_type: str) -> str:
    titles = {
        "wordpress": "WordPress Scanner — Security Assessment Report",
        "light":     "Light Website Vulnerability Scanner Report",
        "deep":      "Deep Website Vulnerability Scanner Report",
        "full":      "Full Website Vulnerability Scanner Report",
    }
    normalized = str(scan_type).strip().lower()
    return titles.get(normalized, "Website Vulnerability Scanner Report")


def _build_styles() -> Any:
    ss = getSampleStyleSheet()

    def _add(**kw: Any) -> None:
        if kw["name"] not in ss:
            ss.add(ParagraphStyle(**kw))

    # Title hierarchy
    _add(name="ReportTitle",
         parent=ss["Title"],
         fontSize=20,
         fontName="Helvetica-Bold",
         textColor=TEXT_DARK,
         spaceAfter=2,
         leading=24)
    _add(name="ReportSubtitle",
         parent=ss["BodyText"],
         fontSize=10,
         textColor=TEXT_MUTED,
         spaceAfter=8,
         leading=14)

    # Section / sub-section
    _add(name="SectionHeader",
         parent=ss["Heading2"],
         fontSize=11,
         textColor=BRAND_DARK,
         fontName="Helvetica-Bold",
         spaceBefore=14,
         spaceAfter=6,
         borderPadding=(0, 0, 2, 0))
    _add(name="SubHeader",
         parent=ss["Heading3"],
         fontSize=10,
         textColor=BRAND_DARK,
         fontName="Helvetica-Bold",
         spaceBefore=8,
         spaceAfter=4)

    # Body text
    _add(name="Body",
         parent=ss["BodyText"],
         fontSize=9,
         textColor=TEXT_DARK,
         spaceAfter=4,
         leading=14)
    _add(name="BodyMuted",
         parent=ss["BodyText"],
         fontSize=8,
         textColor=TEXT_MUTED,
         spaceAfter=3,
         leading=12)

    # Label / value pairs
    _add(name="LabelKey",
         parent=ss["BodyText"],
         fontSize=8,
         textColor=TEXT_MUTED,
         fontName="Helvetica-Bold",
         spaceAfter=2)
    _add(name="LabelVal",
         parent=ss["BodyText"],
         fontSize=8,
         textColor=TEXT_DARK,
         spaceAfter=2)

    # Finding-specific
    _add(name="FindingTitle",
         parent=ss["BodyText"],
         fontSize=10,
         textColor=TEXT_DARK,
         fontName="Helvetica-Bold",
         spaceAfter=2)

    # Small text variants
    _add(name="Small",
         parent=ss["BodyText"],
         fontSize=8,
         textColor=TEXT_DARK,
         spaceAfter=2,
         leading=12)
    _add(name="SmallBold",
         parent=ss["BodyText"],
         fontSize=8,
         textColor=TEXT_DARK,
         fontName="Helvetica-Bold",
         spaceAfter=2)
    _add(name="SmallMuted",
         parent=ss["BodyText"],
         fontSize=8,
         textColor=TEXT_MUTED,
         spaceAfter=2,
         leading=12)

    # Table styles
    _add(name="TableHeader",
         parent=ss["BodyText"],
         fontSize=8,
         textColor=TEXT_DARK,
         fontName="Helvetica-Bold")
    _add(name="TableCell",
         parent=ss["BodyText"],
         fontSize=8,
         textColor=TEXT_DARK,
         leading=12)
    _add(name="TableCellMono",
         parent=ss["BodyText"],
         fontSize=8,
         textColor=TEXT_MUTED,
         fontName="Helvetica",
         leading=12)

    # Target URL
    _add(name="TargetURL",
         parent=ss["BodyText"],
         fontSize=10,
         textColor=BRAND_BLUE,
         fontName="Helvetica-Bold",
         spaceAfter=4)

    return ss


# ── Badge helper ──────────────────────────────────────────────────────────────
def _badge(text: str, bg: colors.Color, ss: Any,
           text_color: colors.Color = colors.white,
           col_w: float = 2.8 * cm) -> Table:
    tbl = Table(
        [[Paragraph(f'<b>{html_escape(text)}</b>', ss["SmallBold"])]],
        colWidths=[col_w],
    )
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), bg),
        ("TEXTCOLOR",     (0, 0), (-1, -1), text_color),
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
    """Three-panel summary card: risk level | severity bars | scan metadata."""

    sev_key    = risk_label.lower()
    badge_color = SEVERITY_COLORS.get(sev_key, SEVERITY_COLORS["info"])
    risk_bg     = SEVERITY_BG.get(sev_key, LIGHT_BG)

    # ── Panel 1: Overall risk level ───────────────────────────────────
    risk_badge = _badge(risk_label, badge_color, ss, col_w=3 * cm)
    panel1 = Table(
        [
            [Paragraph("Overall risk level", ss["BodyMuted"])],
            [risk_badge],
        ],
        colWidths=[4.5 * cm],
    )
    panel1.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), risk_bg),
        ("BOX",           (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("TOPPADDING",    (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ("LEFTPADDING",   (0, 0), (-1, -1), 12),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 12),
        ("ALIGN",         (0, 0), (-1, -1), "LEFT"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))

    # ── Panel 2: Severity bars ────────────────────────────────────────
    rating_rows: List[List[Any]] = [
        [Paragraph("Severity distribution", ss["BodyMuted"]), Paragraph("", ss["BodyMuted"])],
    ]
    max_count   = max([counts.get(s, 0) for s in SEVERITY_ORDER] + [1])
    bar_track_w = 2.8  # cm
    for sev in SEVERITY_ORDER:
        cnt = counts.get(sev, 0)
        c   = SEVERITY_COLORS[sev]
        fill_ratio = cnt / max_count if max_count else 0
        fill_w  = max(bar_track_w * fill_ratio, 0.001)
        empty_w = max(bar_track_w - fill_w, 0.001)
        bar = Table(
            [["", ""]],
            colWidths=[fill_w * cm, empty_w * cm],
            rowHeights=[0.2 * cm],
        )
        bar.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (0, 0), c),
            ("BACKGROUND",    (1, 0), (1, 0), colors.HexColor("#e5e7eb")),
            ("LEFTPADDING",   (0, 0), (-1, -1), 0),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
            ("TOPPADDING",    (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]))
        row_inner = Table(
            [[Paragraph(sev.upper(), ss["SmallMuted"]), bar]],
            colWidths=[1.1 * cm, bar_track_w * cm],
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

    panel2 = Table(rating_rows, colWidths=[3.6 * cm, 0.9 * cm])
    panel2.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), colors.white),
        ("BOX",           (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("SPAN",          (0, 0), (1, 0)),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 12),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))

    # ── Panel 3: Scan metadata ────────────────────────────────────────
    fmt = "%b %d, %Y  %H:%M UTC"
    start_str = start_time.strftime(fmt) if start_time else "-"
    end_str   = end_time.strftime(fmt)   if end_time   else "-"
    if start_time and end_time:
        if start_time.tzinfo is None:
            start_time = start_time.replace(tzinfo=timezone.utc)
        if end_time.tzinfo is None:
            end_time = end_time.replace(tzinfo=timezone.utc)
        secs         = int((end_time - start_time).total_seconds())
        duration_str = f"{secs} s"
    else:
        duration_str = "-"

    info_rows: List[Tuple[str, str]] = [
        ("Start time",        start_str),
        ("End time",          end_str),
        ("Duration",          duration_str),
        ("Scan type",         _scan_type_label(scan_type)),
        ("Findings",          str(total_findings)),
        ("Tests performed",   str(tests_performed) if tests_performed is not None else "-"),
        ("Status",            "Completed"),
    ]
    info_data: List[List[Any]] = [
        [Paragraph("Scan metadata", ss["BodyMuted"]), Paragraph("", ss["BodyMuted"])],
    ]
    for k, v in info_rows:
        info_data.append([Paragraph(k, ss["LabelKey"]), Paragraph(v, ss["LabelVal"])])

    # Last row: status badge
    status_badge = _badge("Completed", colors.HexColor("#16a34a"), ss, col_w=2.2 * cm)
    info_data[-1][1] = status_badge

    panel3 = Table(info_data, colWidths=[3.2 * cm, 5.3 * cm])
    panel3.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), colors.white),
        ("BOX",           (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("SPAN",          (0, 0), (1, 0)),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 12),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))

    # Outer 3-column layout
    outer = Table(
        [[panel1, panel2, panel3]],
        colWidths=[4.5 * cm, 4.7 * cm, 8.7 * cm],
        spaceAfter=12,
    )
    outer.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (0, 0),  6),
        ("RIGHTPADDING",  (1, 0), (1, 0),  6),
    ]))
    return outer


# ── Finding card ──────────────────────────────────────────────────────────────
def _owasp_classification_lines(
    owasp_2017: Any,
    owasp_2021: Any,
    owasp_2025: Any,
    owasp_tags: List[str],
) -> List[str]:
    fallback_2021 = " | ".join(str(t) for t in owasp_tags[:3]) if owasp_tags else "Unclassified"
    return [
        f"OWASP 2017: {owasp_2017 or 'Unclassified'}",
        f"OWASP 2021: {owasp_2021 or fallback_2021}",
        f"OWASP 2025: {owasp_2025 or 'Unclassified'}",
    ]


def _build_kv_table(rows: List[Tuple[str, str]], ss: Any) -> Table:
    """Render a two-column key/value table for finding metadata."""
    data = [
        [Paragraph(k, ss["LabelKey"]), Paragraph(v, ss["Small"])]
        for k, v in rows
    ]
    tbl = Table(data, colWidths=[3.4 * cm, CONTENT_W - 3.4 * cm - 0.35 * cm - 16])
    tbl.setStyle(TableStyle([
        ("TOPPADDING",    (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))
    return tbl


def _build_finding_card(finding: Dict[str, Any], ss: Any) -> List[Any]:
    """Return flowables forming a single finding card."""
    sev = str(finding.get("severity", "info")).lower()
    if sev not in SEVERITY_COLORS:
        sev = "info"
    sev_color = SEVERITY_COLORS[sev]
    sev_bg    = SEVERITY_BG.get(sev, LIGHT_BG)

    title_str  = html_escape(str(finding.get("title", "Finding")))
    confirmed  = finding.get("confirmed", True)
    status_lbl = "CONFIRMED" if confirmed else "UNVERIFIED"
    status_bg  = colors.HexColor("#16a34a") if confirmed else TEXT_MUTED

    port       = str(finding.get("port", ""))
    protocol   = str(finding.get("protocol", "tcp"))
    url_raw    = str(finding.get("url", finding.get("host", "")) or "")
    url_str    = html_escape(url_raw)
    evidence   = html_escape(str(finding.get("evidence", "") or ""))
    desc       = html_escape(str(finding.get("description", "") or ""))
    rec        = html_escape(str(finding.get("recommendation", "") or ""))
    references = [str(r) for r in _ensure_list(finding.get("references")) if str(r).strip()]
    cwe_list   = [str(c) for c in _ensure_list(finding.get("cwe")) if str(c).strip()]
    tags       = [str(t) for t in _ensure_list(finding.get("tags")) if str(t).strip()]
    owasp_tags = [t for t in tags if "owasp" in t.lower()]
    cvss_score = finding.get("cvss_score")
    cve_list   = [str(c) for c in _ensure_list(finding.get("cve")) if str(c).strip()]
    found_by   = html_escape(_resolve_found_by(finding))
    method     = html_escape(str(finding.get("method", "") or ""))
    parameters = finding.get("parameters")
    params_str = ", ".join(str(p) for p in parameters) \
                 if isinstance(parameters, list) else str(parameters or "")
    params_str    = html_escape(params_str)
    owasp_2017    = finding.get("owasp_2017")
    owasp_2021    = finding.get("owasp_2021")
    owasp_2025    = finding.get("owasp_2025")
    epss_score    = finding.get("epss_score")
    epss_pct      = finding.get("epss_percentile")
    cisa_kev      = finding.get("cisa_kev")
    val_steps     = _validation_steps_for_finding(finding)

    STRIP_W = 0.3 * cm
    INNER_W = CONTENT_W - STRIP_W

    # ── Title row ──────────────────────────────────────────────────────
    sev_badge    = _badge(sev.upper(),  sev_color, ss, col_w=2.0 * cm)
    status_badge = _badge(status_lbl, status_bg, ss, col_w=2.5 * cm)

    title_para = Paragraph(
        f'<b><font color="#1e293b">{title_str}</font></b>',
        ss["FindingTitle"],
    )
    title_row = Table(
        [[title_para, sev_badge, status_badge]],
        colWidths=[INNER_W - 4.9 * cm, 2.1 * cm, 2.8 * cm],
    )
    title_row.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), sev_bg),
        ("LINEBELOW",     (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("ALIGN",         (0, 0), (0, 0), "LEFT"),
        ("ALIGN",         (1, 0), (2, 0), "RIGHT"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
    ]))

    # ── Body flowables ────────────────────────────────────────────────
    body_rows: List[List[Any]] = []

    if port:
        body_rows.append([
            Paragraph(f'Port: {port}/{protocol}', ss["SmallMuted"]),
        ])

    # Endpoint / evidence table
    if url_str or evidence:
        ev_cols = [INNER_W * 0.28 - 12, INNER_W * 0.11, INNER_W * 0.19, INNER_W * 0.42 - 12]
        ev_table = Table(
            [
                [Paragraph("Endpoint",         ss["TableHeader"]),
                 Paragraph("Method",           ss["TableHeader"]),
                 Paragraph("Parameters",       ss["TableHeader"]),
                 Paragraph("Evidence",         ss["TableHeader"])],
                [Paragraph(url_str  or "-",    ss["TableCell"]),
                 Paragraph(method   or "-",    ss["TableCell"]),
                 Paragraph(params_str or "-",  ss["TableCell"]),
                 Paragraph(evidence or "-",    ss["TableCell"])],
            ],
            colWidths=ev_cols,
        )
        ev_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), SECTION_BG),
            ("LINEBELOW",     (0, 0), (-1, 0), 0.5, BORDER_COLOR),
            ("BOX",           (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("LINEAFTER",     (0, 0), (2, -1), 0.5, BORDER_COLOR),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        body_rows.append([Spacer(1, 5)])
        body_rows.append([ev_table])

    body_rows.append([Spacer(1, 7)])

    # Description
    if desc:
        body_rows.append([Paragraph("Description", ss["SmallBold"])])
        body_rows.append([Paragraph(desc, ss["Small"])])
        body_rows.append([Spacer(1, 3)])

    # Recommendation
    if rec:
        body_rows.append([Paragraph("Recommendation", ss["SmallBold"])])
        body_rows.append([Paragraph(rec, ss["Small"])])
        body_rows.append([Spacer(1, 3)])

    # References
    if references:
        refs_text = "<br/>".join(
            f'<font color="#2563eb">{html_escape(str(r))}</font>'
            for r in references[:4]
        )
        body_rows.append([Paragraph("References", ss["SmallBold"])])
        body_rows.append([Paragraph(refs_text, ss["Small"])])
        body_rows.append([Spacer(1, 3)])

    # Classification metadata — compact key/value layout
    classify_rows: List[Tuple[str, str]] = []
    classify_rows.append(("Detected by", found_by))
    if cve_list:
        classify_rows.append(("CVE", " | ".join(str(c) for c in cve_list[:5])))
    if cwe_list:
        classify_rows.append(("CWE", " | ".join(str(c) for c in cwe_list[:3])))
    for line in _owasp_classification_lines(owasp_2017, owasp_2021, owasp_2025, owasp_tags):
        key, _, val = line.partition(": ")
        classify_rows.append((key, val))
    if cisa_kev is not None:
        classify_rows.append(("CISA KEV", str(bool(cisa_kev))))
    if cvss_score is not None:
        classify_rows.append(("CVSS v3.1", str(cvss_score)))
    fmt_epss  = _format_epss_score(epss_score)
    fmt_epss_p = _format_epss_percentile(epss_pct)
    if fmt_epss != "-":
        classify_rows.append(("EPSS score", fmt_epss))
    if fmt_epss_p != "-":
        classify_rows.append(("EPSS percentile", fmt_epss_p))

    if classify_rows:
        body_rows.append([Paragraph("Classification", ss["SmallBold"])])
        body_rows.append([_build_kv_table(classify_rows, ss)])
        body_rows.append([Spacer(1, 3)])

    # Validation steps
    if val_steps:
        body_rows.append([Paragraph("Validation steps", ss["SmallBold"])])
        for idx, step in enumerate(val_steps, start=1):
            body_rows.append([Paragraph(f"{idx}.  {html_escape(step)}", ss["Small"])])
        body_rows.append([Spacer(1, 3)])

    # CVE detail table
    if cve_list:
        cve_rows = [[
            Paragraph("CVE",            ss["TableHeader"]),
            Paragraph("CVSS",           ss["TableHeader"]),
            Paragraph("EPSS",           ss["TableHeader"]),
            Paragraph("EPSS pct",       ss["TableHeader"]),
            Paragraph("Summary",        ss["TableHeader"]),
        ]]
        cve_details = _normalize_cve_details(finding.get("cve_details"))
        for cve in cve_list[:8]:
            details = cve_details.get(str(cve), {})
            summary = _format_cve_summary(details, references)
            cve_rows.append([
                Paragraph(html_escape(str(cve)), ss["TableCell"]),
                Paragraph(html_escape(str(details.get("cvss", cvss_score or "-"))), ss["TableCell"]),
                Paragraph(html_escape(_format_epss_score(details.get("epss_score", epss_score))), ss["TableCell"]),
                Paragraph(html_escape(_format_epss_percentile(details.get("epss_percentile", epss_pct))), ss["TableCell"]),
                Paragraph(html_escape(summary), ss["TableCell"]),
            ])
        cve_table = Table(
            cve_rows,
            colWidths=[2.4 * cm, 1.2 * cm, 1.6 * cm, 1.8 * cm,
                       INNER_W - 7.0 * cm - 16],
        )
        cve_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  SECTION_BG),
            ("BOX",           (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("LINEBELOW",     (0, 0), (-1, 0),  0.5, BORDER_COLOR),
            ("LINEAFTER",     (0, 0), (3, -1),  0.5, BORDER_COLOR),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, ROW_ALT]),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        body_rows.append([Paragraph("CVE details", ss["SmallBold"])])
        body_rows.append([cve_table])
        body_rows.append([Spacer(1, 3)])

    # Technology table (WhatWeb findings)
    technologies = _normalize_technologies(finding.get("technologies"))
    if technologies and _is_technology_finding(finding):
        tech_rows = [[
            Paragraph("Software",  ss["TableHeader"]),
            Paragraph("Version",   ss["TableHeader"]),
            Paragraph("Category",  ss["TableHeader"]),
        ]]
        for tech in technologies[:20]:
            tech_rows.append([
                Paragraph(html_escape(str(tech.get("software", "-"))), ss["TableCell"]),
                Paragraph(html_escape(str(tech.get("version", "-"))),  ss["TableCell"]),
                Paragraph(html_escape(str(tech.get("category", "-"))), ss["TableCell"]),
            ])
        col3w = (INNER_W - 16) * 0.35
        tech_table = Table(
            tech_rows,
            colWidths=[(INNER_W - 16) * 0.4,
                       (INNER_W - 16) * 0.25,
                       col3w],
        )
        tech_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  SECTION_BG),
            ("BOX",           (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("LINEBELOW",     (0, 0), (-1, 0),  0.5, BORDER_COLOR),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, ROW_ALT]),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        body_rows.append([Paragraph("Detected technologies", ss["SmallBold"])])
        body_rows.append([tech_table])
        body_rows.append([Spacer(1, 3)])

    body_rows.append([Spacer(1, 4)])

    body_tbl = Table(body_rows, colWidths=[INNER_W - 16])
    body_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), colors.white),
        ("TOPPADDING",    (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))

    # Outer card: left severity strip | content
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


# ── Severity bar chart ────────────────────────────────────────────────────────
def _build_charts(counts: Counter) -> Drawing:
    """Compact vertical bar chart — severity distribution."""
    drawing = Drawing(CONTENT_W, 160)

    bar = VerticalBarChart()
    bar.x      = 0
    bar.y      = 20
    bar.height = 120
    bar.width  = CONTENT_W - 10
    bar.data   = [[counts.get(s, 0) for s in SEVERITY_ORDER]]
    bar.categoryAxis.categoryNames = [s.upper() for s in SEVERITY_ORDER]
    bar.categoryAxis.labels.fontSize = 8
    bar.valueAxis.valueMin  = 0
    max_val = max(bar.data[0]) if bar.data[0] else 1
    bar.valueAxis.valueStep = max(1, max_val // 5)
    bar.valueAxis.labels.fontSize = 7
    bar.barWidth   = 30
    bar.groupSpacing = 20
    bar.strokeColor  = None

    for i, sev in enumerate(SEVERITY_ORDER):
        bar.bars[0, i].fillColor    = SEVERITY_COLORS[sev]
        bar.bars[0, i].strokeColor  = None

    drawing.add(bar)
    return drawing


# ── OWASP mapping ─────────────────────────────────────────────────────────────
def _map_owasp(findings: List[Dict[str, Any]], field_name: str = "owasp_2021") -> Counter:
    mapping: Counter = Counter()
    for finding in findings:
        mapped = finding.get(field_name)
        if mapped:
            mapping[str(mapped)] += 1
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
            mapping["Unclassified"] += 1
    return mapping


def _sorted_scan_coverage(scan_coverage: Dict[str, List[str]]) -> List[Tuple[str, List[str]]]:
    def _sort_key(name: str) -> Tuple[int, int, str]:
        raw = str(name).strip().lower()
        if raw.startswith("porta") or raw.startswith("port"):
            digits = "".join(ch for ch in raw if ch.isdigit())
            if digits:
                return (0, int(digits), raw)
        return (1, 0, raw)

    result: List[Tuple[str, List[str]]] = []
    for key, tests in scan_coverage.items():
        label       = str(key).strip() or "Unspecified"
        unique_tests = sorted({str(t).strip() for t in (tests or []) if str(t).strip()})
        result.append((label, unique_tests))

    return sorted(result, key=lambda item: _sort_key(item[0]))


def _scan_parameters_rows(
    target: str,
    scan_type: str,
    scan_parameters: Optional[Dict[str, Any]],
) -> List[Tuple[str, str]]:
    params = redact_sensitive_data(scan_parameters or {})

    def _str(value: Any, fallback: str = "-") -> str:
        text = str(value).strip() if value is not None else ""
        return text or fallback

    rows: List[Tuple[str, str]] = [
        ("target",         _str(params.get("target",         target))),
        ("scan_type",      _str(params.get("scan_type",      scan_type))),
        ("authentication", _str(params.get("authentication"))),
        ("detection_mode", _str(params.get("detection_mode"))),
    ]
    for key in sorted(k for k in params if str(k).lower().startswith("enumerate_")):
        rows.append((str(key), _str(params.get(key))))

    return rows


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
    safe_scan    = "".join(ch if ch.isalnum() else "_" for ch in (scan_type or "scan")).strip("_")
    safe_target  = "".join(ch if ch.isalnum() else "_" for ch in (target or "target")).strip("_")
    report_name  = f"{safe_scan}-{safe_target}-{generated_at.strftime('%Y%m%d-%H%M')}.pdf"
    report_path  = settings.reports_dir / report_name

    doc = ReportDocTemplate(str(report_path), target=target)
    ss  = _build_styles()

    counts     = _severity_counts(findings)
    risk_level = _risk_label(counts)

    sev_rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    sorted_findings = sorted(
        findings,
        key=lambda f: sev_rank.get(str(f.get("severity", "info")).lower(), 4),
    )

    story: List[Any] = []

    # ── Cover ──────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.4 * cm))
    story.append(Paragraph(_report_title(scan_type), ss["ReportTitle"]))
    story.append(HRFlowable(width=CONTENT_W, thickness=0.5, color=BORDER_COLOR, spaceAfter=6))

    # Target card
    target_rows: List[List[Any]] = [[
        Paragraph(
            f'<font color="#2563eb"><b>{html_escape(target)}</b></font>',
            ss["TargetURL"],
        )
    ]]
    if redirect_from:
        target_rows.append([
            Paragraph(
                f'Redirected from: {html_escape(redirect_from)}',
                ss["BodyMuted"],
            )
        ])
    target_card = Table(target_rows, colWidths=[CONTENT_W])
    target_card.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, -1), colors.HexColor("#f0f9ff")),
        ("BOX",         (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("LINEBEFORE",  (0, 0), (0, -1),  2.5, BRAND_BLUE),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING",(0, 0), (-1, -1), 12),
        ("TOPPADDING",  (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING",(0, 0),(-1, -1), 9),
    ]))
    story.append(target_card)
    story.append(Spacer(1, 4))
    story.append(
        Paragraph(
            f'Generated: {generated_at.strftime("%Y-%m-%d %H:%M UTC")}'
            f'&nbsp;&nbsp;|&nbsp;&nbsp;'
            f'Scan type: {html_escape(_scan_type_label(scan_type))}',
            ss["BodyMuted"],
        )
    )

    # Scan type notice (light / wordpress)
    scan_type_notes = {
        "light": (
            "Light scan executed only WhatWeb, Nikto (HTTP security headers only), "
            "Nmap (top ports) and httpx. SQLi, XSS, Command Injection, XXE and other "
            "deep active checks were not performed."
        ),
        "wordpress": (
            "WordPress scan focuses on WP core, themes and plugins. "
            "Custom application logic may not be fully covered."
        ),
    }
    note = scan_type_notes.get(str(scan_type).lower())
    if note:
        banner = Table(
            [[Paragraph(f"<b>Notice:</b> {html_escape(note)}", ss["Small"])]],
            colWidths=[CONTENT_W],
        )
        banner.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, -1), colors.HexColor("#fff7ed")),
            ("BOX",          (0, 0), (-1, -1), 0.5, colors.HexColor("#f97316")),
            ("LINEBEFORE",   (0, 0), (0, -1),  2.5, colors.HexColor("#f97316")),
            ("LEFTPADDING",  (0, 0), (-1, -1), 12),
            ("RIGHTPADDING", (0, 0), (-1, -1), 12),
            ("TOPPADDING",   (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 7),
        ]))
        story.append(Spacer(1, 8))
        story.append(banner)

    # ── Section 1 — Executive Summary ─────────────────────────────────
    story.append(Spacer(1, 14))
    story.append(Paragraph("Section 1 — Executive Summary", ss["SectionHeader"]))
    story.append(Paragraph(
        "High-level view of the risk posture, severity distribution and top remediation priorities.",
        ss["BodyMuted"],
    ))
    story.append(Spacer(1, 8))
    story.append(_build_executive_kpi_strip(counts, len(findings), risk_level, ss))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Severity distribution", ss["SubHeader"]))
    story.append(_build_severity_heatmap_table(counts, ss))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Remediation roadmap — top priorities", ss["SubHeader"]))
    story.append(_build_remediation_roadmap(sorted_findings, ss, limit=5))
    story.append(Spacer(1, 10))

    # ── Scan summary card ──────────────────────────────────────────────
    story.append(Paragraph("Scan summary", ss["SubHeader"]))
    story.append(
        _build_summary(
            counts, risk_level, target, scan_type,
            start_time, end_time, len(findings), tests_performed, ss,
        )
    )

    # ── Severity chart ─────────────────────────────────────────────────
    if any(counts.values()):
        story.append(Paragraph("Severity chart", ss["SubHeader"]))
        story.append(_build_charts(counts))
        story.append(Spacer(1, 8))

    # ── OWASP mapping ──────────────────────────────────────────────────
    owasp_sets = [
        ("OWASP Top 10 — 2021", OWASP_TOP10_2021, "owasp_2021"),
        ("OWASP Top 10 — 2017", OWASP_TOP10_2017, "owasp_2017"),
        ("OWASP Top 10 — 2025", OWASP_TOP10_2025, "owasp_2025"),
    ]
    for section_title, owasp_categories, field_name in owasp_sets:
        owasp_counts = _map_owasp(findings, field_name=field_name)
        if not owasp_counts:
            continue
        story.append(Paragraph(section_title, ss["SubHeader"]))
        owasp_rows = [[
            Paragraph("Category", ss["TableHeader"]),
            Paragraph("Count",    ss["TableHeader"]),
        ]]
        for entry in owasp_categories:
            cnt = owasp_counts.get(entry, 0)
            owasp_rows.append([
                Paragraph(entry,    ss["TableCell"]),
                Paragraph(str(cnt), ss["TableCell"]),
            ])
        if "Unclassified" in owasp_counts:
            owasp_rows.append([
                Paragraph("Unclassified",                    ss["TableCell"]),
                Paragraph(str(owasp_counts["Unclassified"]), ss["TableCell"]),
            ])
        owasp_tbl = Table(owasp_rows, colWidths=[14 * cm, CONTENT_W - 14 * cm])
        owasp_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  SECTION_BG),
            ("LINEBELOW",     (0, 0), (-1, 0),  0.5, BORDER_COLOR),
            ("BOX",           (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("LINEAFTER",     (0, 0), (0, -1),  0.5, BORDER_COLOR),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, ROW_ALT]),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 10),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN",         (1, 0), (1, -1),  "CENTER"),
        ]))
        story.append(owasp_tbl)
        story.append(Spacer(1, 10))

    # ── Section 2 — Technical Findings ────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("Section 2 — Technical Findings", ss["SectionHeader"]))
    story.append(Paragraph(
        "Full technical appendix with evidence, classification metadata and validation steps "
        "to support triage, remediation and re-test.",
        ss["BodyMuted"],
    ))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Validation checklist", ss["SubHeader"]))
    checklist_rows = [
        [Paragraph("Step", ss["TableHeader"]),
         Paragraph("Objective", ss["TableHeader"])],
        [Paragraph("1", ss["TableCellMono"]),
         Paragraph("Confirm endpoint, HTTP method and parameters impacted by the finding.", ss["TableCell"])],
        [Paragraph("2", ss["TableCellMono"]),
         Paragraph("Reproduce evidence in a controlled environment with least-privilege credentials.", ss["TableCell"])],
        [Paragraph("3", ss["TableCellMono"]),
         Paragraph("Apply remediation and run a focused re-scan to confirm closure.", ss["TableCell"])],
    ]
    checklist_table = Table(checklist_rows, colWidths=[1.5 * cm, CONTENT_W - 1.5 * cm])
    checklist_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  SECTION_BG),
        ("BOX",           (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("LINEAFTER",     (0, 0), (0, -1),  0.5, BORDER_COLOR),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, ROW_ALT]),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
        ("TOPPADDING",    (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("ALIGN",         (0, 0), (0, -1),  "CENTER"),
    ]))
    story.append(checklist_table)
    story.append(Spacer(1, 10))

    story.append(Paragraph("Findings", ss["SectionHeader"]))
    story.append(Spacer(1, 4))

    if not sorted_findings:
        story.append(Paragraph("No findings detected.", ss["Body"]))
    else:
        for finding in sorted_findings:
            story.extend(_build_finding_card(finding, ss))

    # ── Scan parameters ────────────────────────────────────────────────
    story.append(Spacer(1, 8))
    story.append(Paragraph("Scan parameters", ss["SectionHeader"]))
    params_rows = [[
        Paragraph("Parameter", ss["TableHeader"]),
        Paragraph("Value",     ss["TableHeader"]),
    ]]
    for key, value in _scan_parameters_rows(target, scan_type, scan_parameters):
        params_rows.append([
            Paragraph(html_escape(str(key)),   ss["TableCellMono"]),
            Paragraph(html_escape(str(value)), ss["TableCell"]),
        ])
    params_table = Table(params_rows, colWidths=[5.5 * cm, CONTENT_W - 5.5 * cm])
    params_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  SECTION_BG),
        ("BOX",           (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("LINEAFTER",     (0, 0), (0, -1),  0.5, BORDER_COLOR),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, ROW_ALT]),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(params_table)

    # ── Scan statistics ────────────────────────────────────────────────
    if scan_stats:
        story.append(Spacer(1, 8))
        story.append(Paragraph("Scan statistics", ss["SectionHeader"]))
        stats_rows = [[
            Paragraph("Metric", ss["TableHeader"]),
            Paragraph("Value",  ss["TableHeader"]),
        ]]

        def _format_stat_value(metric_key: str) -> str:
            aliases = {
                "average_response_time":   ["average_response_time", "avg_response_time"],
                "urls_spidered":           ["urls_spidered"],
                "unique_injection_points": ["unique_injection_points"],
                "total_http_requests":     ["total_http_requests"],
            }
            value = next(
                (scan_stats.get(a) for a in aliases.get(metric_key, [metric_key]) if a in scan_stats),
                None,
            )
            if value is None:
                return "-"
            if metric_key == "average_response_time":
                try:
                    return f"{float(value):.3f} s"
                except (TypeError, ValueError):
                    return str(value)
            return f"{value:.2f}" if isinstance(value, float) else str(value)

        stat_labels = {
            "urls_spidered":           "URLs spidered",
            "unique_injection_points": "Unique injection points",
            "total_http_requests":     "Total HTTP requests",
            "average_response_time":   "Average response time",
        }
        for key, label in stat_labels.items():
            stats_rows.append([
                Paragraph(label,                               ss["TableCell"]),
                Paragraph(html_escape(_format_stat_value(key)), ss["TableCell"]),
            ])

        stats_table = Table(stats_rows, colWidths=[6.5 * cm, CONTENT_W - 6.5 * cm])
        stats_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  SECTION_BG),
            ("BOX",           (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("LINEAFTER",     (0, 0), (0, -1),  0.5, BORDER_COLOR),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, ROW_ALT]),
            ("LEFTPADDING",   (0, 0), (-1, -1), 10),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(stats_table)

    # ── Scan coverage ──────────────────────────────────────────────────
    if scan_coverage:
        story.append(PageBreak())
        story.append(Paragraph("Scan coverage", ss["SectionHeader"]))
        story.append(Paragraph(
            "Complete list of tests executed, grouped by port / category.",
            ss["BodyMuted"],
        ))
        story.append(Spacer(1, 6))

        coverage_rows = [[
            Paragraph("Port / Category", ss["TableHeader"]),
            Paragraph("Tests performed", ss["TableHeader"]),
        ]]
        for key, tests in _sorted_scan_coverage(scan_coverage):
            tests_text = "<br/>".join(
                f"- {html_escape(t)}" for t in tests
            ) or "- No tests recorded"
            coverage_rows.append([
                Paragraph(html_escape(key), ss["TableCell"]),
                Paragraph(tests_text,        ss["TableCell"]),
            ])

        coverage_table = Table(coverage_rows, colWidths=[6.0 * cm, CONTENT_W - 6.0 * cm])
        coverage_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  SECTION_BG),
            ("BOX",           (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("LINEAFTER",     (0, 0), (0, -1),  0.5, BORDER_COLOR),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, ROW_ALT]),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING",   (0, 0), (-1, -1), 10),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(coverage_table)

    doc.build(story)
    return report_path
