#!/usr/bin/env python3
"""PDF report generator using ReportLab."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableOfContents,
    TableStyle,
)
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.legends import Legend
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing, Rect, String

from config import settings


SEVERITY_COLORS = {
    "critical": colors.red,
    "high": colors.orangered,
    "medium": colors.orange,
    "low": colors.yellow,
    "info": colors.lightgrey,
}

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
OWASP_TOP10 = [
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


class ReportDocTemplate(BaseDocTemplate):
    def __init__(self, filename: str, *, target: str) -> None:
        super().__init__(filename, pagesize=A4)
        self.target = target
        frame = Frame(self.leftMargin, self.bottomMargin, self.width, self.height, id="normal")
        template = PageTemplate(id="report", frames=[frame], onPage=self._draw_header_footer)
        self.addPageTemplates([template])

    def _draw_header_footer(self, canvas, doc) -> None:  # type: ignore[override]
        canvas.saveState()
        canvas.setFont("Helvetica-Bold", 9)
        canvas.drawString(doc.leftMargin, doc.pagesize[1] - 30, "Vulnerability Assessment Report")
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(
            doc.pagesize[0] - doc.rightMargin,
            doc.pagesize[1] - 30,
            f"Target: {self.target}",
        )
        canvas.setFont("Helvetica", 8)
        canvas.drawCentredString(doc.pagesize[0] / 2.0, 20, f"Pagina {doc.page}")
        canvas.restoreState()

    def afterFlowable(self, flowable) -> None:  # type: ignore[override]
        if not isinstance(flowable, Paragraph):
            return
        style_name = flowable.style.name
        if style_name == "Heading2TOC":
            level = 0
        elif style_name == "Heading3TOC":
            level = 1
        else:
            return
        text = flowable.getPlainText()
        self.notify("TOCEntry", (level, text, self.page))


def _severity_counts(findings: List[Dict[str, Any]]) -> Counter:
    return Counter(str(item.get("severity", "info")).lower() for item in findings)


def _risk_label(counts: Counter) -> str:
    for severity in SEVERITY_ORDER:
        if counts.get(severity, 0) > 0:
            return severity.upper()
    return "INFO"


def _build_logo_placeholder() -> Drawing:
    drawing = Drawing(120, 40)
    drawing.add(Rect(0, 0, 120, 40, strokeColor=colors.grey, fillColor=colors.whitesmoke))
    drawing.add(String(60, 15, "LOGO", textAnchor="middle", fontSize=12))
    return drawing


def _build_severity_table(counts: Counter) -> Table:
    data = [["Severity", "Count"]]
    for severity in SEVERITY_ORDER:
        data.append([severity.title(), str(counts.get(severity, 0))])
    table = Table(data, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
            ]
        )
    )
    for row_index, severity in enumerate(SEVERITY_ORDER, start=1):
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, row_index), (0, row_index), SEVERITY_COLORS[severity]),
                    ("TEXTCOLOR", (0, row_index), (0, row_index), colors.black),
                ]
            )
        )
    return table


def _build_charts(counts: Counter) -> Drawing:
    pie = Pie()
    pie.x = 10
    pie.y = 10
    pie.width = 160
    pie.height = 160
    pie.data = [counts.get(sev, 0) for sev in SEVERITY_ORDER]
    pie.labels = [sev.title() for sev in SEVERITY_ORDER]
    pie.slices.strokeWidth = 0.5
    for idx, severity in enumerate(SEVERITY_ORDER):
        pie.slices[idx].fillColor = SEVERITY_COLORS[severity]

    bar = VerticalBarChart()
    bar.x = 210
    bar.y = 20
    bar.height = 140
    bar.width = 220
    bar.data = [[counts.get(sev, 0) for sev in SEVERITY_ORDER]]
    bar.categoryAxis.categoryNames = [sev.title() for sev in SEVERITY_ORDER]
    bar.valueAxis.valueMin = 0
    bar.valueAxis.valueStep = max(1, max(bar.data[0]) // 5) if bar.data[0] else 1
    bar.bars[0].fillColor = colors.HexColor("#2563eb")

    legend = Legend()
    legend.x = 210
    legend.y = 170
    legend.colorNamePairs = [
        (SEVERITY_COLORS[sev], sev.title()) for sev in SEVERITY_ORDER
    ]

    drawing = Drawing(440, 200)
    drawing.add(pie)
    drawing.add(bar)
    drawing.add(legend)
    return drawing


def _scan_coverage(scan_type: str) -> List[Tuple[str, str]]:
    scan_type = scan_type.lower()
    all_scanners = ["nuclei", "nmap", "whatweb", "subfinder", "nikto", "dirsearch"]
    included = set(all_scanners if scan_type == "full" else [scan_type])
    return [(scanner, "Incluso" if scanner in included else "Escluso") for scanner in all_scanners]


def _map_owasp(findings: List[Dict[str, Any]]) -> Counter:
    mapping = Counter()
    for finding in findings:
        tags = [str(tag).lower() for tag in finding.get("tags", []) if tag]
        owasp_tag = next((tag for tag in tags if tag.startswith("owasp")), "")
        if owasp_tag:
            mapping[owasp_tag.upper()] += 1
            continue
        cwe_list = [str(cwe).lower() for cwe in finding.get("cwe", []) if cwe]
        if any(cwe.startswith("cwe-79") for cwe in cwe_list):
            mapping["A03:2021 - Injection"] += 1
        elif any(cwe.startswith("cwe-89") for cwe in cwe_list):
            mapping["A03:2021 - Injection"] += 1
        elif any(cwe.startswith("cwe-306") for cwe in cwe_list):
            mapping["A01:2021 - Broken Access Control"] += 1
        elif any(cwe.startswith("cwe-200") for cwe in cwe_list):
            mapping["A02:2021 - Cryptographic Failures"] += 1
        else:
            mapping["Non classificato"] += 1
    return mapping


def generate_report(scan_id: int, target: str, scan_type: str, findings: List[Dict[str, Any]]) -> Path:
    generated_at = datetime.now(timezone.utc)
    report_name = f"scan_{scan_id}_{generated_at.strftime('%Y%m%d_%H%M%S')}.pdf"
    report_path = settings.reports_dir / report_name

    doc = ReportDocTemplate(str(report_path), target=target)
    styles = getSampleStyleSheet()
    severity_styles = {}
    for severity, color in SEVERITY_COLORS.items():
        style_name = f"Severity{severity.title()}"
        if style_name not in styles:
            styles.add(ParagraphStyle(name=style_name, parent=styles["Heading4"], textColor=color))
        severity_styles[severity] = styles[style_name]
    styles.add(
        ParagraphStyle(
            name="Heading2TOC",
            parent=styles["Heading2"],
            spaceAfter=6,
            spaceBefore=12,
            keepWithNext=True,
            outlineLevel=1,
        )
    )
    styles.add(
        ParagraphStyle(
            name="Heading3TOC",
            parent=styles["Heading3"],
            spaceAfter=6,
            spaceBefore=10,
            keepWithNext=True,
            outlineLevel=2,
        )
    )
    story = []

    story.append(_build_logo_placeholder())
    story.append(Spacer(1, 12))
    story.append(Paragraph("Vulnerability Assessment Report", styles["Title"]))
    story.append(Spacer(1, 12))

    meta_table = Table(
        [
            ["Target", target],
            ["Scan Type", scan_type],
            ["Generated", generated_at.strftime("%Y-%m-%d %H:%M UTC")],
            ["Findings", str(len(findings))],
        ],
        hAlign="LEFT",
    )
    meta_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
            ]
        )
    )
    story.append(meta_table)
    story.append(Spacer(1, 12))
    story.append(PageBreak())

    toc = TableOfContents()
    toc.levelStyles = [
        ParagraphStyle(fontName="Helvetica", name="TOCLevel1", fontSize=10, leftIndent=20),
        ParagraphStyle(fontName="Helvetica", name="TOCLevel2", fontSize=9, leftIndent=40),
    ]
    story.append(Paragraph("Table of Contents", styles["Heading2TOC"]))
    story.append(toc)
    story.append(PageBreak())

    counts = _severity_counts(findings)
    risk_level = _risk_label(counts)
    summary_text = (
        f"Il report sintetizza {len(findings)} finding sul target {target}. "
        f"Il livello di rischio complessivo è {risk_level}. "
        "Gli indicatori principali includono esposizioni di servizi, "
        "configurazioni non sicure e potenziali vulnerabilità applicative."
    )
    story.append(Paragraph("Executive Summary", styles["Heading2TOC"]))
    story.append(Paragraph(summary_text, styles["BodyText"]))
    story.append(Spacer(1, 8))
    story.append(_build_severity_table(counts))
    story.append(Spacer(1, 12))

    scan_params = Table(
        [
            ["Parametro", "Valore"],
            ["Timeout scansione (s)", str(settings.scan_timeout_seconds)],
            ["Max scanner concorrenti", str(settings.max_concurrent_scanners)],
            ["Profilo Nmap", settings.nmap_profile],
            ["Rate limit Nuclei", str(settings.nuclei_rate_limit)],
            ["Severità Nuclei", settings.nuclei_severities],
            ["Template Nuclei", settings.nuclei_templates or "default"],
            ["Live scans abilitate", "Sì" if settings.enable_live_scans else "No"],
        ],
        hAlign="LEFT",
    )
    scan_params.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
            ]
        )
    )
    story.append(Paragraph("Scan Parameters", styles["Heading2TOC"]))
    story.append(scan_params)
    story.append(Spacer(1, 12))

    coverage_table = Table(
        [["Scanner", "Copertura"]] + _scan_coverage(scan_type),
        hAlign="LEFT",
    )
    coverage_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
            ]
        )
    )
    story.append(Paragraph("Scan Coverage", styles["Heading2TOC"]))
    story.append(coverage_table)
    story.append(Spacer(1, 12))

    story.append(Paragraph("Severity Overview", styles["Heading2TOC"]))
    story.append(_build_charts(counts))
    story.append(Spacer(1, 12))

    owasp_counts = _map_owasp(findings)
    owasp_rows = [["Categoria", "Totale"]]
    for entry in OWASP_TOP10:
        owasp_rows.append([entry, str(owasp_counts.get(entry, 0))])
    if "Non classificato" in owasp_counts:
        owasp_rows.append(["Non classificato", str(owasp_counts["Non classificato"])])
    owasp_table = Table(owasp_rows, hAlign="LEFT", colWidths=[11 * cm, 3 * cm])
    owasp_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
            ]
        )
    )
    story.append(Paragraph("OWASP Top 10 Mapping", styles["Heading2TOC"]))
    story.append(owasp_table)

    if not findings:
        story.append(Paragraph("Dettaglio findings", styles["Heading2TOC"]))
        story.append(Paragraph("Nessun finding rilevato.", styles["BodyText"]))
    else:
        story.append(Paragraph("Dettaglio findings", styles["Heading2TOC"]))
        story.append(Spacer(1, 6))
        for finding in findings:
            severity = finding.get("severity", "info").lower()
            title = finding.get("title", "Finding")
            description = finding.get("description", "")
            recommendation = finding.get("recommendation", "")
            cve_list = finding.get("cve") or []
            cwe_list = finding.get("cwe") or []
            cvss_score = finding.get("cvss_score") or "n/d"
            cvss_metrics = finding.get("cvss_metrics") or "n/d"

            severity_style = severity_styles.get(severity, styles["Heading4"])
            story.append(Paragraph(f"<b>{title}</b> ({severity})", severity_style))
            story.append(Paragraph(description, styles["BodyText"]))
            story.append(
                Paragraph(
                    f"<b>CVE:</b> {', '.join(cve_list) if cve_list else 'n/d'} "
                    f" | <b>CWE:</b> {', '.join(cwe_list) if cwe_list else 'n/d'}",
                    styles["BodyText"],
                )
            )
            story.append(
                Paragraph(
                    f"<b>CVSS Score:</b> {cvss_score} | <b>CVSS Metrics:</b> {cvss_metrics}",
                    styles["BodyText"],
                )
            )
            if recommendation:
                story.append(Paragraph(f"<b>Remediation:</b> {recommendation}", styles["BodyText"]))
            story.append(Spacer(1, 8))

    doc.build(story)
    return report_path
