#!/usr/bin/env python3
"""PDF report generator using ReportLab."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

from config import settings


SEVERITY_COLORS = {
    "critical": colors.red,
    "high": colors.orangered,
    "medium": colors.orange,
    "low": colors.yellow,
    "info": colors.lightgrey,
}


def generate_report(scan_id: int, target: str, scan_type: str, findings: List[Dict[str, Any]]) -> Path:
    report_name = f"scan_{scan_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    report_path = settings.reports_dir / report_name

    doc = SimpleDocTemplate(str(report_path), pagesize=A4)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("Vulnerability Assessment Report", styles["Title"]))
    story.append(Spacer(1, 12))

    meta_table = Table(
        [
            ["Target", target],
            ["Scan Type", scan_type],
            ["Generated", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
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

    if not findings:
        story.append(Paragraph("Nessun finding rilevato.", styles["BodyText"]))
    else:
        story.append(Paragraph("Dettaglio findings", styles["Heading2"]))
        story.append(Spacer(1, 6))
        for finding in findings:
            severity = finding.get("severity", "info").lower()
            title = finding.get("title", "Finding")
            description = finding.get("description", "")
            recommendation = finding.get("recommendation", "")

            story.append(Paragraph(f"<b>{title}</b> ({severity})", styles["Heading4"]))
            story.append(Paragraph(description, styles["BodyText"]))
            if recommendation:
                story.append(Paragraph(f"<b>Remediation:</b> {recommendation}", styles["BodyText"]))
            story.append(Spacer(1, 8))

    doc.build(story)
    return report_path
