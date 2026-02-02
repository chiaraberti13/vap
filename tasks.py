#!/usr/bin/env python3
"""Celery tasks for asynchronous scans and maintenance."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any, Dict, List
from uuid import uuid4

from celery import chord

from celery_app import celery_app
from database import SessionLocal, Scan
from enrichment_engine import enrich_findings
from report_generator import generate_report
from scanner_engine import (
    ScanValidationError,
    get_scanner_classes,
    run_single_scanner,
    serialize_findings,
)


def _append_log(scan: Scan, message: str, level: str = "info") -> None:
    payload = json.loads(scan.logs_json or "[]")
    payload.append(
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "message": message,
        }
    )
    scan.logs_json = json.dumps(payload, ensure_ascii=False)


def _append_notifications(scan: Scan, notifications: List[Dict[str, Any]]) -> None:
    payload = json.loads(scan.notifications_json or "[]")
    payload.extend(notifications)
    scan.notifications_json = json.dumps(payload, ensure_ascii=False)


@celery_app.task(bind=True, autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={"max_retries": 3})
def run_scanner_task(self, scan_id: int, scanner_name: str, target: str) -> Dict[str, Any]:
    with SessionLocal() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan or scan.status == "canceled":
            return {"tool": scanner_name, "status": "canceled", "findings": []}

        _append_log(scan, f"Avvio scanner {scanner_name}.")
        db.commit()

    try:
        result = run_single_scanner(scanner_name, target)
    except ScanValidationError as exc:
        result = {"tool": scanner_name, "status": "error", "message": str(exc), "findings": []}

    critical_notifications = [
        {
            "title": finding.get("title", "Finding critico"),
            "severity": finding.get("severity", "critical"),
            "description": finding.get("description", ""),
        }
        for finding in result.get("findings", [])
        if str(finding.get("severity", "")).lower() in {"critical", "high"}
    ]

    with SessionLocal() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return result

        scan.completed_scanners = (scan.completed_scanners or 0) + 1
        total_scanners = max(1, scan.total_scanners or 1)
        scan.progress = min(100, int((scan.completed_scanners / total_scanners) * 100))
        _append_log(scan, f"Scanner {scanner_name} completato con stato {result.get('status')}.")
        if critical_notifications:
            _append_notifications(scan, critical_notifications)
            _append_log(scan, f"Notifiche critiche: {len(critical_notifications)}", "warning")
        db.commit()

    return result


@celery_app.task(bind=True)
def orchestrate_scan(self, scan_id: int, scan_type: str, target: str) -> str:
    scanner_classes = get_scanner_classes(scan_type)
    scanner_names = [scanner.__name__.replace("Scanner", "").lower() for scanner in scanner_classes]

    with SessionLocal() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return "scan_not_found"
        scan.status = "running"
        scan.total_scanners = len(scanner_names)
        scan.completed_scanners = 0
        scan.progress = 0
        priority = scan.priority or 5
        _append_log(scan, "Scansione in esecuzione.")
        db.commit()

    tasks = []
    for scanner_name in scanner_names:
        task_id = str(uuid4())
        tasks.append(
            run_scanner_task.s(scan_id, scanner_name, target).set(task_id=task_id, priority=priority)
        )

    with SessionLocal() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.child_task_ids_json = json.dumps([task.options.get("task_id") for task in tasks])
            db.commit()

    callback = finalize_scan.s(scan_id=scan_id, target=target, scan_type=scan_type)
    chord(tasks)(callback)
    return "queued"


@celery_app.task(bind=True)
def finalize_scan(self, results: List[Dict[str, Any]], scan_id: int, target: str, scan_type: str) -> str:
    findings: List[Dict[str, Any]] = []
    for result in results:
        findings.extend(result.get("findings", []))
    findings = enrich_findings(findings)

    with SessionLocal() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return "scan_not_found"
        if scan.status == "canceled":
            _append_log(scan, "Scansione annullata. Nessun report generato.", "warning")
            db.commit()
            return "canceled"

        scan.completed_at = datetime.now(timezone.utc)
        scan.status = "completed"
        scan.progress = 100
        scan.findings_json = serialize_findings(findings)

        try:
            report_path = generate_report(scan.id, target, scan_type, findings)
        except Exception as exc:
            scan.status = "report_failed"
            scan.report_path = None
            _append_log(scan, f"Errore report PDF: {exc}", "error")
        else:
            scan.report_path = str(report_path)
            _append_log(scan, "Report PDF generato.")

        db.commit()
    return "completed"
