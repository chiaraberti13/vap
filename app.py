#!/usr/bin/env python3
"""FastAPI application for Vulnerability Assessment Platform."""
from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime
import json
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from config import settings
from database import Scan, get_db, init_db
from report_generator import generate_report
from scanner_engine import ScanValidationError, run_scan, serialize_findings


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(title=settings.app_name, lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")

SCAN_TYPES = ["full", "nuclei", "nmap", "whatweb", "subfinder", "nikto", "dirsearch"]


class APIKeyUIError(Exception):
    def __init__(self, detail: str) -> None:
        self.detail = detail


def _resolve_api_key(request: Request, submitted_key: Optional[str] = None) -> Optional[str]:
    return submitted_key or request.headers.get("x-api-key") or request.query_params.get("api_key")


def enforce_api_key(request: Request) -> None:
    if not settings.api_key:
        return
    api_key = _resolve_api_key(request)
    if api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="API key non valida")


def enforce_api_key_from_form(request: Request, submitted_key: Optional[str]) -> None:
    if not settings.api_key:
        return
    api_key = _resolve_api_key(request, submitted_key)
    if api_key != settings.api_key:
        raise APIKeyUIError("API key non valida o mancante.")


def enforce_api_key_form_dependency(
    request: Request,
    api_key: Optional[str] = Form(None),
) -> Optional[str]:
    enforce_api_key_from_form(request, api_key)
    return api_key


@app.exception_handler(APIKeyUIError)
def api_key_ui_exception_handler(request: Request, exc: APIKeyUIError) -> HTMLResponse:
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "scan_types": SCAN_TYPES,
            "api_key_required": bool(settings.api_key),
            "error": exc.detail,
        },
        status_code=401,
    )


@app.middleware("http")
async def enforce_https(request: Request, call_next):
    if settings.require_https:
        forwarded_proto = request.headers.get("x-forwarded-proto", "")
        is_https = request.url.scheme == "https" or forwarded_proto == "https"
        if not is_https:
            https_url = request.url.replace(scheme="https")
            return RedirectResponse(str(https_url), status_code=308)
    return await call_next(request)


class ScanCreate(BaseModel):
    target: str = Field(..., max_length=255)
    scan_type: str = Field("full")


class ScanStatus(BaseModel):
    id: int
    target: str
    scan_type: str
    status: str
    created_at: datetime
    completed_at: Optional[datetime]



@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "scan_types": SCAN_TYPES,
            "api_key_required": bool(settings.api_key),
        },
    )


@app.post("/scans", response_class=HTMLResponse)
def create_scan_form(
    request: Request,
    target: str = Form(...),
    scan_type: str = Form("full"),
    api_key: Optional[str] = Depends(enforce_api_key_form_dependency),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    try:
        scan_result = run_scan(target=target, scan_type=scan_type)
    except ScanValidationError as exc:
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "scan_types": SCAN_TYPES,
                "api_key_required": bool(settings.api_key),
                "error": str(exc),
            },
            status_code=400,
        )

    scan = Scan(
        target=scan_result.target,
        scan_type=scan_result.scan_type,
        status=scan_result.status,
        created_at=scan_result.started_at,
        completed_at=scan_result.completed_at,
        findings_json=serialize_findings(scan_result.findings),
    )
    db.add(scan)
    db.flush()

    report_error = None
    try:
        report_path = generate_report(scan.id, scan.target, scan.scan_type, scan_result.findings)
    except Exception:
        report_error = "Impossibile generare il report PDF. Verifica i permessi della cartella reports/."
        scan.status = "report_failed"
        scan.report_path = None
    else:
        scan.report_path = str(report_path)
    db.commit()
    db.refresh(scan)

    redirect_url = f"/scans/{scan.id}"
    if api_key:
        redirect_url = f"{redirect_url}?api_key={api_key}"

    if report_error:
        findings = json.loads(scan.findings_json or "[]")
        return templates.TemplateResponse(
            "scan_detail.html",
            {
                "request": request,
                "scan": scan,
                "findings": findings,
                "report_error": report_error,
                "download_url": None,
                "api_key": api_key,
            },
            status_code=200,
        )

    return RedirectResponse(url=redirect_url, status_code=303)


@app.get("/scans", response_class=HTMLResponse)
def scans_list(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    scans = db.query(Scan).order_by(Scan.created_at.desc()).all()
    api_key = request.query_params.get("api_key")
    return templates.TemplateResponse(
        "scans_list.html",
        {
            "request": request,
            "scans": scans,
            "api_key": api_key,
        },
    )


@app.get("/scans/{scan_id}", response_class=HTMLResponse)
def scan_detail(request: Request, scan_id: int, db: Session = Depends(get_db)) -> HTMLResponse:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan non trovata")

    findings = json.loads(scan.findings_json or "[]")
    api_key = request.query_params.get("api_key")
    download_url = None
    if scan.report_path:
        download_url = f"/scans/{scan.id}/report/download"
        if api_key:
            download_url = f"{download_url}?api_key={api_key}"
    return templates.TemplateResponse(
        "scan_detail.html",
        {
            "request": request,
            "scan": scan,
            "findings": findings,
            "download_url": download_url,
            "api_key": api_key,
        },
    )


@app.post("/api/v1/scans", response_model=ScanStatus)
def create_scan(
    payload: ScanCreate,
    db: Session = Depends(get_db),
    _: None = Depends(enforce_api_key),
) -> ScanStatus:
    try:
        scan_result = run_scan(target=payload.target, scan_type=payload.scan_type)
    except ScanValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    scan = Scan(
        target=scan_result.target,
        scan_type=scan_result.scan_type,
        status=scan_result.status,
        created_at=scan_result.started_at,
        completed_at=scan_result.completed_at,
        findings_json=serialize_findings(scan_result.findings),
    )
    db.add(scan)
    db.flush()

    try:
        report_path = generate_report(scan.id, scan.target, scan.scan_type, scan_result.findings)
    except Exception:
        scan.status = "report_failed"
        scan.report_path = None
        db.commit()
        return ScanStatus(
            id=scan.id,
            target=scan.target,
            scan_type=scan.scan_type,
            status=scan.status,
            created_at=scan.created_at,
            completed_at=scan.completed_at,
        )

    scan.report_path = str(report_path)
    db.commit()
    db.refresh(scan)

    return ScanStatus(
        id=scan.id,
        target=scan.target,
        scan_type=scan.scan_type,
        status=scan.status,
        created_at=scan.created_at,
        completed_at=scan.completed_at,
    )


@app.get("/scans/{scan_id}/report/download")
def download_report_ui(
    request: Request,
    scan_id: int,
    db: Session = Depends(get_db),
    _: None = Depends(enforce_api_key),
) -> FileResponse:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan or not scan.report_path:
        raise HTTPException(status_code=404, detail="Report non disponibile")

    return FileResponse(
        scan.report_path,
        media_type="application/pdf",
        filename=scan.report_path.split("/")[-1],
    )


@app.get("/api/v1/scans", response_model=List[ScanStatus])
def list_scans(
    db: Session = Depends(get_db),
    _: None = Depends(enforce_api_key),
) -> List[ScanStatus]:
    scans = db.query(Scan).order_by(Scan.created_at.desc()).all()
    return [
        ScanStatus(
            id=scan.id,
            target=scan.target,
            scan_type=scan.scan_type,
            status=scan.status,
            created_at=scan.created_at,
            completed_at=scan.completed_at,
        )
        for scan in scans
    ]


@app.get("/api/v1/scans/{scan_id}/status", response_model=ScanStatus)
def scan_status(
    scan_id: int,
    db: Session = Depends(get_db),
    _: None = Depends(enforce_api_key),
) -> ScanStatus:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan non trovata")

    return ScanStatus(
        id=scan.id,
        target=scan.target,
        scan_type=scan.scan_type,
        status=scan.status,
        created_at=scan.created_at,
        completed_at=scan.completed_at,
    )


@app.get("/api/v1/scans/{scan_id}/report/download")
def download_report(
    scan_id: int,
    db: Session = Depends(get_db),
    _: None = Depends(enforce_api_key),
) -> FileResponse:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan or not scan.report_path:
        raise HTTPException(status_code=404, detail="Report non disponibile")

    return FileResponse(
        scan.report_path,
        media_type="application/pdf",
        filename=scan.report_path.split("/")[-1],
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host=settings.host, port=settings.port, reload=False)
