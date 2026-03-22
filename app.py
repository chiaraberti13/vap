#!/usr/bin/env python3
"""FastAPI application for Vulnerability Assessment Platform."""
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import asyncio
import json
from pathlib import Path
from time import perf_counter
from typing import Any, Dict, List, Optional, Set
from uuid import uuid4

from fastapi import Body, Depends, FastAPI, Form, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from pydantic import BaseModel, Field
from redis import Redis
from redis.exceptions import RedisError
from sqlalchemy import text
from sqlalchemy.orm import Query, Session
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware
import structlog

from background_jobs import start_background_jobs
from celery_app import celery_app, check_broker_connection
from compliance import (
    DATA_CLASSIFICATIONS,
    CONSENT_TYPES,
    anonymize_scan_for_export,
    get_subject_id,
    has_required_consents,
    record_audit_event,
    record_consent,
)
from config import settings
from database import ConsentRecord, Scan, SessionLocal, get_db, init_db
from scanner_engine import (
    ScanValidationError,
    validate_nmap_target,
    validate_target,
)
from security import (
    configure_structlog,
    create_access_token,
    generate_csrf_token,
    log_audit_event,
    redact_api_key,
    require_jwt_configuration,
    validate_csrf_request,
    verify_api_key,
    verify_jwt_token,
)
from tasks import orchestrate_scan


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    configure_structlog()
    require_jwt_configuration()
    scheduler = start_background_jobs()
    if not check_broker_connection():
        import logging
        logging.getLogger("vap.startup").warning(
            "Celery broker non raggiungibile (%s). "
            "Le scansioni non potranno essere accodate finché Redis non è avviato. "
            "Avvia Redis con: redis-server",
            settings.celery_broker_url,
        )
    yield
    scheduler.shutdown(wait=False)


limiter = Limiter(key_func=get_remote_address, default_limits=[settings.rate_limit_default])
http_logger = structlog.get_logger("vap.http")

try:
    REQUEST_COUNT = Counter(
        "vap_http_requests_total",
        "Numero totale di richieste HTTP",
        ["method", "path", "status_code"],
    )
except ValueError:
    # Already registered (e.g., on uvicorn hot-reload)
    from prometheus_client import REGISTRY as _REGISTRY
    REQUEST_COUNT = _REGISTRY._names_to_collectors["vap_http_requests"]

try:
    REQUEST_LATENCY = Histogram(
        "vap_http_request_duration_seconds",
        "Durata delle richieste HTTP in secondi",
        ["method", "path"],
    )
except ValueError:
    from prometheus_client import REGISTRY as _REGISTRY
    REQUEST_LATENCY = _REGISTRY._names_to_collectors["vap_http_request_duration_seconds"]

app = FastAPI(
    title=settings.app_name,
    description="Vulnerability Assessment Platform API",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.mount("/static", StaticFiles(directory="static"), name="static")
app.add_middleware(SessionMiddleware, secret_key=settings.csrf_secret)

if settings.cors_allowed_origins:
    from fastapi.middleware.cors import CORSMiddleware

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allowed_origins,
        allow_credentials=settings.cors_allow_credentials,
        allow_methods=settings.cors_allowed_methods,
        allow_headers=settings.cors_allowed_headers,
    )

templates = Jinja2Templates(directory="templates")

SCAN_TYPES = [
    "full",
    "nuclei",
    "nmap",
    "whatweb",
    "subfinder",
    "nikto",
    "dirsearch",
    "sqlmap",
    "xsstrike",
    "zap",
    "burp",
    "wapiti",
    "commix",
    "acunetix",
    "nessus",
]


def _init_api_cache() -> Optional[Redis]:
    if not settings.api_cache_enabled or not settings.api_cache_redis_url:
        return None
    try:
        client = Redis.from_url(settings.api_cache_redis_url, decode_responses=True)
        client.ping()
    except RedisError:
        return None
    return client


api_cache = _init_api_cache()


def _cache_key(*parts: str) -> str:
    return ":".join([settings.api_cache_prefix, *parts])


def _get_cached_json(key: str) -> Optional[Any]:
    if not api_cache:
        return None
    try:
        cached = api_cache.get(key)
    except RedisError:
        return None
    if not cached:
        return None
    try:
        return json.loads(cached)
    except json.JSONDecodeError:
        return None


def _set_cached_json(key: str, payload: Any) -> None:
    if not api_cache:
        return
    try:
        api_cache.setex(key, settings.api_cache_ttl_seconds, json.dumps(payload))
    except RedisError:
        return


def _invalidate_cache_keys(*keys: str) -> None:
    if not api_cache or not keys:
        return
    try:
        api_cache.delete(*keys)
    except RedisError:
        return


def _record_audit(
    db: Session,
    request: Request,
    event: str,
    subject_id: Optional[str] = None,
    **metadata: Any,
) -> None:
    log_audit_event(event, request=request, **metadata)
    record_audit_event(db, request=request, event=event, subject_id=subject_id, metadata=metadata)


class APIKeyUIError(Exception):
    def __init__(self, detail: str) -> None:
        self.detail = detail


def _resolve_api_key(request: Request, submitted_key: Optional[str] = None) -> Optional[str]:
    return submitted_key or request.headers.get("x-api-key") or request.query_params.get("api_key")


def enforce_api_key(request: Request) -> None:
    if not settings.api_key and not settings.api_key_hash:
        return
    api_key = _resolve_api_key(request)
    if not api_key or not verify_api_key(api_key):
        log_audit_event(
            "api_key_invalid",
            request=request,
            api_key=redact_api_key(api_key),
        )
        raise HTTPException(status_code=401, detail="API key non valida")


def enforce_api_key_from_form(request: Request, submitted_key: Optional[str]) -> None:
    if not settings.api_key and not settings.api_key_hash:
        return
    api_key = _resolve_api_key(request, submitted_key)
    if not api_key or not verify_api_key(api_key):
        log_audit_event(
            "api_key_invalid",
            request=request,
            api_key=redact_api_key(api_key),
        )
        raise APIKeyUIError("API key non valida o mancante.")


def enforce_api_key_form_dependency(
    request: Request,
    api_key: Optional[str] = Form(None),
) -> Optional[str]:
    enforce_api_key_from_form(request, api_key)
    return api_key


@app.exception_handler(APIKeyUIError)
def api_key_ui_exception_handler(request: Request, exc: APIKeyUIError) -> Response:
    csrf_token = generate_csrf_token()
    with SessionLocal() as db:
        kpi_metrics = _build_kpi_metrics(db)
    dashboard_timestamp = datetime.now(timezone.utc)
    response = templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "scan_types": SCAN_TYPES,
            "api_key_required": bool(settings.api_key or settings.api_key_hash),
            "error": exc.detail,
            "csrf_token": csrf_token,
            "data_classifications": DATA_CLASSIFICATIONS,
            "privacy_policy_version": settings.privacy_policy_version,
            "terms_version": settings.terms_of_service_version,
            "kpi_metrics": kpi_metrics,
            "dashboard_timestamp": dashboard_timestamp,
        },
        status_code=401,
    )
    response.set_cookie(
        settings.csrf_cookie_name,
        csrf_token,
        httponly=True,
        secure=settings.require_https,
        samesite="lax",
    )
    return response


@app.middleware("http")
async def enforce_https(request: Request, call_next):
    if settings.require_https:
        forwarded_proto = request.headers.get("x-forwarded-proto", "")
        is_https = request.url.scheme == "https" or forwarded_proto == "https"
        if not is_https:
            https_url = request.url.replace(scheme="https")
            return RedirectResponse(str(https_url), status_code=308)
    return await call_next(request)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    if settings.security_headers_enabled:
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"] = settings.csp_policy
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        if settings.require_https:
            response.headers["Strict-Transport-Security"] = f"max-age={settings.hsts_max_age}"
    return response


@app.middleware("http")
async def metrics_and_logging(request: Request, call_next):
    request_id = request.headers.get("x-request-id") or str(uuid4())
    structlog.contextvars.bind_contextvars(request_id=request_id)
    start_time = perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        duration = perf_counter() - start_time
        REQUEST_COUNT.labels(request.method, request.url.path, "500").inc()
        REQUEST_LATENCY.labels(request.method, request.url.path).observe(duration)
        http_logger.exception(
            "http_request_failed",
            method=request.method,
            path=request.url.path,
            duration_ms=round(duration * 1000, 2),
            client_ip=request.client.host if request.client else "unknown",
        )
        structlog.contextvars.clear_contextvars()
        raise
    duration = perf_counter() - start_time
    status_code = response.status_code
    REQUEST_COUNT.labels(request.method, request.url.path, str(status_code)).inc()
    REQUEST_LATENCY.labels(request.method, request.url.path).observe(duration)
    response.headers["X-Request-ID"] = request_id
    http_logger.info(
        "http_request",
        method=request.method,
        path=request.url.path,
        status_code=status_code,
        duration_ms=round(duration * 1000, 2),
        client_ip=request.client.host if request.client else "unknown",
    )
    structlog.contextvars.clear_contextvars()
    return response


class AuditLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        if settings.audit_logging_enabled:
            log_audit_event(
                "http_request",
                request=request,
                status_code=response.status_code,
            )
        return response


app.add_middleware(AuditLoggingMiddleware)


def _check_database() -> bool:
    try:
        with SessionLocal() as db:
            db.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


def _check_api_cache() -> bool:
    if not settings.api_cache_enabled:
        return True
    if not api_cache:
        return False
    try:
        api_cache.ping()
    except RedisError:
        return False
    return True


def _check_broker() -> bool:
    """Return True if the Celery broker (Redis) is reachable."""
    return check_broker_connection()


@app.get("/metrics")
def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/health")
def health_check() -> Dict[str, Any]:
    return {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "environment": settings.app_env,
    }


@app.get("/ready")
def readiness_check() -> JSONResponse:
    checks = {
        "database": _check_database(),
        "api_cache": _check_api_cache(),
        "broker": _check_broker(),
    }
    overall_ok = all(checks.values())
    payload = {
        "status": "ok" if overall_ok else "degraded",
        "checks": checks,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    status_code = 200 if overall_ok else 503
    return JSONResponse(content=payload, status_code=status_code)


def enforce_jwt(request: Request) -> None:
    if not settings.jwt_required:
        return
    token = request.headers.get("Authorization", "")
    if not token.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="JWT mancante")
    try:
        verify_jwt_token(token.split(" ", 1)[1].strip())
    except ValueError as exc:
        log_audit_event("jwt_invalid", request=request)
        raise HTTPException(status_code=401, detail="JWT non valido") from exc


def enforce_csrf(request: Request, token: str) -> None:
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return
    validate_csrf_request(request, token)


class ScanCreate(BaseModel):
    target: str = Field(..., max_length=255)
    scan_type: str = Field("full")
    priority: int = Field(5, ge=0, le=9)
    data_classification: str = Field("internal", max_length=40)
    accept_privacy: bool = Field(False)
    accept_terms: bool = Field(False)


class ScanStatus(BaseModel):
    id: int
    target: str
    scan_type: str
    status: str
    created_at: datetime
    completed_at: Optional[datetime]
    progress: int
    priority: int
    data_classification: str


class ScanDelete(BaseModel):
    reason: Optional[str] = Field(None, max_length=255)


class ConsentRequest(BaseModel):
    consent_type: str = Field(..., max_length=40)
    version: Optional[str] = Field(None, max_length=40)


class ConsentStatus(BaseModel):
    subject_id: str
    consent_type: str
    version: str
    accepted_at: datetime


class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: Dict[int, Set[WebSocket]] = {}

    async def connect(self, scan_id: int, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.setdefault(scan_id, set()).add(websocket)

    def disconnect(self, scan_id: int, websocket: WebSocket) -> None:
        if scan_id in self.active_connections:
            self.active_connections[scan_id].discard(websocket)
            if not self.active_connections[scan_id]:
                self.active_connections.pop(scan_id, None)

    async def broadcast(self, scan_id: int, payload: Dict[str, Any]) -> None:
        for connection in list(self.active_connections.get(scan_id, set())):
            try:
                await connection.send_json(payload)
            except Exception:
                self.disconnect(scan_id, connection)


manager = ConnectionManager()


def _load_json_list(value: Optional[str]) -> List[Any]:
    if not value:
        return []
    try:
        payload = json.loads(value)
    except json.JSONDecodeError:
        return []
    return payload if isinstance(payload, list) else []


def _build_scan_payload(scan: Scan) -> Dict[str, Any]:
    return {
        "id": scan.id,
        "status": scan.status,
        "progress": scan.progress,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "logs": _load_json_list(scan.logs_json)[-50:],
        "notifications": _load_json_list(scan.notifications_json)[-10:],
    }


def _active_scan_query(db: Session) -> Query:
    return db.query(Scan).filter(Scan.deleted_at.is_(None))


def _count_findings(records: List[Optional[str]]) -> int:
    total = 0
    for record in records:
        if not record:
            continue
        try:
            payload = json.loads(record)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, list):
            total += len(payload)
    return total


def _build_kpi_metrics(db: Session) -> Dict[str, Any]:
    base_query = _active_scan_query(db)
    total_scans = base_query.count()
    active_scans = base_query.filter(Scan.status.in_(["queued", "running"])).count()
    completed_scans = base_query.filter(Scan.status == "completed").count()
    failed_scans = base_query.filter(Scan.status == "report_failed").count()
    avg_duration_minutes = 0.0
    completed_rows = (
        base_query.filter(Scan.completed_at.isnot(None))
        .with_entities(Scan.created_at, Scan.completed_at)
        .all()
    )
    if completed_rows:
        total_seconds = sum(
            (completed_at - created_at).total_seconds()
            for created_at, completed_at in completed_rows
            if completed_at and created_at
        )
        avg_duration_minutes = round(total_seconds / max(len(completed_rows), 1) / 60, 1)
    findings_records = (
        base_query.filter(Scan.findings_json.isnot(None))
        .with_entities(Scan.findings_json)
        .all()
    )
    total_findings = _count_findings([record[0] for record in findings_records])
    return {
        "total_scans": total_scans,
        "active_scans": active_scans,
        "completed_scans": completed_scans,
        "failed_scans": failed_scans,
        "avg_duration_minutes": avg_duration_minutes,
        "total_findings": total_findings,
    }


@app.get("/", response_class=HTMLResponse)
def index(request: Request, db: Session = Depends(get_db)) -> Response:
    csrf_token = generate_csrf_token()
    kpi_metrics = _build_kpi_metrics(db)
    dashboard_timestamp = datetime.now(timezone.utc)
    response = templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "scan_types": SCAN_TYPES,
            "api_key_required": bool(settings.api_key or settings.api_key_hash),
            "csrf_token": csrf_token,
            "data_classifications": DATA_CLASSIFICATIONS,
            "privacy_policy_version": settings.privacy_policy_version,
            "terms_version": settings.terms_of_service_version,
            "kpi_metrics": kpi_metrics,
            "dashboard_timestamp": dashboard_timestamp,
        },
    )
    response.set_cookie(
        settings.csrf_cookie_name,
        csrf_token,
        httponly=True,
        secure=settings.require_https,
        samesite="lax",
    )
    return response


@app.get("/privacy-policy", response_class=HTMLResponse)
def privacy_policy(request: Request) -> Response:
    return templates.TemplateResponse(
        "privacy_policy.html",
        {
            "request": request,
            "privacy_policy_version": settings.privacy_policy_version,
        },
    )


@app.get("/terms-of-service", response_class=HTMLResponse)
def terms_of_service(request: Request) -> Response:
    return templates.TemplateResponse(
        "terms_of_service.html",
        {
            "request": request,
            "terms_version": settings.terms_of_service_version,
        },
    )


@app.post("/auth/token")
@limiter.limit(settings.rate_limit_auth)
def issue_token(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
) -> Dict[str, str]:
    if not settings.jwt_secret:
        raise HTTPException(status_code=503, detail="JWT non configurato")
    if not settings.jwt_demo_user or not settings.jwt_demo_password:
        raise HTTPException(status_code=503, detail="Credenziali JWT non configurate")
    if not (username == settings.jwt_demo_user and password == settings.jwt_demo_password):
        _record_audit(
            db,
            request,
            "auth_failed",
            subject_id=get_subject_id(request),
            username=username,
        )
        raise HTTPException(status_code=401, detail="Credenziali non valide")
    token = create_access_token(username)
    _record_audit(
        db,
        request,
        "auth_success",
        subject_id=get_subject_id(request),
        username=username,
    )
    return {"access_token": token, "token_type": "bearer"}


@app.post("/scans", response_class=HTMLResponse)
@limiter.limit(settings.rate_limit_create_scan)
def create_scan_form(
    request: Request,
    target: str = Form(...),
    scan_type: str = Form("full"),
    priority: int = Form(5),
    data_classification: str = Form("internal"),
    accept_privacy: Optional[str] = Form(None),
    accept_terms: Optional[str] = Form(None),
    csrf_token: str = Form(""),
    api_key: Optional[str] = Depends(enforce_api_key_form_dependency),
    db: Session = Depends(get_db),
) -> Response:
    try:
        enforce_csrf(request, csrf_token)
        scan_type = scan_type.lower().strip()
        data_classification = data_classification.lower().strip()
        if data_classification not in DATA_CLASSIFICATIONS:
            raise ScanValidationError("Classificazione dati non valida.")
        if scan_type == "nmap":
            validate_nmap_target(target)
        else:
            validate_target(target)
    except ValueError:
        csrf_token = generate_csrf_token()
        kpi_metrics = _build_kpi_metrics(db)
        dashboard_timestamp = datetime.now(timezone.utc)
        response = templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "scan_types": SCAN_TYPES,
                "api_key_required": bool(settings.api_key or settings.api_key_hash),
                "error": "Token CSRF non valido o scaduto.",
                "csrf_token": csrf_token,
                "data_classifications": DATA_CLASSIFICATIONS,
                "privacy_policy_version": settings.privacy_policy_version,
                "terms_version": settings.terms_of_service_version,
                "kpi_metrics": kpi_metrics,
                "dashboard_timestamp": dashboard_timestamp,
            },
            status_code=400,
        )
        response.set_cookie(
            settings.csrf_cookie_name,
            csrf_token,
            httponly=True,
            secure=settings.require_https,
            samesite="lax",
        )
        return response
    except ScanValidationError as exc:
        csrf_token = generate_csrf_token()
        kpi_metrics = _build_kpi_metrics(db)
        dashboard_timestamp = datetime.now(timezone.utc)
        response = templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "scan_types": SCAN_TYPES,
                "api_key_required": bool(settings.api_key or settings.api_key_hash),
                "error": str(exc),
                "csrf_token": csrf_token,
                "data_classifications": DATA_CLASSIFICATIONS,
                "privacy_policy_version": settings.privacy_policy_version,
                "terms_version": settings.terms_of_service_version,
                "kpi_metrics": kpi_metrics,
                "dashboard_timestamp": dashboard_timestamp,
            },
            status_code=400,
        )
        response.set_cookie(
            settings.csrf_cookie_name,
            csrf_token,
            httponly=True,
            secure=settings.require_https,
            samesite="lax",
        )
        return response

    subject_id = get_subject_id(request)
    privacy_ok = bool(accept_privacy)
    terms_ok = bool(accept_terms)
    if not has_required_consents(db, subject_id):
        if not (privacy_ok and terms_ok):
            csrf_token = generate_csrf_token()
            kpi_metrics = _build_kpi_metrics(db)
            dashboard_timestamp = datetime.now(timezone.utc)
            response = templates.TemplateResponse(
                "index.html",
                {
                    "request": request,
                    "scan_types": SCAN_TYPES,
                    "api_key_required": bool(settings.api_key or settings.api_key_hash),
                    "error": "Accetta privacy policy e termini di servizio per procedere.",
                    "csrf_token": csrf_token,
                    "data_classifications": DATA_CLASSIFICATIONS,
                    "privacy_policy_version": settings.privacy_policy_version,
                    "terms_version": settings.terms_of_service_version,
                    "kpi_metrics": kpi_metrics,
                    "dashboard_timestamp": dashboard_timestamp,
                },
                status_code=403,
            )
            response.set_cookie(
                settings.csrf_cookie_name,
                csrf_token,
                httponly=True,
                secure=settings.require_https,
                samesite="lax",
            )
            return response
        for consent_type in CONSENT_TYPES:
            version = (
                settings.privacy_policy_version
                if consent_type == "privacy_policy"
                else settings.terms_of_service_version
            )
            existing = (
                db.query(ConsentRecord)
                .filter(
                    ConsentRecord.subject_id == subject_id,
                    ConsentRecord.consent_type == consent_type,
                    ConsentRecord.version == version,
                )
                .first()
            )
            if not existing:
                record_consent(db, request, subject_id, consent_type, version)
                _record_audit(
                    db,
                    request,
                    "consent_recorded",
                    subject_id=subject_id,
                    consent_type=consent_type,
                    version=version,
                )

    scan = Scan(
        target=target,
        scan_type=scan_type,
        status="queued",
        created_at=datetime.now(timezone.utc),
        progress=0,
        priority=priority,
        data_subject_id=subject_id,
        data_classification=data_classification,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    try:
        task_result = orchestrate_scan.apply_async(
            args=[scan.id, scan.scan_type, scan.target],
            priority=priority,
        )
        scan.celery_task_id = task_result.id
        db.commit()
    except Exception as exc:
        http_logger.error("celery_dispatch_failed", scan_id=scan.id, error=str(exc))
        scan.status = "failed"
        db.commit()
        _record_audit(
            db,
            request,
            "scan_created",
            subject_id=subject_id,
            scan_id=scan.id,
            scan_type=scan.scan_type,
            data_classification=scan.data_classification,
        )
        _record_audit(
            db,
            request,
            "scan_dispatch_failed",
            subject_id=subject_id,
            scan_id=scan.id,
            error=str(exc),
        )
        csrf_token = generate_csrf_token()
        kpi_metrics = _build_kpi_metrics(db)
        dashboard_timestamp = datetime.now(timezone.utc)
        response = templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "scan_types": SCAN_TYPES,
                "api_key_required": bool(settings.api_key or settings.api_key_hash),
                "error": "Servizio di accodamento non disponibile. Riprova più tardi.",
                "csrf_token": csrf_token,
                "data_classifications": DATA_CLASSIFICATIONS,
                "privacy_policy_version": settings.privacy_policy_version,
                "terms_version": settings.terms_of_service_version,
                "kpi_metrics": kpi_metrics,
                "dashboard_timestamp": dashboard_timestamp,
            },
            status_code=503,
        )
        response.set_cookie(
            settings.csrf_cookie_name,
            csrf_token,
            httponly=True,
            secure=settings.require_https,
            samesite="lax",
        )
        return response

    redirect_url = f"/scans/{scan.id}"
    if api_key:
        redirect_url = f"{redirect_url}?api_key={api_key}"

    _record_audit(
        db,
        request,
        "scan_created",
        subject_id=subject_id,
        scan_id=scan.id,
        scan_type=scan.scan_type,
        data_classification=scan.data_classification,
    )

    return RedirectResponse(url=redirect_url, status_code=303)


@app.get("/scans", response_class=HTMLResponse)
def scans_list(request: Request, db: Session = Depends(get_db)) -> Response:
    scans = _active_scan_query(db).order_by(Scan.created_at.desc()).all()
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
def scan_detail(request: Request, scan_id: int, db: Session = Depends(get_db)) -> Response:
    scan = _active_scan_query(db).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan non trovata")

    findings = json.loads(scan.findings_json or "[]")
    logs = _load_json_list(scan.logs_json)
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
            "logs": logs,
            "download_url": download_url,
            "api_key": api_key,
        },
    )


@app.post("/api/v1/scans", response_model=ScanStatus)
@limiter.limit(settings.rate_limit_create_scan)
def create_scan(
    request: Request,
    payload: ScanCreate,
    db: Session = Depends(get_db),
    _: None = Depends(enforce_api_key),
    __: None = Depends(enforce_jwt),
) -> ScanStatus:
    try:
        scan_type = payload.scan_type.lower().strip()
        data_classification = payload.data_classification.lower().strip()
        if data_classification not in DATA_CLASSIFICATIONS:
            raise ScanValidationError("Classificazione dati non valida.")
        if scan_type == "nmap":
            validate_nmap_target(payload.target)
        else:
            validate_target(payload.target)
    except ScanValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    subject_id = get_subject_id(request)
    if not has_required_consents(db, subject_id):
        if not (payload.accept_privacy and payload.accept_terms):
            raise HTTPException(
                status_code=403,
                detail="Consenso privacy policy e termini richiesto.",
            )
        for consent_type in CONSENT_TYPES:
            version = (
                settings.privacy_policy_version
                if consent_type == "privacy_policy"
                else settings.terms_of_service_version
            )
            existing = (
                db.query(ConsentRecord)
                .filter(
                    ConsentRecord.subject_id == subject_id,
                    ConsentRecord.consent_type == consent_type,
                    ConsentRecord.version == version,
                )
                .first()
            )
            if not existing:
                record_consent(db, request, subject_id, consent_type, version)
                _record_audit(
                    db,
                    request,
                    "consent_recorded",
                    subject_id=subject_id,
                    consent_type=consent_type,
                    version=version,
                )

    scan = Scan(
        target=payload.target,
        scan_type=scan_type,
        status="queued",
        created_at=datetime.now(timezone.utc),
        progress=0,
        priority=payload.priority,
        data_subject_id=subject_id,
        data_classification=data_classification,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    try:
        task_result = orchestrate_scan.apply_async(
            args=[scan.id, scan.scan_type, scan.target],
            priority=payload.priority,
        )
        scan.celery_task_id = task_result.id
        db.commit()
    except Exception as exc:
        http_logger.error("celery_dispatch_failed", scan_id=scan.id, error=str(exc))
        scan.status = "failed"
        db.commit()
        _record_audit(
            db,
            request,
            "scan_dispatch_failed",
            subject_id=subject_id,
            scan_id=scan.id,
            error=str(exc),
        )
        raise HTTPException(
            status_code=503,
            detail=(
                "Servizio di accodamento non disponibile: impossibile connettersi al broker "
                f"({settings.celery_broker_url}). Verifica che Redis sia avviato."
            ),
        )

    _invalidate_cache_keys(_cache_key("scans:list"))

    _record_audit(
        db,
        request,
        "scan_created",
        subject_id=subject_id,
        scan_id=scan.id,
        scan_type=scan.scan_type,
        data_classification=scan.data_classification,
    )

    return ScanStatus(
        id=scan.id,
        target=scan.target,
        scan_type=scan.scan_type,
        status=scan.status,
        created_at=scan.created_at,
        completed_at=scan.completed_at,
        progress=scan.progress,
        priority=scan.priority,
        data_classification=scan.data_classification,
    )


@app.post("/api/v1/consents", response_model=ConsentStatus)
def record_consent_api(
    request: Request,
    payload: ConsentRequest,
    db: Session = Depends(get_db),
    _: None = Depends(enforce_api_key),
    __: None = Depends(enforce_jwt),
) -> ConsentStatus:
    consent_type = payload.consent_type.lower().strip()
    if consent_type not in CONSENT_TYPES:
        raise HTTPException(status_code=400, detail="Tipo consenso non valido.")
    version = payload.version
    if not version:
        version = (
            settings.privacy_policy_version
            if consent_type == "privacy_policy"
            else settings.terms_of_service_version
        )
    subject_id = get_subject_id(request)
    consent = record_consent(db, request, subject_id, consent_type, version)
    _record_audit(
        db,
        request,
        "consent_recorded",
        subject_id=subject_id,
        consent_type=consent_type,
        version=version,
    )
    return ConsentStatus(
        subject_id=consent.subject_id,
        consent_type=consent.consent_type,
        version=consent.version,
        accepted_at=consent.accepted_at,
    )


@app.get("/api/v1/gdpr/export")
def export_gdpr_data(
    request: Request,
    db: Session = Depends(get_db),
    _: None = Depends(enforce_api_key),
    __: None = Depends(enforce_jwt),
) -> Dict[str, Any]:
    subject_id = get_subject_id(request)
    scans = db.query(Scan).filter(Scan.data_subject_id == subject_id).all()
    payload = [anonymize_scan_for_export(scan) for scan in scans]
    _record_audit(
        db,
        request,
        "gdpr_export",
        subject_id=subject_id,
        exported_scans=len(payload),
    )
    return {"subject_id": subject_id, "exported_at": datetime.now(timezone.utc).isoformat(), "scans": payload}


@app.delete("/api/v1/gdpr/delete")
def delete_gdpr_data(
    request: Request,
    db: Session = Depends(get_db),
    _: None = Depends(enforce_api_key),
    __: None = Depends(enforce_jwt),
) -> Dict[str, Any]:
    subject_id = get_subject_id(request)
    scans = db.query(Scan).filter(Scan.data_subject_id == subject_id).all()
    deleted_reports = 0
    for scan in scans:
        if scan.report_path:
            try:
                Path(scan.report_path).unlink(missing_ok=True)
            except OSError:
                pass
            deleted_reports += 1
        db.delete(scan)
    db.query(ConsentRecord).filter(ConsentRecord.subject_id == subject_id).delete()
    db.commit()
    _record_audit(
        db,
        request,
        "gdpr_deletion",
        subject_id=subject_id,
        deleted_scans=len(scans),
        deleted_reports=deleted_reports,
    )
    return {
        "subject_id": subject_id,
        "deleted_scans": len(scans),
        "deleted_reports": deleted_reports,
        "deleted_at": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/scans/{scan_id}/report/download")
def download_report_ui(
    request: Request,
    scan_id: int,
    db: Session = Depends(get_db),
    _: None = Depends(enforce_api_key),
    __: None = Depends(enforce_jwt),
) -> FileResponse:
    scan = _active_scan_query(db).filter(Scan.id == scan_id).first()
    if not scan or not scan.report_path:
        raise HTTPException(status_code=404, detail="Report non disponibile")

    _record_audit(
        db,
        request,
        "report_downloaded",
        subject_id=scan.data_subject_id,
        scan_id=scan.id,
        data_classification=scan.data_classification,
    )

    return FileResponse(
        scan.report_path,
        media_type="application/pdf",
        filename=scan.report_path.split("/")[-1],
    )


@app.get("/api/v1/scans", response_model=List[ScanStatus])
@limiter.limit(settings.rate_limit_read)
def list_scans(
    request: Request,
    db: Session = Depends(get_db),
    _: None = Depends(enforce_api_key),
    __: None = Depends(enforce_jwt),
) -> List[ScanStatus]:
    cache_key = _cache_key("scans:list")
    cached_payload = _get_cached_json(cache_key)
    if cached_payload:
        return [ScanStatus.model_validate(item) for item in cached_payload]
    scans = _active_scan_query(db).order_by(Scan.created_at.desc()).all()
    response_payload = [
        ScanStatus(
            id=scan.id,
            target=scan.target,
            scan_type=scan.scan_type,
            status=scan.status,
            created_at=scan.created_at,
            completed_at=scan.completed_at,
            progress=scan.progress,
            priority=scan.priority,
            data_classification=scan.data_classification,
        )
        for scan in scans
    ]
    _set_cached_json(
        cache_key,
        [item.model_dump(mode="json") for item in response_payload],
    )
    return response_payload


@app.get("/api/v1/scans/{scan_id}/status", response_model=ScanStatus)
@limiter.limit(settings.rate_limit_read)
def scan_status(
    request: Request,
    scan_id: int,
    db: Session = Depends(get_db),
    _: None = Depends(enforce_api_key),
    __: None = Depends(enforce_jwt),
) -> ScanStatus:
    cache_key = _cache_key("scans", str(scan_id), "status")
    cached_payload = _get_cached_json(cache_key)
    if cached_payload:
        return ScanStatus.model_validate(cached_payload)
    scan = _active_scan_query(db).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan non trovata")

    response_payload = ScanStatus(
        id=scan.id,
        target=scan.target,
        scan_type=scan.scan_type,
        status=scan.status,
        created_at=scan.created_at,
        completed_at=scan.completed_at,
        progress=scan.progress,
        priority=scan.priority,
        data_classification=scan.data_classification,
    )
    _set_cached_json(cache_key, response_payload.model_dump(mode="json"))
    return response_payload


@app.get("/api/v1/scans/{scan_id}/report/download")
def download_report(
    request: Request,
    scan_id: int,
    db: Session = Depends(get_db),
    _: None = Depends(enforce_api_key),
    __: None = Depends(enforce_jwt),
) -> FileResponse:
    scan = _active_scan_query(db).filter(Scan.id == scan_id).first()
    if not scan or not scan.report_path:
        raise HTTPException(status_code=404, detail="Report non disponibile")

    _record_audit(
        db,
        request,
        "report_downloaded",
        subject_id=scan.data_subject_id,
        scan_id=scan.id,
        data_classification=scan.data_classification,
    )

    return FileResponse(
        scan.report_path,
        media_type="application/pdf",
        filename=scan.report_path.split("/")[-1],
    )


@app.get("/api/v1/scans/{scan_id}/task")
@limiter.limit(settings.rate_limit_read)
def scan_task_status(
    request: Request,
    scan_id: int,
    db: Session = Depends(get_db),
    _: None = Depends(enforce_api_key),
    __: None = Depends(enforce_jwt),
) -> Dict[str, Any]:
    scan = _active_scan_query(db).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan non trovata")
    status = None
    if scan.celery_task_id:
        result = celery_app.AsyncResult(scan.celery_task_id)
        status = result.status
    return {
        "scan_id": scan.id,
        "celery_task_id": scan.celery_task_id,
        "status": status,
    }


@app.post("/api/v1/scans/{scan_id}/cancel")
@limiter.limit(settings.rate_limit_create_scan)
def cancel_scan(
    request: Request,
    scan_id: int,
    db: Session = Depends(get_db),
    _: None = Depends(enforce_api_key),
    __: None = Depends(enforce_jwt),
) -> Dict[str, Any]:
    scan = _active_scan_query(db).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan non trovata")
    if scan.status in {"completed", "report_failed"}:
        raise HTTPException(status_code=400, detail="Scansione già completata.")
    scan.status = "canceled"
    scan.progress = 0
    db.commit()

    if scan.celery_task_id:
        celery_app.control.revoke(scan.celery_task_id, terminate=True)

    child_tasks = _load_json_list(scan.child_task_ids_json)
    for task_id in child_tasks:
        if isinstance(task_id, str):
            celery_app.control.revoke(task_id, terminate=True)

    _invalidate_cache_keys(
        _cache_key("scans:list"),
        _cache_key("scans", str(scan_id), "status"),
    )
    _record_audit(
        db,
        request,
        "scan_canceled",
        subject_id=scan.data_subject_id,
        scan_id=scan.id,
        data_classification=scan.data_classification,
    )
    return {"scan_id": scan.id, "status": scan.status}


@app.delete("/api/v1/scans/{scan_id}", response_model=ScanStatus)
@limiter.limit(settings.rate_limit_create_scan)
def soft_delete_scan(
    request: Request,
    scan_id: int,
    payload: ScanDelete = Body(default=ScanDelete()),
    db: Session = Depends(get_db),
    _: None = Depends(enforce_api_key),
    __: None = Depends(enforce_jwt),
) -> ScanStatus:
    scan = _active_scan_query(db).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan non trovata")
    scan.deleted_at = datetime.now(timezone.utc)
    scan.status = "deleted"
    db.commit()

    _record_audit(
        db,
        request,
        "scan_deleted",
        subject_id=scan.data_subject_id,
        scan_id=scan.id,
        scan_type=scan.scan_type,
        reason=payload.reason,
        data_classification=scan.data_classification,
    )

    _invalidate_cache_keys(
        _cache_key("scans:list"),
        _cache_key("scans", str(scan_id), "status"),
    )
    return ScanStatus(
        id=scan.id,
        target=scan.target,
        scan_type=scan.scan_type,
        status=scan.status,
        created_at=scan.created_at,
        completed_at=scan.completed_at,
        progress=scan.progress,
        priority=scan.priority,
        data_classification=scan.data_classification,
    )


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    scan_id_param = websocket.query_params.get("scan_id")
    api_key = websocket.query_params.get("api_key")
    if (settings.api_key or settings.api_key_hash) and not verify_api_key(api_key or ""):
        await websocket.close(code=1008)
        return
    if not scan_id_param or not scan_id_param.isdigit():
        await websocket.close(code=1003)
        return
    scan_id = int(scan_id_param)

    await manager.connect(scan_id, websocket)
    try:
        while True:
            await asyncio.sleep(settings.websocket_poll_seconds)
            with SessionLocal() as db:
                scan = _active_scan_query(db).filter(Scan.id == scan_id).first()
                if not scan:
                    await websocket.send_json({"error": "Scan non trovata"})
                    continue
                payload = _build_scan_payload(scan)
                await manager.broadcast(scan_id, payload)
    except (WebSocketDisconnect, Exception):
        manager.disconnect(scan_id, websocket)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app:app",
        host=settings.host,
        port=settings.port,
        reload=False,
        ssl_certfile=settings.tls_certfile or None,
        ssl_keyfile=settings.tls_keyfile or None,
        ssl_ca_certs=settings.tls_ca_certs or None,
    )
