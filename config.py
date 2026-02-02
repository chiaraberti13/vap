#!/usr/bin/env python3
"""
Configurazione centrale per Vulnerability Assessment Platform.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import secrets
from typing import List

from dotenv import load_dotenv


load_dotenv()


def _split_env_list(value: str) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    app_name: str = "Vulnerability Assessment Platform"
    app_env: str = os.getenv("VAP_ENV", "development")
    host: str = os.getenv("VAP_HOST", "0.0.0.0")
    port: int = int(os.getenv("VAP_PORT", "8000"))
    database_url: str = os.getenv("VAP_DATABASE_URL", "sqlite:///./vap.db")
    sqlcipher_key: str = os.getenv("VAP_SQLCIPHER_KEY", "")
    reports_dir: Path = Path(os.getenv("VAP_REPORTS_DIR", "reports"))
    scan_timeout_seconds: int = int(os.getenv("VAP_SCAN_TIMEOUT", "300"))
    enable_live_scans: bool = os.getenv("VAP_ENABLE_LIVE_SCANS", "false").lower() == "true"
    max_findings: int = int(os.getenv("VAP_MAX_FINDINGS", "200"))
    max_concurrent_scanners: int = int(os.getenv("VAP_MAX_CONCURRENT_SCANNERS", "5"))
    api_key: str = os.getenv("VAP_API_KEY", "")
    api_key_hash: str = os.getenv("VAP_API_KEY_HASH", "")
    require_https: bool = os.getenv("VAP_REQUIRE_HTTPS", "false").lower() == "true"
    csrf_secret: str = os.getenv("VAP_CSRF_SECRET", "") or secrets.token_urlsafe(32)
    csrf_cookie_name: str = os.getenv("VAP_CSRF_COOKIE", "vap_csrf")
    csrf_token_ttl_seconds: int = int(os.getenv("VAP_CSRF_TTL", "3600"))
    jwt_secret: str = os.getenv("VAP_JWT_SECRET", "")
    jwt_algorithm: str = os.getenv("VAP_JWT_ALGORITHM", "HS256")
    jwt_issuer: str = os.getenv("VAP_JWT_ISSUER", "vap")
    jwt_audience: str = os.getenv("VAP_JWT_AUDIENCE", "vap-users")
    jwt_exp_minutes: int = int(os.getenv("VAP_JWT_EXP_MINUTES", "60"))
    jwt_required: bool = os.getenv("VAP_JWT_REQUIRED", "false").lower() == "true"
    jwt_demo_user: str = os.getenv("VAP_JWT_DEMO_USER", "admin")
    jwt_demo_password: str = os.getenv("VAP_JWT_DEMO_PASSWORD", "change-me")
    cors_allowed_origins: List[str] = field(
        default_factory=lambda: _split_env_list(os.getenv("VAP_CORS_ALLOWED_ORIGINS", ""))
    )
    cors_allowed_methods: List[str] = field(
        default_factory=lambda: _split_env_list(
            os.getenv("VAP_CORS_ALLOWED_METHODS", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
        )
    )
    cors_allowed_headers: List[str] = field(
        default_factory=lambda: _split_env_list(
            os.getenv("VAP_CORS_ALLOWED_HEADERS", "Authorization,Content-Type,X-API-Key")
        )
    )
    cors_allow_credentials: bool = os.getenv("VAP_CORS_ALLOW_CREDENTIALS", "false").lower() == "true"
    rate_limit_default: str = os.getenv("VAP_RATE_LIMIT_DEFAULT", "120/minute")
    rate_limit_create_scan: str = os.getenv("VAP_RATE_LIMIT_CREATE_SCAN", "10/minute")
    rate_limit_auth: str = os.getenv("VAP_RATE_LIMIT_AUTH", "15/minute")
    rate_limit_read: str = os.getenv("VAP_RATE_LIMIT_READ", "120/minute")
    hsts_max_age: int = int(os.getenv("VAP_HSTS_MAX_AGE", "31536000"))
    csp_policy: str = os.getenv(
        "VAP_CSP_POLICY",
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; connect-src 'self'; frame-ancestors 'none'",
    )
    security_headers_enabled: bool = os.getenv("VAP_SECURITY_HEADERS", "true").lower() == "true"
    audit_logging_enabled: bool = os.getenv("VAP_AUDIT_LOGGING", "true").lower() == "true"
    tls_certfile: str = os.getenv("VAP_TLS_CERTFILE", "")
    tls_keyfile: str = os.getenv("VAP_TLS_KEYFILE", "")
    tls_ca_certs: str = os.getenv("VAP_TLS_CA_CERTS", "")
    nuclei_rate_limit: int = int(os.getenv("VAP_NUCLEI_RATE_LIMIT", "150"))
    nuclei_timeout_seconds: int = int(os.getenv("VAP_NUCLEI_TIMEOUT", "10"))
    nuclei_severities: str = os.getenv(
        "VAP_NUCLEI_SEVERITIES", "critical,high,medium,low,info"
    )
    nuclei_templates: str = os.getenv("VAP_NUCLEI_TEMPLATES", "")
    nuclei_update_templates: bool = (
        os.getenv("VAP_NUCLEI_UPDATE_TEMPLATES", "true").lower() == "true"
    )
    nuclei_additional_args: str = os.getenv("VAP_NUCLEI_ADDITIONAL_ARGS", "")
    nmap_profile: str = os.getenv("VAP_NMAP_PROFILE", "quick").lower()
    nmap_additional_args: str = os.getenv("VAP_NMAP_ADDITIONAL_ARGS", "")
    securitytrails_api_key: str = os.getenv("VAP_SECURITYTRAILS_API_KEY", "")
    virustotal_api_key: str = os.getenv("VAP_VIRUSTOTAL_API_KEY", "")
    shodan_api_key: str = os.getenv("VAP_SHODAN_API_KEY", "")
    subfinder_sources: str = os.getenv("VAP_SUBFINDER_SOURCES", "")
    subfinder_resolve_limit: int = int(os.getenv("VAP_SUBFINDER_RESOLVE_LIMIT", "200"))
    dirsearch_path: str = os.getenv("VAP_DIRSEARCH_PATH", "dirsearch")
    dirsearch_wordlist: str = os.getenv("VAP_DIRSEARCH_WORDLIST", "")
    dirsearch_extensions: str = os.getenv(
        "VAP_DIRSEARCH_EXTENSIONS", "php,asp,aspx,js,html,zip,tar.gz,bak,old,backup"
    )
    dirsearch_threads: int = int(os.getenv("VAP_DIRSEARCH_THREADS", "20"))
    celery_broker_url: str = os.getenv("VAP_CELERY_BROKER_URL", "redis://localhost:6379/0")
    celery_result_backend: str = os.getenv("VAP_CELERY_RESULT_BACKEND", "redis://localhost:6379/1")
    celery_default_queue: str = os.getenv("VAP_CELERY_DEFAULT_QUEUE", "scans")
    celery_worker_concurrency: int = int(os.getenv("VAP_CELERY_WORKER_CONCURRENCY", "4"))
    celery_task_time_limit: int = int(os.getenv("VAP_CELERY_TASK_TIME_LIMIT", "900"))
    celery_task_soft_time_limit: int = int(os.getenv("VAP_CELERY_TASK_SOFT_TIME_LIMIT", "840"))
    celery_result_expires_seconds: int = int(os.getenv("VAP_CELERY_RESULT_EXPIRES", "3600"))
    scan_retention_days: int = int(os.getenv("VAP_SCAN_RETENTION_DAYS", "30"))
    scan_archive_after_days: int = int(os.getenv("VAP_SCAN_ARCHIVE_AFTER_DAYS", "7"))
    scheduled_scans: str = os.getenv("VAP_SCHEDULED_SCANS", "[]")
    websocket_poll_seconds: float = float(os.getenv("VAP_WEBSOCKET_POLL_SECONDS", "2.0"))


settings = Settings()
settings.reports_dir.mkdir(parents=True, exist_ok=True)
