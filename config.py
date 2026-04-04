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


def _split_env_roles(value: str) -> List[str]:
    return [item.lower() for item in _split_env_list(value)]


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
    jwt_demo_user: str = os.getenv("VAP_JWT_DEMO_USER", "")
    jwt_demo_password: str = os.getenv("VAP_JWT_DEMO_PASSWORD", "")
    jwt_demo_role: str = os.getenv("VAP_JWT_DEMO_ROLE", "admin").lower()
    rbac_enabled: bool = os.getenv("VAP_RBAC_ENABLED", "true").lower() == "true"
    rbac_viewer_roles: List[str] = field(
        default_factory=lambda: _split_env_roles(os.getenv("VAP_RBAC_VIEWER_ROLES", "viewer,operator,admin"))
    )
    rbac_operator_roles: List[str] = field(
        default_factory=lambda: _split_env_roles(os.getenv("VAP_RBAC_OPERATOR_ROLES", "operator,admin"))
    )
    rbac_admin_roles: List[str] = field(
        default_factory=lambda: _split_env_roles(os.getenv("VAP_RBAC_ADMIN_ROLES", "admin"))
    )
    trusted_proxy_ip: str = os.getenv("VAP_TRUSTED_PROXY_IP", "")
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
    privacy_policy_version: str = os.getenv("VAP_PRIVACY_POLICY_VERSION", "2024-01")
    terms_of_service_version: str = os.getenv("VAP_TERMS_VERSION", "2024-01")
    consent_retention_days: int = int(os.getenv("VAP_CONSENT_RETENTION_DAYS", "365"))
    audit_retention_days: int = int(os.getenv("VAP_AUDIT_RETENTION_DAYS", "365"))
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
    sqlmap_path: str = os.getenv("VAP_SQLMAP_PATH", "sqlmap")
    sqlmap_level: int = int(os.getenv("VAP_SQLMAP_LEVEL", "2"))
    sqlmap_risk: int = int(os.getenv("VAP_SQLMAP_RISK", "1"))
    sqlmap_crawl_depth: int = int(os.getenv("VAP_SQLMAP_CRAWL_DEPTH", "1"))
    sqlmap_forms: bool = os.getenv("VAP_SQLMAP_FORMS", "true").lower() == "true"
    sqlmap_additional_args: str = os.getenv("VAP_SQLMAP_ADDITIONAL_ARGS", "")
    xsstrike_path: str = os.getenv("VAP_XSSTRIKE_PATH", "xsstrike")
    xsstrike_crawl: bool = os.getenv("VAP_XSSTRIKE_CRAWL", "true").lower() == "true"
    xsstrike_additional_args: str = os.getenv("VAP_XSSTRIKE_ADDITIONAL_ARGS", "")
    zap_api_base_url: str = os.getenv("VAP_ZAP_API_BASE_URL", "")
    zap_api_key: str = os.getenv("VAP_ZAP_API_KEY", "")
    zap_max_alerts: int = int(os.getenv("VAP_ZAP_MAX_ALERTS", "200"))
    zap_timeout_seconds: int = int(os.getenv("VAP_ZAP_TIMEOUT", "20"))
    burp_api_base_url: str = os.getenv("VAP_BURP_API_BASE_URL", "")
    burp_api_key: str = os.getenv("VAP_BURP_API_KEY", "")
    burp_api_scan_endpoint: str = os.getenv("VAP_BURP_API_SCAN_ENDPOINT", "/v0.1/scan")
    burp_api_issues_endpoint: str = os.getenv(
        "VAP_BURP_API_ISSUES_ENDPOINT", "/v0.1/scan/{scan_id}/issues"
    )
    burp_timeout_seconds: int = int(os.getenv("VAP_BURP_TIMEOUT", "20"))
    wapiti_path: str = os.getenv("VAP_WAPITI_PATH", "wapiti")
    commix_path: str = os.getenv("VAP_COMMIX_PATH", "commix")
    commix_additional_args: str = os.getenv("VAP_COMMIX_ADDITIONAL_ARGS", "")
    acunetix_api_base_url: str = os.getenv("VAP_ACUNETIX_API_BASE_URL", "")
    acunetix_api_key: str = os.getenv("VAP_ACUNETIX_API_KEY", "")
    acunetix_vulnerabilities_endpoint: str = os.getenv(
        "VAP_ACUNETIX_VULNERABILITIES_ENDPOINT", "/api/v1/vulnerabilities"
    )
    acunetix_timeout_seconds: int = int(os.getenv("VAP_ACUNETIX_TIMEOUT", "20"))
    nessus_api_base_url: str = os.getenv("VAP_NESSUS_API_BASE_URL", "")
    nessus_api_key: str = os.getenv("VAP_NESSUS_API_KEY", "")
    nessus_vulnerabilities_endpoint: str = os.getenv(
        "VAP_NESSUS_VULNERABILITIES_ENDPOINT", "/vulnerabilities"
    )
    nessus_timeout_seconds: int = int(os.getenv("VAP_NESSUS_TIMEOUT", "20"))
    wpscan_api_token: str = os.getenv("VAP_WPSCAN_API_TOKEN", "")
    wpscan_enumerate: str = os.getenv(
        "VAP_WPSCAN_ENUMERATE", "plugins,themes,users,timthumbs,config_backups,db_exports"
    )
    nvd_api_base_url: str = os.getenv("VAP_NVD_API_BASE_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
    nvd_api_key: str = os.getenv("VAP_NVD_API_KEY", "")
    nvd_timeout_seconds: int = int(os.getenv("VAP_NVD_TIMEOUT", "10"))
    nvd_max_cves: int = int(os.getenv("VAP_NVD_MAX_CVES", "20"))
    exploitdb_searchsploit_path: str = os.getenv("VAP_EXPLOITDB_SEARCHSPLOIT_PATH", "searchsploit")
    exploitdb_timeout_seconds: int = int(os.getenv("VAP_EXPLOITDB_TIMEOUT", "10"))
    exploitdb_max_cves: int = int(os.getenv("VAP_EXPLOITDB_MAX_CVES", "20"))
    false_positive_medium_threshold: float = float(os.getenv("VAP_FP_MEDIUM_THRESHOLD", "0.4"))
    false_positive_high_threshold: float = float(os.getenv("VAP_FP_HIGH_THRESHOLD", "0.7"))
    celery_broker_url: str = os.getenv("VAP_CELERY_BROKER_URL", "redis://localhost:6379/0")
    celery_result_backend: str = os.getenv("VAP_CELERY_RESULT_BACKEND", "redis://localhost:6379/1")
    celery_default_queue: str = os.getenv("VAP_CELERY_DEFAULT_QUEUE", "scans")
    celery_worker_concurrency: int = int(os.getenv("VAP_CELERY_WORKER_CONCURRENCY", "4"))
    celery_task_time_limit: int = int(os.getenv("VAP_CELERY_TASK_TIME_LIMIT", "900"))
    celery_task_soft_time_limit: int = int(os.getenv("VAP_CELERY_TASK_SOFT_TIME_LIMIT", "840"))
    celery_result_expires_seconds: int = int(os.getenv("VAP_CELERY_RESULT_EXPIRES", "3600"))
    api_cache_enabled: bool = os.getenv("VAP_API_CACHE_ENABLED", "true").lower() == "true"
    api_cache_redis_url: str = os.getenv("VAP_API_CACHE_REDIS_URL", "redis://localhost:6379/2")
    api_cache_ttl_seconds: int = int(os.getenv("VAP_API_CACHE_TTL", "30"))
    api_cache_prefix: str = os.getenv("VAP_API_CACHE_PREFIX", "vap:api")
    scan_retention_days: int = int(os.getenv("VAP_SCAN_RETENTION_DAYS", "30"))
    scan_archive_after_days: int = int(os.getenv("VAP_SCAN_ARCHIVE_AFTER_DAYS", "7"))
    scheduled_scans: str = os.getenv("VAP_SCHEDULED_SCANS", "[]")
    websocket_poll_seconds: float = float(os.getenv("VAP_WEBSOCKET_POLL_SECONDS", "2.0"))


settings = Settings()
settings.reports_dir.mkdir(parents=True, exist_ok=True)


def _warn_production_security() -> None:
    """Log warnings for insecure settings when running in production."""
    import logging
    _log = logging.getLogger("vap.config")

    if settings.app_env != "production":
        return

    warnings = []

    if not settings.csrf_secret:
        warnings.append(
            "VAP_CSRF_SECRET is not set: a random secret will be generated on each restart, "
            "invalidating all active sessions. Set a stable secret in production."
        )
    if not settings.jwt_secret:
        warnings.append(
            "VAP_JWT_SECRET is not set: JWT authentication will fail or use an empty key. "
            "Set a strong random secret (e.g. `openssl rand -hex 32`)."
        )
    if not settings.api_key and not settings.api_key_hash:
        warnings.append(
            "No API key configured (VAP_API_KEY / VAP_API_KEY_HASH): "
            "the API is accessible without authentication."
        )
    if not settings.require_https:
        warnings.append(
            "VAP_REQUIRE_HTTPS=false: traffic is not forced over HTTPS. "
            "Enable in production to protect credentials and scan data."
        )
    if settings.host == "0.0.0.0":
        warnings.append(
            "VAP_HOST=0.0.0.0: the server binds to all network interfaces. "
            "Restrict to a specific interface if external exposure is not intended."
        )

    for msg in warnings:
        _log.warning("[VAP PRODUCTION SECURITY] %s", msg)


_warn_production_security()
