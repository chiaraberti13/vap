#!/usr/bin/env python3
"""
Configurazione centrale per Vulnerability Assessment Platform.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path

from dotenv import load_dotenv


load_dotenv()


@dataclass(frozen=True)
class Settings:
    app_name: str = "Vulnerability Assessment Platform"
    app_env: str = os.getenv("VAP_ENV", "development")
    host: str = os.getenv("VAP_HOST", "0.0.0.0")
    port: int = int(os.getenv("VAP_PORT", "8000"))
    database_url: str = os.getenv("VAP_DATABASE_URL", "sqlite:///./vap.db")
    reports_dir: Path = Path(os.getenv("VAP_REPORTS_DIR", "reports"))
    scan_timeout_seconds: int = int(os.getenv("VAP_SCAN_TIMEOUT", "300"))
    enable_live_scans: bool = os.getenv("VAP_ENABLE_LIVE_SCANS", "false").lower() == "true"
    max_findings: int = int(os.getenv("VAP_MAX_FINDINGS", "200"))
    max_concurrent_scanners: int = int(os.getenv("VAP_MAX_CONCURRENT_SCANNERS", "5"))
    api_key: str = os.getenv("VAP_API_KEY", "")
    require_https: bool = os.getenv("VAP_REQUIRE_HTTPS", "false").lower() == "true"
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


settings = Settings()
settings.reports_dir.mkdir(parents=True, exist_ok=True)
