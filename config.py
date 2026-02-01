#!/usr/bin/env python3
"""
Configurazione centrale per Vulnerability Assessment Platform.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os


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
    api_key: str = os.getenv("VAP_API_KEY", "")
    require_https: bool = os.getenv("VAP_REQUIRE_HTTPS", "false").lower() == "true"


settings = Settings()
settings.reports_dir.mkdir(parents=True, exist_ok=True)
