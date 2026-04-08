from __future__ import annotations

import hashlib
import json
from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


SeverityThreshold = Literal["low", "medium", "high", "critical"]
EvidenceMinimum = Literal["minimal", "standard", "strict"]
AuthMode = Literal["none", "basic", "bearer", "cookie"]


class ScopeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed_hosts: List[str] = Field(default_factory=list, max_length=50)
    in_scope_paths: List[str] = Field(default_factory=list, max_length=100)

    @field_validator("allowed_hosts", "in_scope_paths")
    @classmethod
    def _strip_values(cls, values: List[str]) -> List[str]:
        normalized = [value.strip() for value in values if value and value.strip()]
        if len(set(normalized)) != len(normalized):
            raise ValueError("Sono presenti valori duplicati nel perimetro di scansione.")
        return normalized


class RateAndTimeoutConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    requests_per_minute: int = Field(60, ge=1, le=600)
    max_concurrency: int = Field(4, ge=1, le=20)
    request_timeout_seconds: int = Field(15, ge=1, le=120)


class CrawlerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = Field(True)
    max_depth: int = Field(2, ge=0, le=10)
    follow_subdomains: bool = Field(False)


class AuthConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: AuthMode = Field("none")
    username: Optional[str] = Field(None, max_length=128)
    password: Optional[str] = Field(None, max_length=256)
    bearer_token: Optional[str] = Field(None, max_length=4096)
    cookie_header: Optional[str] = Field(None, max_length=4096)

    @model_validator(mode="after")
    def _validate_auth_payload(self) -> "AuthConfig":
        if self.mode == "none":
            return self
        if self.mode == "basic" and (not self.username or not self.password):
            raise ValueError("Per auth basic sono richiesti username e password.")
        if self.mode == "bearer" and not self.bearer_token:
            raise ValueError("Per auth bearer è richiesto bearer_token.")
        if self.mode == "cookie" and not self.cookie_header:
            raise ValueError("Per auth cookie è richiesto cookie_header.")
        return self


class ToolOverrideConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = Field(True)
    timeout_seconds: int = Field(20, ge=1, le=300)
    max_payloads: int = Field(30, ge=1, le=500)


class ScanConfigurationV1(BaseModel):
    """Schema versionato della configurazione scansione (A1)."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["scan-config/v1"] = Field("scan-config/v1")
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    runtime: RateAndTimeoutConfig = Field(default_factory=RateAndTimeoutConfig)
    crawler: CrawlerConfig = Field(default_factory=CrawlerConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    exclusions: List[str] = Field(default_factory=list, max_length=100)
    severity_threshold: SeverityThreshold = Field("low")
    minimum_evidence: EvidenceMinimum = Field("standard")
    tool_overrides: Dict[str, ToolOverrideConfig] = Field(default_factory=dict)

    @field_validator("exclusions")
    @classmethod
    def _validate_exclusions(cls, values: List[str]) -> List[str]:
        normalized = [value.strip() for value in values if value and value.strip()]
        if any(len(value) > 200 for value in normalized):
            raise ValueError("Ogni esclusione deve avere massimo 200 caratteri.")
        return normalized


def get_scan_config_schema_v1() -> Dict[str, object]:
    return ScanConfigurationV1.model_json_schema()


def checksum_scan_config_v1(config: ScanConfigurationV1) -> str:
    payload = json.dumps(config.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
