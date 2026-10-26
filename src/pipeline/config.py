"""Pipeline configuration — loads from YAML and environment variables."""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator


class AnTAresConfig(BaseModel):
    """Cisco AnTAres API connection settings."""

    base_url: str = Field(default="https://api.cisco.com/antares/v1", description="AnTAres API base URL")
    api_key: str = Field(default="", description="AnTAres API key (set ANTARES_API_KEY env var)")
    timeout_seconds: int = Field(default=30, ge=5, le=120)
    max_retries: int = Field(default=3, ge=1, le=10)
    rate_limit_per_minute: int = Field(default=60, ge=10, le=300)

    @field_validator("api_key")
    @classmethod
    def resolve_api_key(cls, v: str) -> str:
        return v or os.environ.get("ANTARES_API_KEY", "")


class PipelineConfig(BaseModel):
    """Top-level pipeline configuration."""

    antares: AnTAresConfig = Field(default_factory=AnTAresConfig)
    scan_targets: list[str] = Field(default_factory=list, description="Git repo URLs or local paths to scan")
    output_dir: Path = Field(default=Path("./reports"), description="Where to write SARIF and JSON reports")
    governance: dict = Field(default_factory=dict)
    dashboard: dict = Field(default_factory=lambda: {"host": "127.0.0.1", "port": 8181})

    @classmethod
    def load(cls, path: str | Path = "config/pipeline.yaml") -> "PipelineConfig":
        p = Path(path)
        if not p.exists():
            return cls()
        with open(p) as f:
            raw = yaml.safe_load(f) or {}
        return cls(**raw)


DEFAULT_CONFIG = PipelineConfig()
