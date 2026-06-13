from __future__ import annotations

from pathlib import Path
from typing import Any

import toml
from pydantic import BaseModel, Field, model_validator

from agentshield.core.models import Ecosystem, ResponseMode, Severity

DEFAULT_CONFIG_PATH = Path.home() / ".config" / "agentshield" / "config.toml"
DEFAULT_DB_PATH = Path.home() / ".agentshield" / "agentshield.db"
DEFAULT_REPORT_DIR = Path.home() / ".agentshield" / "reports"


class SeverityPolicy(BaseModel):
    critical: ResponseMode = ResponseMode.BLOCK
    high: ResponseMode = ResponseMode.WARN_CONFIRM
    medium: ResponseMode = ResponseMode.ASYNC_REPORT
    low: ResponseMode = ResponseMode.IGNORE
    info: ResponseMode = ResponseMode.IGNORE

    def for_severity(self, severity: Severity) -> ResponseMode:
        return getattr(self, severity.value.lower(), ResponseMode.IGNORE)


class CacheConfig(BaseModel):
    ttl_hours: int = 24
    max_entries: int = 50_000
    db_path: Path = DEFAULT_DB_PATH

    @model_validator(mode="before")
    @classmethod
    def _expand_paths(cls, data: Any) -> Any:
        if isinstance(data, dict) and "db_path" in data:
            data["db_path"] = Path(str(data["db_path"])).expanduser()
        return data


class ReportingConfig(BaseModel):
    report_dir: Path = DEFAULT_REPORT_DIR
    auto_report_on_exit: bool = True

    @model_validator(mode="before")
    @classmethod
    def _expand_paths(cls, data: Any) -> Any:
        if isinstance(data, dict) and "report_dir" in data:
            data["report_dir"] = Path(str(data["report_dir"])).expanduser()
        return data


class Config(BaseModel):
    defaults: SeverityPolicy = Field(default_factory=SeverityPolicy)
    ecosystems: dict[str, SeverityPolicy] = Field(default_factory=dict)
    rules: dict[str, dict[str, Any]] = Field(default_factory=dict)
    allowlist: list[str] = Field(default_factory=list)
    denylist: list[str] = Field(default_factory=list)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)

    @model_validator(mode="before")
    @classmethod
    def _normalise_lists(cls, data: Any) -> Any:
        """TOML encodes allowlist/denylist as [allowlist] tables with a packages key.
        Flatten them to plain lists before Pydantic validation.
        """
        if not isinstance(data, dict):
            return data
        for field in ("allowlist", "denylist"):
            val = data.get(field)
            if isinstance(val, dict):
                data[field] = val.get("packages", [])
        return data

    @classmethod
    def load(cls, path: Path | None = None) -> Config:
        config_path = path or DEFAULT_CONFIG_PATH
        if not config_path.exists():
            return cls()
        raw = toml.loads(config_path.read_text())
        return cls.model_validate(raw)

    def response_mode_for(
        self,
        rule_id: str,
        severity: Severity,
        ecosystem: Ecosystem | None = None,
    ) -> ResponseMode:
        # Rule-level override has highest priority
        if rule_id in self.rules and "mode" in self.rules[rule_id]:
            return ResponseMode(self.rules[rule_id]["mode"])

        # Ecosystem-level override
        if ecosystem and ecosystem.value in self.ecosystems:
            return self.ecosystems[ecosystem.value].for_severity(severity)

        # Global default
        return self.defaults.for_severity(severity)
