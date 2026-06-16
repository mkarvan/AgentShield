from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any, Literal

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
    db_path: Path = Field(default_factory=lambda: DEFAULT_DB_PATH)

    @model_validator(mode="before")
    @classmethod
    def _expand_paths(cls, data: Any) -> Any:
        if isinstance(data, dict) and "db_path" in data:
            data["db_path"] = Path(str(data["db_path"])).expanduser()
        return data


class ReportingConfig(BaseModel):
    report_dir: Path = Field(default_factory=lambda: DEFAULT_REPORT_DIR)
    auto_report_on_exit: bool = True

    @model_validator(mode="before")
    @classmethod
    def _expand_paths(cls, data: Any) -> Any:
        if isinstance(data, dict) and "report_dir" in data:
            data["report_dir"] = Path(str(data["report_dir"])).expanduser()
        return data


class APIConfig(BaseModel):
    """API credentials for external enrichment sources.

    Keys can also be supplied via environment variables:
      NVD_API_KEY      — NIST National Vulnerability Database API key
      GITHUB_TOKEN     — GitHub Personal Access Token (for Advisory Database)
    """

    nvd_api_key: str | None = None
    github_token: str | None = None

    @model_validator(mode="after")
    def _apply_env_vars(self) -> APIConfig:
        if self.nvd_api_key is None:
            env = os.environ.get("NVD_API_KEY")
            if env:
                self.nvd_api_key = env
        if self.github_token is None:
            env = os.environ.get("GITHUB_TOKEN")
            if env:
                self.github_token = env
        return self


_DEFAULT_DENIED_LICENSES: list[str] = [
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "SSPL-1.0",
    "EUPL-1.1",
    "OSL-3.0",
]


class LicensePolicy(BaseModel):
    """License compliance policy.

    Modes:
    - ``disabled``       — no license checking (default, opt-in)
    - ``denylist``       — flag packages whose license is in ``denied``
    - ``allowlist``      — flag packages whose license is NOT in ``allowed``
    - ``permissive-only``— flag any copyleft or non-permissive license
    """

    mode: Literal["disabled", "denylist", "allowlist", "permissive-only"] = "disabled"
    denied: list[str] = Field(default_factory=lambda: list(_DEFAULT_DENIED_LICENSES))
    allowed: list[str] = Field(default_factory=list)


class RateLimitsConfig(BaseModel):
    """Per-session rate limiting configuration.

    Configure in config.toml under [rate_limits]:

        [rate_limits]
        max_packages_per_hour = 20
        max_wheel_mb_per_session = 500
    """

    max_packages_per_hour: int = 20
    max_wheel_mb_per_session: int = 500


class TrustScoreConfig(BaseModel):
    """Trust-score (T5.1) behaviour.

    Configure in config.toml under [trust_score]:

        [trust_score]
        threshold = 40       # emit T5.1 below this score (default 50)
        min_signals = 2      # require at least this many concrete signals
    """

    threshold: int = 50
    min_signals: int = 2


class SysPkgConfig(BaseModel):
    """System package CVE scanning configuration (v0.9.0).

    Detection (``enabled``) is on by default and always emits the lightweight
    ``SP1.1`` warning for system package-manager invocations. CVE scanning
    (``cve_scan``) is *opt-in*: it makes live network calls to OSV and distro
    trackers, and historically blocked everyday installs (``apt-get install
    curl``, ``yum install httpd``) on the many low/medium CVEs that ship with
    distro packages. It stays off unless a user explicitly turns it on.

    When ``cve_scan`` is enabled:
    - ``severity_floor`` drops findings below the floor (default HIGH) so that
      noisy MEDIUM/LOW distro CVEs don't drown the user.
    - ``max_findings`` caps how many findings are surfaced (default 50); any
      overflow is summarised as "+N more".

    Configure in config.toml under [syspkg]:

        [syspkg]
        enabled = true        # detect + warn (SP1.1); default true
        cve_scan = false      # live CVE scan; opt-in, default false
        severity_floor = "HIGH"
        max_findings = 50

        [syspkg.severity_policy]
        critical = "block"
        high = "warn_confirm"
        medium = "async_report"
        low = "ignore"
        info = "ignore"
    """

    enabled: bool = True
    cve_scan: bool = False
    severity_floor: Severity = Severity.HIGH
    max_findings: int = 50
    severity_policy: SeverityPolicy = Field(default_factory=SeverityPolicy)


class Config(BaseModel):
    defaults: SeverityPolicy = Field(default_factory=SeverityPolicy)
    ecosystems: dict[str, SeverityPolicy] = Field(default_factory=dict)
    rules: dict[str, dict[str, Any]] = Field(default_factory=dict)
    allowlist: list[str] = Field(default_factory=list)
    denylist: list[str] = Field(default_factory=list)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    api: APIConfig = Field(default_factory=APIConfig)
    license_policy: LicensePolicy = Field(default_factory=LicensePolicy)
    rate_limits: RateLimitsConfig = Field(default_factory=RateLimitsConfig)
    trust_score: TrustScoreConfig = Field(default_factory=TrustScoreConfig)
    syspkg: SysPkgConfig = Field(default_factory=SysPkgConfig)
    offline: bool = False

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
        # Support AGENTSHIELD_OFFLINE env var overriding the config file
        if not data.get("offline") and os.environ.get("AGENTSHIELD_OFFLINE", "").lower() in (
            "1",
            "true",
            "yes",
        ):
            data["offline"] = True
        return data

    @classmethod
    def load(cls, path: Path | None = None) -> Config:
        config_path = path or DEFAULT_CONFIG_PATH
        if not config_path.exists():
            return cls()
        raw = tomllib.loads(config_path.read_text())
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
