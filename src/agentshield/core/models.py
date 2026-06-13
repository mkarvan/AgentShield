"""Core Pydantic models for AgentShield.

All data flowing through the scan pipeline is represented by these types.
They are the contract between the integration layers, core engine, and CLI.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


class Ecosystem(str, Enum):
    """Package ecosystem / registry."""

    PYPI = "pypi"
    NPM = "npm"
    CARGO = "cargo"


_SEVERITY_ORDER = ["NONE", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


class Severity(str, Enum):
    """Finding severity, ordered from NONE (lowest) to CRITICAL (highest)."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    NONE = "NONE"

    def _rank(self) -> int:
        return _SEVERITY_ORDER.index(self.value)

    # All six comparisons defined explicitly because str's implementations
    # take MRO priority over functools.total_ordering's generated methods.
    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self._rank() < other._rank()

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self._rank() <= other._rank()

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self._rank() > other._rank()

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self._rank() >= other._rank()

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.value == other.value
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.value)


class ResponseMode(str, Enum):
    """How AgentShield responds when a finding fires."""

    BLOCK = "block"
    WARN_CONFIRM = "warn_confirm"
    IGNORE = "ignore"
    ASYNC_REPORT = "async_report"


class DecisionAction(str, Enum):
    """The concrete action returned to the calling integration."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    NEEDS_CONFIRMATION = "NEEDS_CONFIRMATION"
    LOG_ASYNC = "LOG_ASYNC"


class Finding(BaseModel):
    """A single security finding from any analysis source.

    Fields:
        rule_id: Short identifier — a threat taxonomy ID (e.g. "T1.2"),
                 a CVE number, or an arbitrary DB-specific ID.
        title: One-line human-readable title.
        description: Full finding description (may be multi-paragraph).
        severity: CRITICAL / HIGH / MEDIUM / LOW / INFO.
        source: Which component produced this finding.
        references: List of URLs with additional context.
        cvss_score: Numeric CVSS base score (0.0–10.0), if available.
        remediation: Suggested fix or upgrade path.
        metadata: Arbitrary key/value bag for source-specific data.
    """

    rule_id: str = Field(..., min_length=1)
    title: str = Field(..., min_length=1)
    description: str = ""
    severity: Severity
    source: str = Field(..., min_length=1)
    references: list[str] = Field(default_factory=list)
    cvss_score: float | None = None
    remediation: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("cvss_score")
    @classmethod
    def _validate_cvss(cls, v: float | None) -> float | None:
        if v is not None and not (0.0 <= v <= 10.0):
            raise ValueError(f"cvss_score must be between 0.0 and 10.0, got {v}")
        return v

    @field_validator("references")
    @classmethod
    def _dedupe_references(cls, v: list[str]) -> list[str]:
        seen: set[str] = set()
        return [x for x in v if x and not (x in seen or seen.add(x))]  # type: ignore[func-returns-value]


class Decision(BaseModel):
    """The response engine's verdict for a scan.

    Fields:
        action: ALLOW / BLOCK / NEEDS_CONFIRMATION / LOG_ASYNC.
        reason: Human-readable explanation of why this action was chosen.
        findings: The subset of findings that drove this decision.
        override_token: Short-lived token allowing the user to bypass a BLOCK once.
    """

    action: DecisionAction
    reason: str
    findings: list[Finding] = Field(default_factory=list)
    override_token: str | None = None


class ScanRequest(BaseModel):
    """Input to a scan — describes which package to evaluate.

    Fields:
        package: Package name as it appears in the registry.
        version: Pinned version string (PEP 440 for PyPI). None = latest.
        ecosystem: Which registry the package belongs to.
        source: Identifies the calling integration (e.g. "hermes", "cli").
        context_hint: Short snippet explaining why the agent wants this package.
                      Used by the T4.1 prompt-injection heuristic.
        deep: If True, static analysis (semgrep/bandit) runs in addition to CVE lookups.
    """

    package: str
    version: str | None = None
    ecosystem: Ecosystem
    source: str | None = None
    context_hint: str | None = None
    deep: bool = False

    @field_validator("package")
    @classmethod
    def _validate_package(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("package name must not be empty")
        if " " in v:
            raise ValueError(f"package name must not contain spaces, got: {v!r}")
        return v

    @field_validator("version")
    @classmethod
    def _validate_version(cls, v: str | None) -> str | None:
        if v is not None:
            v = v.strip()
            if not v:
                return None
        return v


class ScanResult(BaseModel):
    """Aggregated output from a completed scan.

    Fields:
        request: The original ScanRequest that triggered this scan.
        findings: All findings from all analysis sources.
        max_severity: The highest severity across all findings; NONE if none found.
        decision: The response engine's verdict.
        scan_duration_ms: Wall-clock time for this scan in milliseconds.
        cache_hit: True if the result was served from the local cache.
        scanned_at: UTC timestamp when the scan completed.
    """

    request: ScanRequest
    findings: list[Finding] = Field(default_factory=list)
    max_severity: Severity = Severity.NONE
    decision: Decision
    scan_duration_ms: int = 0
    cache_hit: bool = False
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="after")
    def _check_max_severity_consistent(self) -> ScanResult:
        """max_severity must be >= every individual finding's severity."""
        if not self.findings:
            return self
        order = ["NONE", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        max_rank = order.index(self.max_severity.value)
        for f in self.findings:
            if order.index(f.severity.value) > max_rank:
                raise ValueError(
                    f"max_severity {self.max_severity} is lower than finding "
                    f"{f.rule_id} severity {f.severity}"
                )
        return self
