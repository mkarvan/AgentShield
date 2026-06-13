"""Pydantic models for posture reports."""
from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field

from agentshield.core.models import Finding, Severity


class AsyncLogEntry(BaseModel):
    """A single LOG_ASYNC decision recorded during a past scan."""

    id: int
    package: str
    version: str | None
    ecosystem: str
    findings: list[Finding]
    reason: str
    logged_at: datetime


class ToolInfo(BaseModel):
    """A registered agent tool with a risk classification."""

    name: str
    risk_level: str  # "high" | "medium" | "low"


class PackageSummary(BaseModel):
    """Security summary for one installed package."""

    name: str
    version: str | None
    ecosystem: str
    findings: list[Finding] = Field(default_factory=list)
    max_severity: Severity = Severity.NONE


class PostureReport(BaseModel):
    """Full posture report — produced by the posture scanner."""

    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    risk_score: int
    risk_label: str
    packages_scanned: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    package_summaries: list[PackageSummary] = Field(default_factory=list)
    tools: list[ToolInfo] = Field(default_factory=list)
    env_vars_detected: list[str] = Field(default_factory=list)
    async_log_entries: list[AsyncLogEntry] = Field(default_factory=list)
    async_log_medium_plus_count: int = 0

    @property
    def high_risk_tools(self) -> list[ToolInfo]:
        return [t for t in self.tools if t.risk_level == "high"]

    @property
    def medium_risk_tools(self) -> list[ToolInfo]:
        return [t for t in self.tools if t.risk_level == "medium"]

    @property
    def critical_findings(self) -> list[tuple[str, Finding]]:
        """Returns (package_name, finding) pairs for CRITICAL findings."""
        out = []
        for ps in self.package_summaries:
            for f in ps.findings:
                if f.severity == Severity.CRITICAL:
                    out.append((ps.name, f))
        return out

    @property
    def high_findings(self) -> list[tuple[str, Finding]]:
        """Returns (package_name, finding) pairs for HIGH findings."""
        out = []
        for ps in self.package_summaries:
            for f in ps.findings:
                if f.severity == Severity.HIGH:
                    out.append((ps.name, f))
        return out
