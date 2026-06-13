"""Posture scanner — enumerates the current environment and produces a PostureReport.

Design notes:
- Package enumeration uses importlib.metadata (stdlib, no network).
- CVE lookups use the local SQLite mirror (fast, offline-capable).  Users who
  want a full online rescan can run `agentshield scan` on individual packages.
- Async report log is read from the local DB (written by LOG_ASYNC decisions).
- Tool risk classification uses a predefined lookup; callers can pass a list of
  tool names to override.
- Sensitive env var detection uses pattern matching only — values are never read.
"""

from __future__ import annotations

import json
import os
import time
from datetime import UTC, datetime
from importlib import metadata as importlib_metadata
from pathlib import Path

from agentshield.core.cache import ScanCache
from agentshield.core.config import CacheConfig
from agentshield.core.models import Finding, Severity
from agentshield.reports.models import AsyncLogEntry, PackageSummary, PostureReport, ToolInfo
from agentshield.reports.scoring import risk_label, risk_score

_HIGH_RISK_TOOLS = frozenset(
    {
        "bash",
        "shell",
        "run_code",
        "execute_python",
        "execute_javascript",
        "write_file",
        "edit_file",
        "subprocess",
        "computer",
        "computer_use",
        "computer_batch",
    }
)

_MEDIUM_RISK_TOOLS = frozenset(
    {
        "web_search",
        "web_fetch",
        "browser",
        "read_file",
        "read",
        "list_directory",
        "file_search",
        "grep",
        "find",
    }
)

_SENSITIVE_ENV_PATTERNS = (
    "_KEY",
    "_TOKEN",
    "_SECRET",
    "_PASSWORD",
    "_CREDENTIAL",
    "_API_KEY",
    "OPENAI_",
    "ANTHROPIC_",
    "AWS_",
    "AZURE_",
    "GCP_",
    "GOOGLE_",
)


def _classify_tool(name: str) -> str:
    lower = name.lower()
    for h in _HIGH_RISK_TOOLS:
        if h in lower:
            return "high"
    for m in _MEDIUM_RISK_TOOLS:
        if m in lower:
            return "medium"
    return "low"


def _detect_sensitive_env_vars() -> list[str]:
    found = []
    for key in os.environ:
        upper = key.upper()
        if any(upper.startswith(p) or upper.endswith(p) for p in _SENSITIVE_ENV_PATTERNS):
            found.append(key)
    return sorted(found)


def _installed_packages() -> list[tuple[str, str]]:
    """Return (name, version) pairs for all packages visible to importlib.metadata."""
    pkgs = []
    for dist in importlib_metadata.distributions():
        name = dist.name
        version = dist.metadata["Version"] or ""
        if name:
            pkgs.append((name, version))
    return pkgs


async def _package_summary_from_local_db(
    name: str,
    version: str,
    db_path: Path,
) -> PackageSummary:
    """Build a PackageSummary for one package using only the local SQLite cache."""
    _SEV_MAP = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "INFO": Severity.INFO,
    }

    cache = ScanCache(CacheConfig(db_path=db_path))
    findings: list[Finding] = []

    # CVE mirror lookup
    rows = await cache.query_cve_mirror(name, "pypi")
    for row in rows:
        sev = _SEV_MAP.get(row.get("severity", ""), Severity.MEDIUM)
        findings.append(
            Finding(
                rule_id=row["id"],
                title=(row.get("description") or row["id"])[:200],
                description=row.get("description") or "",
                severity=sev,
                source="cve_mirror",
                cvss_score=row.get("cvss_score"),
                metadata={"offline": True},
            )
        )

    # Malicious DB lookup
    mal = await cache.is_malicious(name, "pypi")
    if mal:
        findings.append(
            Finding(
                rule_id="T1.1",
                title=f"{name} is listed as a known-malicious package",
                description=mal.get("reason") or "Flagged as malicious",
                severity=Severity.CRITICAL,
                source=mal.get("source") or "malicious_db",
            )
        )

    max_sev = max((f.severity for f in findings), default=Severity.NONE)
    return PackageSummary(
        name=name, version=version, ecosystem="pypi", findings=findings, max_severity=max_sev
    )


async def _load_async_log(db_path: Path, since_hours: int = 24) -> list[AsyncLogEntry]:
    """Read async report log entries from the last *since_hours* hours."""
    cache = ScanCache(CacheConfig(db_path=db_path))
    since_ts = int(time.time()) - since_hours * 3600
    rows = await cache.get_async_log(since_ts=since_ts)

    entries = []
    for row in rows:
        try:
            findings_raw = json.loads(row["findings_json"])
            findings = [Finding.model_validate(f) for f in findings_raw]
        except Exception:
            findings = []
        entries.append(
            AsyncLogEntry(
                id=row["id"],
                package=row["package"],
                version=row.get("version"),
                ecosystem=row["ecosystem"],
                findings=findings,
                reason=row["reason"],
                logged_at=datetime.fromtimestamp(row["logged_at"], tz=UTC),
            )
        )
    return entries


async def run_posture_check(
    db_path: Path,
    tool_names: list[str] | None = None,
    async_log_hours: int = 24,
    skip_package_scan: bool = False,
) -> PostureReport:
    """Run the posture check and return a PostureReport.

    Args:
        db_path: Path to the AgentShield SQLite database.
        tool_names: Optional list of agent tool names to classify.
        async_log_hours: How many hours of async report log to include.
        skip_package_scan: If True, skip installed-package CVE lookups (faster).
    """
    # Enumerate installed packages
    package_summaries: list[PackageSummary] = []
    if not skip_package_scan:
        packages = _installed_packages()
        for name, version in packages:
            summary = await _package_summary_from_local_db(name, version, db_path)
            package_summaries.append(summary)

    # Count findings by severity across all packages
    critical_count = sum(
        1 for ps in package_summaries for f in ps.findings if f.severity == Severity.CRITICAL
    )
    high_count = sum(
        1 for ps in package_summaries for f in ps.findings if f.severity == Severity.HIGH
    )
    medium_count = sum(
        1 for ps in package_summaries for f in ps.findings if f.severity == Severity.MEDIUM
    )
    low_count = sum(
        1 for ps in package_summaries for f in ps.findings if f.severity == Severity.LOW
    )
    info_count = sum(
        1 for ps in package_summaries for f in ps.findings if f.severity == Severity.INFO
    )

    # Classify tools
    tools: list[ToolInfo] = []
    if tool_names:
        for name in tool_names:
            tools.append(ToolInfo(name=name, risk_level=_classify_tool(name)))

    high_risk_tool_count = sum(1 for t in tools if t.risk_level == "high")

    # Score
    score = risk_score(critical_count, high_count, medium_count, low_count, high_risk_tool_count)
    label = risk_label(score)

    # Sensitive env vars
    env_vars = _detect_sensitive_env_vars()

    # Async report log
    async_log_entries = await _load_async_log(db_path, since_hours=async_log_hours)
    async_log_medium_plus = sum(
        1 for entry in async_log_entries for f in entry.findings if f.severity >= Severity.MEDIUM
    )

    return PostureReport(
        generated_at=datetime.now(UTC),
        risk_score=score,
        risk_label=label,
        packages_scanned=len(package_summaries),
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        info_count=info_count,
        package_summaries=package_summaries,
        tools=tools,
        env_vars_detected=env_vars,
        async_log_entries=async_log_entries,
        async_log_medium_plus_count=async_log_medium_plus,
    )
