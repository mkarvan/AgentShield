"""Tests for posture report generation, renderers, and async log."""
from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

from agentshield.core.cache import ScanCache
from agentshield.core.config import CacheConfig
from agentshield.core.models import Finding, Severity
from agentshield.reports.models import AsyncLogEntry, PackageSummary, PostureReport, ToolInfo
from agentshield.reports.posture import (
    _classify_tool,
    run_posture_check,
)
from agentshield.reports.renderers import render_html, render_json, render_markdown
from agentshield.reports.scoring import risk_label, risk_score

# ------------------------------------------------------------------ helpers

def _make_finding(rule_id: str, severity: Severity, title: str = "Test finding") -> Finding:
    return Finding(rule_id=rule_id, title=title, severity=severity, source="test")


def _make_report(
    *,
    critical: int = 0,
    high: int = 0,
    medium: int = 0,
    low: int = 0,
    tools: list[ToolInfo] | None = None,
    async_entries: list[AsyncLogEntry] | None = None,
) -> PostureReport:
    findings_flat: list[Finding] = (
        [_make_finding(f"C{i}", Severity.CRITICAL) for i in range(critical)]
        + [_make_finding(f"H{i}", Severity.HIGH) for i in range(high)]
        + [_make_finding(f"M{i}", Severity.MEDIUM) for i in range(medium)]
        + [_make_finding(f"L{i}", Severity.LOW) for i in range(low)]
    )
    ps = PackageSummary(name="test-pkg", version="1.0", ecosystem="pypi", findings=findings_flat)
    score = risk_score(critical, high, medium, low, sum(1 for t in (tools or []) if t.risk_level == "high"))
    return PostureReport(
        generated_at=datetime(2026, 6, 13, 12, 0, 0, tzinfo=UTC),
        risk_score=score,
        risk_label=risk_label(score),
        packages_scanned=1,
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        low_count=low,
        info_count=0,
        package_summaries=[ps] if findings_flat else [],
        tools=tools or [],
        env_vars_detected=[],
        async_log_entries=async_entries or [],
        async_log_medium_plus_count=0,
    )


# ------------------------------------------------------------------ tool classification

class TestToolClassification:
    def test_bash_is_high(self) -> None:
        assert _classify_tool("bash") == "high"

    def test_write_file_is_high(self) -> None:
        assert _classify_tool("write_file") == "high"

    def test_run_code_is_high(self) -> None:
        assert _classify_tool("run_code") == "high"

    def test_web_search_is_medium(self) -> None:
        assert _classify_tool("web_search") == "medium"

    def test_read_file_is_medium(self) -> None:
        assert _classify_tool("read_file") == "medium"

    def test_unknown_tool_is_low(self) -> None:
        assert _classify_tool("list_models") == "low"

    def test_case_insensitive(self) -> None:
        assert _classify_tool("BASH") == "high"


# ------------------------------------------------------------------ render_json

class TestRenderJson:
    def test_valid_json(self) -> None:
        report = _make_report(critical=1, high=2)
        text = render_json(report)
        parsed = json.loads(text)
        assert parsed["risk_score"] == report.risk_score
        assert parsed["critical_count"] == 1
        assert parsed["high_count"] == 2

    def test_zero_findings(self) -> None:
        report = _make_report()
        text = render_json(report)
        parsed = json.loads(text)
        assert parsed["packages_scanned"] == 0 or parsed["critical_count"] == 0


# ------------------------------------------------------------------ render_markdown

class TestRenderMarkdown:
    def test_contains_heading(self) -> None:
        report = _make_report()
        md = render_markdown(report)
        assert "# AgentShield Posture Report" in md

    def test_contains_risk_score(self) -> None:
        report = _make_report(critical=3, high=5)
        md = render_markdown(report)
        assert str(report.risk_score) in md
        assert report.risk_label in md

    def test_critical_section_present(self) -> None:
        report = _make_report(critical=2)
        md = render_markdown(report)
        assert "## Critical Findings" in md

    def test_no_critical_section_when_clean(self) -> None:
        report = _make_report()
        md = render_markdown(report)
        assert "## Critical Findings" not in md

    def test_async_log_section(self) -> None:
        entry = AsyncLogEntry(
            id=1,
            package="some-pkg",
            version="1.0",
            ecosystem="pypi",
            findings=[_make_finding("T2.2", Severity.HIGH)],
            reason="LOG_ASYNC due to T2.2",
            logged_at=datetime(2026, 6, 13, 10, 0, tzinfo=UTC),
        )
        report = _make_report(async_entries=[entry])
        md = render_markdown(report)
        assert "Async Report Log" in md
        assert "some-pkg" in md

    def test_tool_section(self) -> None:
        tools = [
            ToolInfo(name="bash", risk_level="high"),
            ToolInfo(name="web_search", risk_level="medium"),
        ]
        report = _make_report(tools=tools)
        md = render_markdown(report)
        assert "bash" in md
        assert "web_search" in md


# ------------------------------------------------------------------ render_html

class TestRenderHtml:
    def test_produces_html(self) -> None:
        report = _make_report(critical=1)
        html = render_html(report)
        assert "<!DOCTYPE html>" in html
        assert "AgentShield Posture Report" in html

    def test_contains_score(self) -> None:
        report = _make_report(critical=3, high=5)
        html = render_html(report)
        assert str(report.risk_score) in html

    def test_contains_finding_title(self) -> None:
        report = _make_report(critical=1)
        html = render_html(report)
        assert "Test finding" in html


# ------------------------------------------------------------------ async report log (cache)

class TestAsyncReportLog:
    @pytest.fixture
    def db_path(self, tmp_path: Path) -> Path:
        return tmp_path / "test.db"

    @pytest.fixture
    def cache(self, db_path: Path) -> ScanCache:
        return ScanCache(CacheConfig(db_path=db_path))

    @pytest.mark.asyncio
    async def test_append_and_retrieve(self, cache: ScanCache) -> None:
        findings = [_make_finding("T2.1", Severity.CRITICAL)]
        findings_json = json.dumps([f.model_dump() for f in findings])
        await cache.append_async_log(
            package="evil-pkg",
            version="0.1.0",
            ecosystem="pypi",
            findings_json=findings_json,
            reason="LOG_ASYNC due to T2.1",
        )
        rows = await cache.get_async_log()
        assert len(rows) == 1
        assert rows[0]["package"] == "evil-pkg"
        assert rows[0]["version"] == "0.1.0"
        assert rows[0]["ecosystem"] == "pypi"

    @pytest.mark.asyncio
    async def test_since_ts_filter(self, cache: ScanCache) -> None:
        await cache.append_async_log("pkg-a", "1.0", "pypi", "[]", "reason")
        since_future = int(time.time()) + 60
        rows = await cache.get_async_log(since_ts=since_future)
        assert rows == []

    @pytest.mark.asyncio
    async def test_clear_async_log(self, cache: ScanCache) -> None:
        await cache.append_async_log("pkg-a", "1.0", "pypi", "[]", "reason")
        deleted = await cache.clear_async_log()
        assert deleted == 1
        rows = await cache.get_async_log()
        assert rows == []

    @pytest.mark.asyncio
    async def test_multiple_entries(self, cache: ScanCache) -> None:
        for i in range(3):
            await cache.append_async_log(f"pkg-{i}", "1.0", "pypi", "[]", "reason")
        rows = await cache.get_async_log()
        assert len(rows) == 3


# ------------------------------------------------------------------ run_posture_check

class TestRunPostureCheck:
    @pytest.mark.asyncio
    async def test_empty_environment(self, tmp_path: Path) -> None:
        """Posture check on a fresh DB with no packages scanned should return score 0."""
        db_path = tmp_path / "test.db"
        report = await run_posture_check(db_path=db_path, skip_package_scan=True)
        assert report.risk_score == 0
        assert report.risk_label == "LOW"
        assert report.packages_scanned == 0
        assert report.async_log_entries == []

    @pytest.mark.asyncio
    async def test_tool_classification(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        report = await run_posture_check(
            db_path=db_path,
            tool_names=["bash", "web_search", "list_models"],
            skip_package_scan=True,
        )
        assert len(report.tools) == 3
        high = [t for t in report.tools if t.risk_level == "high"]
        med = [t for t in report.tools if t.risk_level == "medium"]
        low = [t for t in report.tools if t.risk_level == "low"]
        assert len(high) == 1 and high[0].name == "bash"
        assert len(med) == 1 and med[0].name == "web_search"
        assert len(low) == 1 and low[0].name == "list_models"

    @pytest.mark.asyncio
    async def test_async_log_aggregation(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        cache = ScanCache(CacheConfig(db_path=db_path))
        findings = [_make_finding("T2.2", Severity.HIGH)]
        await cache.append_async_log(
            "risky-pkg", "1.0", "pypi",
            json.dumps([f.model_dump() for f in findings]),
            "LOG_ASYNC due to T2.2",
        )
        report = await run_posture_check(db_path=db_path, skip_package_scan=True)
        assert len(report.async_log_entries) == 1
        assert report.async_log_entries[0].package == "risky-pkg"
        assert report.async_log_medium_plus_count == 1
