"""Comprehensive tests for all four report renderers.

Covers: render_json, render_markdown, render_html, render_terminal.
Each renderer is tested with a normal report, an empty/clean report,
reports with tools, async log entries, env vars, CVSS scores, and
optional fields (description, remediation).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from io import StringIO

import pytest
import rich.console as _rich_console

from agentshield.core.models import Finding, Severity
from agentshield.reports.models import AsyncLogEntry, PackageSummary, PostureReport, ToolInfo
from agentshield.reports.renderers import (
    render_html,
    render_json,
    render_markdown,
    render_terminal,
)
from agentshield.reports.scoring import risk_label, risk_score

# ──────────────────────────────────────────── helpers ─────────────────────────

_FIXED_TS = datetime(2026, 6, 13, 12, 0, 0, tzinfo=UTC)


def _finding(
    rule_id: str,
    severity: Severity,
    *,
    title: str = "Test finding",
    description: str | None = None,
    remediation: str | None = None,
    cvss_score: float | None = None,
) -> Finding:
    kwargs: dict = dict(rule_id=rule_id, title=title, severity=severity, source="test")
    if description is not None:
        kwargs["description"] = description
    if remediation is not None:
        kwargs["remediation"] = remediation
    if cvss_score is not None:
        kwargs["cvss_score"] = cvss_score
    return Finding(**kwargs)


def _report(
    *,
    critical: int = 0,
    high: int = 0,
    medium: int = 0,
    low: int = 0,
    tools: list[ToolInfo] | None = None,
    async_entries: list[AsyncLogEntry] | None = None,
    env_vars: list[str] | None = None,
    rich_findings: list[Finding] | None = None,
) -> PostureReport:
    """Build a PostureReport.  rich_findings overrides the count-based ones."""
    if rich_findings is not None:
        all_findings = rich_findings
    else:
        all_findings = (
            [_finding(f"C{i}", Severity.CRITICAL) for i in range(critical)]
            + [_finding(f"H{i}", Severity.HIGH) for i in range(high)]
            + [_finding(f"M{i}", Severity.MEDIUM) for i in range(medium)]
            + [_finding(f"L{i}", Severity.LOW) for i in range(low)]
        )
        critical = sum(1 for f in all_findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in all_findings if f.severity == Severity.HIGH)
        medium = sum(1 for f in all_findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f in all_findings if f.severity == Severity.LOW)

    ps_list = (
        [PackageSummary(name="test-pkg", version="1.0", ecosystem="pypi", findings=all_findings)]
        if all_findings
        else []
    )
    score = risk_score(
        critical, high, medium, low, sum(1 for t in (tools or []) if t.risk_level == "high")
    )
    return PostureReport(
        generated_at=_FIXED_TS,
        risk_score=score,
        risk_label=risk_label(score),
        packages_scanned=len(ps_list),
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        low_count=low,
        info_count=0,
        package_summaries=ps_list,
        tools=tools or [],
        env_vars_detected=env_vars or [],
        async_log_entries=async_entries or [],
        async_log_medium_plus_count=sum(
            1
            for e in (async_entries or [])
            if any(f.severity >= Severity.MEDIUM for f in e.findings)
        ),
    )


def _async_entry(pkg: str, severity: Severity = Severity.HIGH) -> AsyncLogEntry:
    return AsyncLogEntry(
        id=1,
        package=pkg,
        version="0.1.0",
        ecosystem="pypi",
        findings=[_finding("T2.2", severity)],
        reason=f"LOG_ASYNC due to T2.2 ({severity.value})",
        logged_at=_FIXED_TS,
    )


def _capture_terminal(report: PostureReport) -> str:
    """Run render_terminal and return captured plain-text output."""
    buf = StringIO()
    real_console = _rich_console.Console(file=buf, no_color=True, width=120, force_terminal=False)
    original = _rich_console.Console

    class _FakeConsoleClass:
        def __new__(cls, **kwargs):  # noqa: ANN001
            return real_console

    _rich_console.Console = _FakeConsoleClass  # type: ignore[assignment]
    try:
        render_terminal(report)
    finally:
        _rich_console.Console = original  # type: ignore[assignment]

    return buf.getvalue()


# ──────────────────────────────────────────── render_json ─────────────────────


class TestRenderJson:
    def test_is_valid_json(self) -> None:
        text = render_json(_report(critical=1, high=2))
        parsed = json.loads(text)
        assert isinstance(parsed, dict)

    def test_counts_match(self) -> None:
        report = _report(critical=2, high=3, medium=1)
        parsed = json.loads(render_json(report))
        assert parsed["critical_count"] == 2
        assert parsed["high_count"] == 3
        assert parsed["medium_count"] == 1

    def test_risk_score_present(self) -> None:
        report = _report(critical=1)
        parsed = json.loads(render_json(report))
        assert parsed["risk_score"] == report.risk_score
        assert parsed["risk_label"] == report.risk_label

    def test_generated_at_present(self) -> None:
        parsed = json.loads(render_json(_report()))
        assert "generated_at" in parsed

    def test_empty_report_serialises(self) -> None:
        parsed = json.loads(render_json(_report()))
        assert parsed["critical_count"] == 0
        assert parsed["packages_scanned"] == 0

    def test_tools_serialised(self) -> None:
        tools = [ToolInfo(name="bash", risk_level="high")]
        parsed = json.loads(render_json(_report(tools=tools)))
        assert any(t["name"] == "bash" for t in parsed["tools"])

    def test_async_log_entries_serialised(self) -> None:
        entry = _async_entry("risky-pkg")
        parsed = json.loads(render_json(_report(async_entries=[entry])))
        assert len(parsed["async_log_entries"]) == 1
        assert parsed["async_log_entries"][0]["package"] == "risky-pkg"

    def test_env_vars_serialised(self) -> None:
        parsed = json.loads(render_json(_report(env_vars=["OPENAI_API_KEY"])))
        assert "OPENAI_API_KEY" in parsed["env_vars_detected"]

    def test_is_pretty_printed(self) -> None:
        text = render_json(_report())
        assert "\n" in text

    def test_package_summaries_contain_findings(self) -> None:
        report = _report(critical=1)
        parsed = json.loads(render_json(report))
        assert len(parsed["package_summaries"]) == 1
        assert len(parsed["package_summaries"][0]["findings"]) == 1


# ──────────────────────────────────────────── render_markdown ─────────────────


class TestRenderMarkdown:
    def test_heading_present(self) -> None:
        assert "# AgentShield Posture Report" in render_markdown(_report())

    def test_generated_timestamp(self) -> None:
        md = render_markdown(_report())
        assert "2026-06-13" in md

    def test_risk_score_in_table(self) -> None:
        report = _report(critical=2, high=1)
        md = render_markdown(report)
        assert str(report.risk_score) in md
        assert report.risk_label in md

    def test_counts_in_summary(self) -> None:
        md = render_markdown(_report(critical=3, high=2, medium=1, low=4))
        assert "3" in md
        assert "2" in md
        assert "1" in md
        assert "4" in md

    def test_critical_section_present_when_findings_exist(self) -> None:
        assert "## Critical Findings" in render_markdown(_report(critical=1))

    def test_critical_section_absent_when_clean(self) -> None:
        assert "## Critical Findings" not in render_markdown(_report())

    def test_high_section_present(self) -> None:
        assert "## High Findings" in render_markdown(_report(high=1))

    def test_high_section_absent_when_clean(self) -> None:
        assert "## High Findings" not in render_markdown(_report())

    def test_finding_title_appears(self) -> None:
        report = _report(
            rich_findings=[_finding("C0", Severity.CRITICAL, title="Malicious package detected")]
        )
        assert "Malicious package detected" in render_markdown(report)

    def test_cvss_score_in_finding(self) -> None:
        report = _report(rich_findings=[_finding("C0", Severity.CRITICAL, cvss_score=9.8)])
        md = render_markdown(report)
        assert "9.8" in md

    def test_no_cvss_field_omitted(self) -> None:
        report = _report(rich_findings=[_finding("C0", Severity.CRITICAL, cvss_score=None)])
        md = render_markdown(report)
        assert "CVSS" not in md

    def test_description_appears(self) -> None:
        report = _report(
            rich_findings=[_finding("C0", Severity.CRITICAL, description="Runs arbitrary code.")]
        )
        assert "Runs arbitrary code." in render_markdown(report)

    def test_remediation_appears(self) -> None:
        report = _report(
            rich_findings=[_finding("C0", Severity.CRITICAL, remediation="Upgrade to 2.0.")]
        )
        assert "Upgrade to 2.0." in render_markdown(report)

    def test_tool_section_lists_names(self) -> None:
        tools = [
            ToolInfo(name="bash", risk_level="high"),
            ToolInfo(name="web_search", risk_level="medium"),
            ToolInfo(name="list_files", risk_level="low"),
        ]
        md = render_markdown(_report(tools=tools))
        assert "bash" in md
        assert "web_search" in md
        assert "list_files" in md

    def test_no_tool_section_when_no_tools(self) -> None:
        assert "## Attack Surface" not in render_markdown(_report())

    def test_env_vars_section(self) -> None:
        md = render_markdown(_report(env_vars=["OPENAI_API_KEY", "ANTHROPIC_API_KEY"]))
        assert "OPENAI_API_KEY" in md
        assert "ANTHROPIC_API_KEY" in md

    def test_async_log_section_present(self) -> None:
        md = render_markdown(_report(async_entries=[_async_entry("risky-pkg")]))
        assert "Async Report Log" in md
        assert "risky-pkg" in md

    def test_async_log_table_row(self) -> None:
        entry = _async_entry("some-pkg", Severity.HIGH)
        md = render_markdown(_report(async_entries=[entry]))
        assert "some-pkg" in md
        assert "HIGH" in md

    def test_empty_async_log_no_section(self) -> None:
        assert "Async Report Log" not in render_markdown(_report())

    def test_footer_present(self) -> None:
        assert "AgentShield" in render_markdown(_report())

    def test_returns_string(self) -> None:
        assert isinstance(render_markdown(_report()), str)


# ──────────────────────────────────────────── render_html ─────────────────────


class TestRenderHtml:
    def test_returns_html_doctype(self) -> None:
        html = render_html(_report(critical=1))
        assert "<!DOCTYPE html>" in html

    def test_title_in_output(self) -> None:
        html = render_html(_report())
        assert "AgentShield Posture Report" in html

    def test_risk_score_in_output(self) -> None:
        report = _report(critical=2, high=3)
        assert str(report.risk_score) in render_html(report)

    def test_risk_label_in_output(self) -> None:
        report = _report(critical=2)
        assert report.risk_label in render_html(report)

    def test_finding_title_rendered(self) -> None:
        report = _report(rich_findings=[_finding("C0", Severity.CRITICAL, title="Evil dependency")])
        assert "Evil dependency" in render_html(report)

    def test_package_name_rendered(self) -> None:
        assert "test-pkg" in render_html(_report(critical=1))

    def test_empty_report_renders(self) -> None:
        html = render_html(_report())
        assert "<!DOCTYPE html>" in html

    def test_tool_names_rendered(self) -> None:
        tools = [ToolInfo(name="bash", risk_level="high")]
        assert "bash" in render_html(_report(tools=tools))

    def test_env_var_rendered(self) -> None:
        assert "OPENAI_API_KEY" in render_html(_report(env_vars=["OPENAI_API_KEY"]))

    def test_async_log_entry_rendered(self) -> None:
        entry = _async_entry("async-pkg")
        assert "async-pkg" in render_html(_report(async_entries=[entry]))

    def test_cvss_score_rendered(self) -> None:
        report = _report(rich_findings=[_finding("C0", Severity.CRITICAL, cvss_score=9.1)])
        assert "9.1" in render_html(report)

    def test_returns_string(self) -> None:
        assert isinstance(render_html(_report()), str)

    def test_jinja2_import_error_raises_runtime_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import sys

        monkeypatch.setitem(sys.modules, "jinja2", None)  # type: ignore[call-overload]
        with pytest.raises((ImportError, RuntimeError)):
            render_html(_report())


# ──────────────────────────────────────────── render_terminal ─────────────────


class TestRenderTerminal:
    def test_returns_none(self) -> None:
        assert render_terminal(_report()) is None

    def test_does_not_raise_on_empty_report(self) -> None:
        _capture_terminal(_report())  # must not raise

    def test_does_not_raise_with_findings(self) -> None:
        _capture_terminal(_report(critical=1, high=2, medium=3))

    def test_output_contains_agentshield(self) -> None:
        output = _capture_terminal(_report())
        assert "AgentShield" in output

    def test_output_contains_risk_score(self) -> None:
        report = _report(critical=1, high=2)
        output = _capture_terminal(report)
        assert str(report.risk_score) in output

    def test_output_contains_risk_label(self) -> None:
        report = _report(critical=1)
        output = _capture_terminal(report)
        assert report.risk_label in output

    def test_critical_rule_id_appears(self) -> None:
        report = _report(rich_findings=[_finding("CVE-2024-1234", Severity.CRITICAL)])
        output = _capture_terminal(report)
        assert "CVE-2024-1234" in output

    def test_high_rule_id_appears(self) -> None:
        report = _report(rich_findings=[_finding("T2.2", Severity.HIGH)])
        output = _capture_terminal(report)
        assert "T2.2" in output

    def test_package_name_in_output(self) -> None:
        output = _capture_terminal(_report(critical=1))
        assert "test-pkg" in output

    def test_cvss_score_in_critical_finding(self) -> None:
        report = _report(rich_findings=[_finding("C0", Severity.CRITICAL, cvss_score=9.8)])
        output = _capture_terminal(report)
        assert "9.8" in output

    def test_remediation_in_critical_finding(self) -> None:
        report = _report(
            rich_findings=[_finding("C0", Severity.CRITICAL, remediation="Upgrade to v2.")]
        )
        output = _capture_terminal(report)
        assert "Upgrade to v2." in output

    def test_tool_names_in_attack_surface(self) -> None:
        tools = [
            ToolInfo(name="bash", risk_level="high"),
            ToolInfo(name="web_search", risk_level="medium"),
        ]
        output = _capture_terminal(_report(tools=tools))
        assert "bash" in output
        assert "web_search" in output

    def test_no_tools_shows_placeholder(self) -> None:
        output = _capture_terminal(_report())
        assert "No tools registered" in output

    def test_env_vars_in_output(self) -> None:
        output = _capture_terminal(_report(env_vars=["OPENAI_API_KEY"]))
        assert "OPENAI_API_KEY" in output

    def test_async_log_entry_in_output(self) -> None:
        entry = _async_entry("risky-pkg")
        output = _capture_terminal(_report(async_entries=[entry]))
        assert "risky-pkg" in output

    def test_empty_async_log_shows_placeholder(self) -> None:
        output = _capture_terminal(_report())
        assert "No async-report log entries" in output

    def test_package_count_displayed(self) -> None:
        output = _capture_terminal(_report(critical=1))
        # packages_scanned = 1 is rendered
        assert "1" in output

    def test_multiple_findings_all_rendered(self) -> None:
        findings = [
            _finding("C0", Severity.CRITICAL, title="Critical one"),
            _finding("H0", Severity.HIGH, title="High one"),
        ]
        output = _capture_terminal(_report(rich_findings=findings))
        assert "Critical one" in output
        assert "High one" in output
