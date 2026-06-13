"""Integration tests for the Hermes Agent plugin.

These tests exercise the full plugin → scanner → response-engine pipeline
using mocked enrichment calls (no real network access).
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from agentshield.core.config import Config
from agentshield.core.models import (
    Decision,
    DecisionAction,
    Ecosystem,
    Finding,
    ScanRequest,
    ScanResult,
    Severity,
)
from agentshield.integrations.hermes._types import ToolCall, ToolResult
from agentshield.integrations.hermes.plugin import AgentShieldPlugin


def _make_plugin(tmp_path: Path, extra_config: dict | None = None) -> AgentShieldPlugin:
    base: dict = {"cache": {"db_path": str(tmp_path / "test.db")}}
    if extra_config:
        base.update(extra_config)
    config = Config.model_validate(base)
    return AgentShieldPlugin(config=config)


def _clean_result(request: ScanRequest) -> ScanResult:
    return ScanResult(
        request=request,
        findings=[],
        max_severity=Severity.NONE,
        decision=Decision(action=DecisionAction.ALLOW, reason="No issues found"),
    )


def _block_result(request: ScanRequest, finding: Finding) -> ScanResult:
    return ScanResult(
        request=request,
        findings=[finding],
        max_severity=Severity.CRITICAL,
        decision=Decision(
            action=DecisionAction.BLOCK,
            reason=f"BLOCK due to {finding.rule_id}",
            findings=[finding],
        ),
    )


def _warn_result(request: ScanRequest, finding: Finding) -> ScanResult:
    return ScanResult(
        request=request,
        findings=[finding],
        max_severity=Severity.HIGH,
        decision=Decision(
            action=DecisionAction.NEEDS_CONFIRMATION,
            reason=f"NEEDS_CONFIRMATION due to {finding.rule_id}",
            findings=[finding],
        ),
    )


# ── Pass-through (ALLOW) ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_clean_package_passes_through(tmp_path):
    plugin = _make_plugin(tmp_path)
    call = ToolCall(name="pip_install", args={"package": "requests"})
    req = ScanRequest(package="requests", ecosystem=Ecosystem.PYPI, source="hermes")

    with patch.object(plugin.shield, "ascan", new=AsyncMock(return_value=_clean_result(req))):
        result = await plugin.before_tool_call(call)

    # Must return the original ToolCall unmodified (ALLOW → pass through)
    assert result is call


@pytest.mark.asyncio
async def test_non_intercepted_tool_passes_through(tmp_path):
    plugin = _make_plugin(tmp_path)
    call = ToolCall(name="read_file", args={"path": "/etc/passwd"})

    # Shield should never be called for non-install tools
    with patch.object(plugin.shield, "ascan", new=AsyncMock()) as mock_scan:
        result = await plugin.before_tool_call(call)

    assert result is call
    mock_scan.assert_not_called()


# ── BLOCK decision ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_blocked_package_returns_tool_error(tmp_path):
    plugin = _make_plugin(tmp_path)
    call = ToolCall(name="pip_install", args={"package": "evil-pkg"})
    req = ScanRequest(package="evil-pkg", ecosystem=Ecosystem.PYPI, source="hermes")
    finding = Finding(
        rule_id="T1.1",
        title="Known malicious package",
        severity=Severity.CRITICAL,
        source="malicious_db",
    )

    with patch.object(plugin.shield, "ascan", new=AsyncMock(return_value=_block_result(req, finding))):
        result = await plugin.before_tool_call(call)

    assert isinstance(result, ToolResult)
    assert result.is_error
    assert "blocked" in (result.error or "").lower()
    assert "pip_install" in (result.error or "") or "evil-pkg" in (result.error or "")


@pytest.mark.asyncio
async def test_blocked_npm_package(tmp_path):
    plugin = _make_plugin(tmp_path)
    call = ToolCall(name="npm_install", args={"package": "evil-npm"})
    req = ScanRequest(package="evil-npm", ecosystem=Ecosystem.NPM, source="hermes")
    finding = Finding(
        rule_id="T1.1",
        title="Malicious npm package",
        severity=Severity.CRITICAL,
        source="malicious_db",
    )

    with patch.object(plugin.shield, "ascan", new=AsyncMock(return_value=_block_result(req, finding))):
        result = await plugin.before_tool_call(call)

    assert isinstance(result, ToolResult)
    assert result.is_error


@pytest.mark.asyncio
async def test_blocked_cargo_package(tmp_path):
    plugin = _make_plugin(tmp_path)
    call = ToolCall(name="cargo_add", args={"package": "evil-crate"})
    req = ScanRequest(package="evil-crate", ecosystem=Ecosystem.CARGO, source="hermes")
    finding = Finding(
        rule_id="T1.1",
        title="Malicious crate",
        severity=Severity.CRITICAL,
        source="malicious_db",
    )

    with patch.object(plugin.shield, "ascan", new=AsyncMock(return_value=_block_result(req, finding))):
        result = await plugin.before_tool_call(call)

    assert isinstance(result, ToolResult)
    assert result.is_error


# ── NEEDS_CONFIRMATION decision ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_warn_package_returns_confirmation_request(tmp_path):
    plugin = _make_plugin(tmp_path)
    call = ToolCall(name="pip_install", args={"package": "suspicious-pkg"})
    req = ScanRequest(package="suspicious-pkg", ecosystem=Ecosystem.PYPI, source="hermes")
    finding = Finding(
        rule_id="CVE-2024-9999",
        title="High severity CVE",
        severity=Severity.HIGH,
        source="osv",
    )

    with patch.object(plugin.shield, "ascan", new=AsyncMock(return_value=_warn_result(req, finding))):
        result = await plugin.before_tool_call(call)

    assert isinstance(result, ToolResult)
    assert result.requires_confirmation
    assert result.on_confirm is call
    assert "CVE-2024-9999" in result.confirmation_message or "issue" in result.confirmation_message


# ── ScanRequest construction ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_scan_request_uses_package_from_args(tmp_path):
    plugin = _make_plugin(tmp_path)
    call = ToolCall(
        name="pip_install",
        args={"package": "numpy", "version": "1.24.0"},
    )

    captured: list[ScanRequest] = []

    async def _mock_scan(r: ScanRequest) -> ScanResult:
        captured.append(r)
        return _clean_result(r)

    with patch.object(plugin.shield, "ascan", new=_mock_scan):
        await plugin.before_tool_call(call)

    assert captured[0].package == "numpy"
    assert captured[0].version == "1.24.0"
    assert captured[0].ecosystem == Ecosystem.PYPI
    assert captured[0].source == "hermes"


@pytest.mark.asyncio
async def test_context_hint_forwarded(tmp_path):
    plugin = _make_plugin(tmp_path)
    call = ToolCall(
        name="pip_install",
        args={"package": "flask", "reason": "Building a web API"},
    )

    captured: list[ScanRequest] = []

    async def _mock_scan(r: ScanRequest) -> ScanResult:
        captured.append(r)
        return _clean_result(r)

    with patch.object(plugin.shield, "ascan", new=_mock_scan):
        await plugin.before_tool_call(call)

    assert captured[0].context_hint == "Building a web API"


# ── Denylist short-circuit (real scanner, no network) ─────────────────────────


@pytest.mark.asyncio
async def test_denylist_blocks_via_plugin(tmp_path):
    plugin = _make_plugin(tmp_path, {"denylist": ["colouredlogs"]})
    call = ToolCall(name="pip_install", args={"package": "colouredlogs"})

    result = await plugin.before_tool_call(call)

    assert isinstance(result, ToolResult)
    assert result.is_error
    assert "colouredlogs" in (result.error or "").lower() or "blocked" in (result.error or "").lower()
