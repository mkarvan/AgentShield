"""Integration tests for the OpenClaw skill.

These tests exercise the full skill → scanner → response-engine pipeline
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
from agentshield.integrations.openclaw._types import SkillContext, SkillResult
from agentshield.integrations.openclaw.skill import AgentShieldSkill


def _make_skill(tmp_path: Path, extra_config: dict | None = None) -> AgentShieldSkill:
    base: dict = {"cache": {"db_path": str(tmp_path / "test.db")}}
    if extra_config:
        base.update(extra_config)
    config = Config.model_validate(base)
    return AgentShieldSkill(config=config)


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


def _log_async_result(request: ScanRequest, finding: Finding) -> ScanResult:
    return ScanResult(
        request=request,
        findings=[finding],
        max_severity=Severity.MEDIUM,
        decision=Decision(
            action=DecisionAction.LOG_ASYNC,
            reason=f"LOG_ASYNC due to {finding.rule_id}",
            findings=[finding],
        ),
    )


# ── ALLOW path ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_clean_package_allowed(tmp_path):
    skill = _make_skill(tmp_path)
    ctx = SkillContext(params={"package": "requests", "ecosystem": "pypi"})
    req = ScanRequest(package="requests", ecosystem=Ecosystem.PYPI)

    with patch.object(skill.shield, "ascan", new=AsyncMock(return_value=_clean_result(req))):
        result = await skill.execute(ctx)

    assert isinstance(result, SkillResult)
    assert result.allowed is True
    assert result.decision == "ALLOW"


@pytest.mark.asyncio
async def test_log_async_is_treated_as_allowed(tmp_path):
    skill = _make_skill(tmp_path)
    ctx = SkillContext(params={"package": "semi-bad", "ecosystem": "pypi"})
    req = ScanRequest(package="semi-bad", ecosystem=Ecosystem.PYPI)
    finding = Finding(
        rule_id="CVE-MEDIUM",
        title="Medium CVE",
        severity=Severity.MEDIUM,
        source="osv",
    )

    with patch.object(
        skill.shield, "ascan", new=AsyncMock(return_value=_log_async_result(req, finding))
    ):
        result = await skill.execute(ctx)

    # LOG_ASYNC → allowed=True (install proceeds; finding logged for posture report)
    assert result.allowed is True
    assert result.decision == "LOG_ASYNC"


# ── BLOCK path ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_blocked_package_not_allowed(tmp_path):
    skill = _make_skill(tmp_path)
    ctx = SkillContext(params={"package": "evil-pkg", "ecosystem": "pypi"})
    req = ScanRequest(package="evil-pkg", ecosystem=Ecosystem.PYPI)
    finding = Finding(
        rule_id="T1.1",
        title="Known malicious package",
        severity=Severity.CRITICAL,
        source="malicious_db",
    )

    with patch.object(
        skill.shield, "ascan", new=AsyncMock(return_value=_block_result(req, finding))
    ):
        result = await skill.execute(ctx)

    assert result.allowed is False
    assert result.decision == "BLOCK"
    assert len(result.findings) == 1
    assert result.findings[0]["rule_id"] == "T1.1"


# ── Ecosystem mapping ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_npm_ecosystem_mapped_correctly(tmp_path):
    skill = _make_skill(tmp_path)
    ctx = SkillContext(params={"package": "lodash", "ecosystem": "npm"})

    captured: list[ScanRequest] = []

    async def _mock_scan(r: ScanRequest) -> ScanResult:
        captured.append(r)
        return _clean_result(r)

    with patch.object(skill.shield, "ascan", new=_mock_scan):
        await skill.execute(ctx)

    assert captured[0].ecosystem == Ecosystem.NPM


@pytest.mark.asyncio
async def test_unknown_ecosystem_defaults_to_pypi(tmp_path):
    skill = _make_skill(tmp_path)
    ctx = SkillContext(params={"package": "pkg", "ecosystem": "unknown"})

    captured: list[ScanRequest] = []

    async def _mock_scan(r: ScanRequest) -> ScanResult:
        captured.append(r)
        return _clean_result(r)

    with patch.object(skill.shield, "ascan", new=_mock_scan):
        await skill.execute(ctx)

    assert captured[0].ecosystem == Ecosystem.PYPI


# ── Edge cases ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_no_package_param_returns_allow(tmp_path):
    skill = _make_skill(tmp_path)
    ctx = SkillContext(params={"ecosystem": "pypi"})

    with patch.object(skill.shield, "ascan", new=AsyncMock()) as mock_scan:
        result = await skill.execute(ctx)

    mock_scan.assert_not_called()
    assert result.allowed is True
    assert result.decision == "ALLOW"


@pytest.mark.asyncio
async def test_context_hint_forwarded(tmp_path):
    skill = _make_skill(tmp_path)
    ctx = SkillContext(params={"package": "requests", "ecosystem": "pypi", "reason": "API calls"})

    captured: list[ScanRequest] = []

    async def _mock_scan(r: ScanRequest) -> ScanResult:
        captured.append(r)
        return _clean_result(r)

    with patch.object(skill.shield, "ascan", new=_mock_scan):
        await skill.execute(ctx)

    assert captured[0].context_hint == "API calls"
    assert captured[0].source == "openclaw"


@pytest.mark.asyncio
async def test_findings_serialized_in_result(tmp_path):
    skill = _make_skill(tmp_path)
    ctx = SkillContext(params={"package": "evil", "ecosystem": "pypi"})
    req = ScanRequest(package="evil", ecosystem=Ecosystem.PYPI)
    finding = Finding(
        rule_id="T1.2",
        title="Typosquatting",
        severity=Severity.HIGH,
        source="typosquatting",
    )

    block = ScanResult(
        request=req,
        findings=[finding],
        max_severity=Severity.HIGH,
        decision=Decision(
            action=DecisionAction.BLOCK,
            reason="BLOCK",
            findings=[finding],
        ),
    )

    with patch.object(skill.shield, "ascan", new=AsyncMock(return_value=block)):
        result = await skill.execute(ctx)

    assert len(result.findings) == 1
    assert result.findings[0]["rule_id"] == "T1.2"
    assert result.findings[0]["severity"] == "HIGH"


# ── Denylist short-circuit (real scanner, no network) ─────────────────────────


@pytest.mark.asyncio
async def test_denylist_blocks_via_skill(tmp_path):
    skill = _make_skill(tmp_path, {"denylist": ["colouredlogs"]})
    ctx = SkillContext(params={"package": "colouredlogs", "ecosystem": "pypi"})

    result = await skill.execute(ctx)

    assert result.allowed is False
    assert result.decision == "BLOCK"
