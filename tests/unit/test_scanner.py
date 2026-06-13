"""Unit tests for the AgentShield scanner / orchestration layer.

All network calls are mocked; this module does not require network access.
"""
from __future__ import annotations

import asyncio
import time
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
import respx
from httpx import Response

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
from agentshield.core.scanner import AgentShield, _max_severity

OSV_URL = "https://api.osv.dev/v1/query"


# ── _max_severity helper ──────────────────────────────────────────────────────

def _finding(severity: Severity) -> Finding:
    return Finding(rule_id="X", title="t", severity=severity, source="test")


def test_max_severity_empty():
    assert _max_severity([]) == Severity.NONE


def test_max_severity_single():
    assert _max_severity([_finding(Severity.HIGH)]) == Severity.HIGH


def test_max_severity_multiple():
    findings = [_finding(Severity.LOW), _finding(Severity.CRITICAL), _finding(Severity.MEDIUM)]
    assert _max_severity(findings) == Severity.CRITICAL


# ── Denylist / allowlist short-circuits ──────────────────────────────────────

def test_denylist_blocks_immediately(tmp_path):
    cfg = Config.model_validate({
        "denylist": ["evil-pkg"],
        "cache": {"db_path": str(tmp_path / "cache.db")},
    })
    shield = AgentShield(config=cfg)
    result = shield.scan(ScanRequest(package="evil-pkg", ecosystem=Ecosystem.PYPI))
    assert result.decision.action == DecisionAction.BLOCK
    assert "denylist" in result.decision.reason.lower()
    assert result.cache_hit is False


def test_allowlist_skips_scan_no_network(tmp_path):
    cfg = Config.model_validate({
        "allowlist": ["requests"],
        "cache": {"db_path": str(tmp_path / "cache.db")},
    })
    shield = AgentShield(config=cfg)
    # This must not make any network calls
    result = shield.scan(ScanRequest(package="requests", ecosystem=Ecosystem.PYPI))
    assert result.decision.action == DecisionAction.ALLOW
    assert result.cache_hit is True
    assert result.findings == []


def test_denylist_case_insensitive(tmp_path):
    cfg = Config.model_validate({
        "denylist": ["Evil-Pkg"],
        "cache": {"db_path": str(tmp_path / "cache.db")},
    })
    shield = AgentShield(config=cfg)
    result = shield.scan(ScanRequest(package="evil-pkg", ecosystem=Ecosystem.PYPI))
    assert result.decision.action == DecisionAction.BLOCK


# ── Cache hit path ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
@respx.mock
async def test_cache_hit_skips_network(tmp_path):
    cfg = Config.model_validate({"cache": {"db_path": str(tmp_path / "cache.db")}})
    shield = AgentShield(config=cfg)
    req = ScanRequest(package="requests", version="2.28.0", ecosystem=Ecosystem.PYPI)

    # Prime the cache with a clean result (no OSV call)
    clean_result = ScanResult(
        request=req,
        findings=[],
        max_severity=Severity.NONE,
        decision=Decision(action=DecisionAction.ALLOW, reason="cached"),
    )
    await shield.cache.set(req, clean_result)

    # Second scan must NOT hit the network (respx.mock would raise if it did)
    result = await shield.ascan(req)
    assert result.cache_hit is True
    assert result.decision.action == DecisionAction.ALLOW


# ── Full scan with mocked OSV ─────────────────────────────────────────────────

@pytest.mark.asyncio
@respx.mock
async def test_scan_no_findings_returns_allow(tmp_path):
    respx.post(OSV_URL).mock(return_value=Response(200, json={"vulns": []}))
    cfg = Config.model_validate({"cache": {"db_path": str(tmp_path / "cache.db")}})
    shield = AgentShield(config=cfg)

    # Suppress typosquatting by monkeypatching data
    with patch("agentshield.analyzers.typosquatting.TyposquattingChecker._load", return_value=[]):
        result = await shield.ascan(
            ScanRequest(package="clean-package", ecosystem=Ecosystem.PYPI)
        )

    assert result.decision.action in (DecisionAction.ALLOW, DecisionAction.LOG_ASYNC)
    assert result.cache_hit is False
    assert result.scan_duration_ms >= 0


@pytest.mark.asyncio
@respx.mock
async def test_scan_critical_vuln_returns_block(tmp_path):
    respx.post(OSV_URL).mock(return_value=Response(200, json={
        "vulns": [{
            "id": "CVE-2024-CRITICAL",
            "summary": "Critical RCE",
            "details": "Remote code execution",
            "severity": [],
            "database_specific": {"severity": "CRITICAL"},
            "references": [],
            "affected": [],
        }]
    }))
    cfg = Config.model_validate({"cache": {"db_path": str(tmp_path / "cache.db")}})
    shield = AgentShield(config=cfg)

    with patch("agentshield.analyzers.typosquatting.TyposquattingChecker._load", return_value=[]):
        result = await shield.ascan(
            ScanRequest(package="vuln-pkg", version="1.0.0", ecosystem=Ecosystem.PYPI)
        )

    assert result.decision.action == DecisionAction.BLOCK
    assert result.max_severity == Severity.CRITICAL
    assert any(f.rule_id == "CVE-2024-CRITICAL" for f in result.findings)


@pytest.mark.asyncio
@respx.mock
async def test_scan_result_is_cached_after_fresh_scan(tmp_path):
    respx.post(OSV_URL).mock(return_value=Response(200, json={"vulns": []}))
    cfg = Config.model_validate({"cache": {"db_path": str(tmp_path / "cache.db")}})
    shield = AgentShield(config=cfg)
    req = ScanRequest(package="some-pkg", version="1.2.3", ecosystem=Ecosystem.PYPI)

    with patch("agentshield.analyzers.typosquatting.TyposquattingChecker._load", return_value=[]):
        result1 = await shield.ascan(req)
        assert result1.cache_hit is False

        # Second scan from same shield should hit cache (no OSV needed)
        result2 = await shield.ascan(req)
        assert result2.cache_hit is True


@pytest.mark.asyncio
@respx.mock
async def test_osv_failure_does_not_crash_scan(tmp_path):
    """If the OSV client raises an exception, the scan should still complete."""
    respx.post(OSV_URL).mock(return_value=Response(500))
    cfg = Config.model_validate({"cache": {"db_path": str(tmp_path / "cache.db")}})
    shield = AgentShield(config=cfg)

    with patch("agentshield.analyzers.typosquatting.TyposquattingChecker._load", return_value=[]):
        result = await shield.ascan(
            ScanRequest(package="pkg", ecosystem=Ecosystem.PYPI)
        )

    # Scan should still return a result, even if OSV errored
    assert result is not None


@pytest.mark.asyncio
@respx.mock
async def test_scan_malicious_package_blocks(tmp_path):
    respx.post(OSV_URL).mock(return_value=Response(200, json={
        "vulns": [{
            "id": "MAL-2024-1234",
            "summary": "Malicious package",
            "details": "Known malicious",
            "severity": [],
            "database_specific": {"type": "MALICIOUS", "severity": "CRITICAL"},
            "references": [],
            "affected": [],
        }]
    }))
    cfg = Config.model_validate({
        "rules": {"T1.1": {"mode": "block"}},
        "cache": {"db_path": str(tmp_path / "cache.db")},
    })
    shield = AgentShield(config=cfg)

    with patch("agentshield.analyzers.typosquatting.TyposquattingChecker._load", return_value=[]):
        result = await shield.ascan(
            ScanRequest(package="colouredlogs", ecosystem=Ecosystem.PYPI)
        )

    assert result.decision.action == DecisionAction.BLOCK
    t1_findings = [f for f in result.findings if f.rule_id == "T1.1"]
    assert len(t1_findings) == 1


# ── Synchronous scan wrapper ──────────────────────────────────────────────────

@respx.mock
def test_sync_scan_works(tmp_path):
    respx.post(OSV_URL).mock(return_value=Response(200, json={"vulns": []}))
    cfg = Config.model_validate({
        "allowlist": ["requests"],
        "cache": {"db_path": str(tmp_path / "cache.db")},
    })
    shield = AgentShield(config=cfg)
    result = shield.scan(ScanRequest(package="requests", ecosystem=Ecosystem.PYPI))
    assert result.decision.action == DecisionAction.ALLOW
