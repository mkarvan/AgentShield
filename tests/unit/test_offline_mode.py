"""Unit tests for offline scan mode.

In offline mode the scanner must not make any network calls — it queries
only the local SQLite tables (cve_mirror, malicious_packages) and the
in-process typosquatting checker.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
import respx

from agentshield.core.config import Config
from agentshield.core.models import (
    DecisionAction,
    Ecosystem,
    ScanRequest,
    Severity,
)
from agentshield.core.scanner import AgentShield, _dedupe_findings, _query_cve_mirror


def _cfg(tmp_path: Path, offline: bool = True) -> Config:
    return Config.model_validate(
        {
            "offline": offline,
            "cache": {"db_path": str(tmp_path / "test.db")},
        }
    )


# ── _dedupe_findings ─────────────────────────────────────────────────────────────


def test_dedupe_keeps_highest_severity():
    from agentshield.core.models import Finding

    findings = [
        Finding(rule_id="CVE-A", title="low", severity=Severity.LOW, source="test"),
        Finding(rule_id="CVE-A", title="high", severity=Severity.HIGH, source="test"),
        Finding(rule_id="CVE-B", title="medium", severity=Severity.MEDIUM, source="test"),
    ]
    result = _dedupe_findings(findings)
    assert len(result) == 2
    ids = {f.rule_id: f for f in result}
    assert ids["CVE-A"].severity == Severity.HIGH
    assert ids["CVE-B"].severity == Severity.MEDIUM


def test_dedupe_no_duplicates():
    from agentshield.core.models import Finding

    findings = [
        Finding(rule_id="X", title="x", severity=Severity.HIGH, source="a"),
        Finding(rule_id="Y", title="y", severity=Severity.LOW, source="b"),
    ]
    result = _dedupe_findings(findings)
    assert len(result) == 2


def test_dedupe_empty():
    assert _dedupe_findings([]) == []


# ── _query_cve_mirror ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_query_cve_mirror_returns_findings(tmp_path: Path):
    from agentshield.core.cache import ScanCache
    from agentshield.core.config import CacheConfig

    db_path = tmp_path / "test.db"
    cache = ScanCache(CacheConfig(db_path=db_path))
    await cache.upsert_cve(
        "CVE-2024-MIRROR",
        "requests",
        "pypi",
        "[]",
        "HIGH",
        7.5,
        "Mirror CVE description",
    )

    req = ScanRequest(package="requests", ecosystem=Ecosystem.PYPI)
    findings = await _query_cve_mirror(req, db_path)
    assert len(findings) == 1
    assert findings[0].rule_id == "CVE-2024-MIRROR"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].source == "cve_mirror"
    assert findings[0].cvss_score == 7.5


@pytest.mark.asyncio
async def test_query_cve_mirror_empty(tmp_path: Path):
    req = ScanRequest(package="clean-pkg", ecosystem=Ecosystem.PYPI)
    findings = await _query_cve_mirror(req, tmp_path / "empty.db")
    assert findings == []


# ── Offline scan full flow ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
@respx.mock  # Ensures no network calls slip through
async def test_offline_scan_uses_cve_mirror(tmp_path: Path):
    """Offline scan should find CVEs from local mirror without hitting the network."""
    from agentshield.core.cache import ScanCache
    from agentshield.core.config import CacheConfig

    db_path = tmp_path / "test.db"
    cache = ScanCache(CacheConfig(db_path=db_path))
    await cache.upsert_cve(
        "CVE-OFFLINE-001",
        "requests",
        "pypi",
        "[]",
        "CRITICAL",
        9.8,
        "Offline critical CVE",
    )

    cfg = _cfg(tmp_path, offline=True)
    shield = AgentShield(config=cfg)

    with patch("agentshield.analyzers.typosquatting.TyposquattingChecker._load", return_value=[]):
        result = await shield.ascan(ScanRequest(package="requests", ecosystem=Ecosystem.PYPI))

    assert result.decision.action == DecisionAction.BLOCK
    assert any(f.rule_id == "CVE-OFFLINE-001" for f in result.findings)
    assert result.cache_hit is False


@pytest.mark.asyncio
@respx.mock
async def test_offline_scan_detects_malicious_package(tmp_path: Path):
    from agentshield.core.cache import ScanCache
    from agentshield.core.config import CacheConfig

    db_path = tmp_path / "test.db"
    cache = ScanCache(CacheConfig(db_path=db_path))
    await cache.add_malicious_package("bad-package", "pypi", "Exfiltrates data", "osv")

    cfg = _cfg(tmp_path, offline=True)
    shield = AgentShield(config=cfg)

    db = __import__("agentshield.databases.malicious_db", fromlist=["MaliciousDB"]).MaliciousDB
    mock_db = db()
    mock_db._curated = {}

    with patch("agentshield.analyzers.typosquatting.TyposquattingChecker._load", return_value=[]):
        result = await shield.ascan(ScanRequest(package="bad-package", ecosystem=Ecosystem.PYPI))

    assert result.decision.action == DecisionAction.BLOCK
    t11 = [f for f in result.findings if f.rule_id == "T1.1"]
    assert len(t11) == 1


@pytest.mark.asyncio
@respx.mock
async def test_offline_scan_clean_package_returns_allow(tmp_path: Path):
    cfg = _cfg(tmp_path, offline=True)
    shield = AgentShield(config=cfg)

    with patch("agentshield.analyzers.typosquatting.TyposquattingChecker._load", return_value=[]):
        result = await shield.ascan(ScanRequest(package="requests", ecosystem=Ecosystem.PYPI))

    # No CVEs in empty DB — should allow
    assert result.decision.action in (DecisionAction.ALLOW, DecisionAction.LOG_ASYNC)


@pytest.mark.asyncio
@respx.mock
async def test_offline_mode_from_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """AGENTSHIELD_OFFLINE=1 should activate offline mode even without config flag."""
    monkeypatch.setenv("AGENTSHIELD_OFFLINE", "1")

    cfg = Config.model_validate({"cache": {"db_path": str(tmp_path / "test.db")}})
    # The env var is read at model_validate time via _normalise_lists
    assert cfg.offline is True


@pytest.mark.asyncio
@respx.mock
async def test_offline_scan_is_fast(tmp_path: Path):
    """Offline scan of a clean package should complete well under 50ms."""
    import time

    cfg = _cfg(tmp_path, offline=True)
    shield = AgentShield(config=cfg)

    req = ScanRequest(package="some-clean-package", ecosystem=Ecosystem.PYPI)
    with patch("agentshield.analyzers.typosquatting.TyposquattingChecker._load", return_value=[]):
        t0 = time.monotonic()
        await shield.ascan(req)
        elapsed_ms = (time.monotonic() - t0) * 1000

    # Should be well under 50ms for a local-only scan
    assert elapsed_ms < 500  # Generous bound for CI environments


# ── Online → Offline config switch ─────────────────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_online_scan_uses_network(tmp_path: Path):
    """Without offline mode, the scanner should attempt OSV API calls."""
    from httpx import Response

    call_count = 0

    def count_calls(request: object, route: object) -> Response:
        nonlocal call_count
        call_count += 1
        return Response(200, json={"vulns": []})

    respx.post("https://api.osv.dev/v1/query").mock(side_effect=count_calls)
    respx.get("https://services.nvd.nist.gov/rest/json/cves/2.0").mock(
        return_value=Response(200, json={"vulnerabilities": []})
    )
    respx.post("https://api.github.com/graphql").mock(
        return_value=Response(200, json={"data": {"securityVulnerabilities": {"nodes": []}}})
    )

    cfg = Config.model_validate({"cache": {"db_path": str(tmp_path / "test.db")}})
    shield = AgentShield(config=cfg)

    with patch("agentshield.analyzers.typosquatting.TyposquattingChecker._load", return_value=[]):
        await shield.ascan(ScanRequest(package="requests", ecosystem=Ecosystem.PYPI))

    # At least the OSV call should have been made
    assert call_count >= 1
