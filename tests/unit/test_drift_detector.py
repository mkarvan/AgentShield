"""Unit tests for drift_detector.py."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from agentshield.analyzers.drift_detector import DriftDetector
from agentshield.core.cache import ScanCache
from agentshield.core.config import CacheConfig
from agentshield.core.models import DecisionAction, Severity


@pytest.fixture
def tmp_db(tmp_path: Path) -> Path:
    return tmp_path / "test.db"


@pytest.fixture
def cache(tmp_db: Path) -> ScanCache:
    return ScanCache(CacheConfig(db_path=tmp_db))


# ── record ────────────────────────────────────────────────────────────────────


def test_record_stores_decision(tmp_db: Path, cache: ScanCache) -> None:
    dd = DriftDetector(tmp_db)
    asyncio.run(dd.record("requests", "pypi", DecisionAction.ALLOW))

    last = asyncio.run(cache.get_last_decision("requests", "pypi"))
    assert last == DecisionAction.ALLOW.value


def test_record_normalises_package_case(tmp_db: Path, cache: ScanCache) -> None:
    dd = DriftDetector(tmp_db)
    asyncio.run(dd.record("Requests", "pypi", DecisionAction.ALLOW))

    last = asyncio.run(cache.get_last_decision("requests", "pypi"))
    assert last == DecisionAction.ALLOW.value


def test_record_overwrites_old_with_newer(tmp_db: Path, cache: ScanCache) -> None:
    dd = DriftDetector(tmp_db)
    asyncio.run(dd.record("pkg", "pypi", DecisionAction.ALLOW))
    asyncio.run(dd.record("pkg", "pypi", DecisionAction.BLOCK))

    last = asyncio.run(cache.get_last_decision("pkg", "pypi"))
    assert last == DecisionAction.BLOCK.value


# ── check — no prior history ───────────────────────────────────────────────


def test_check_no_history_returns_empty(tmp_db: Path) -> None:
    dd = DriftDetector(tmp_db)
    findings = asyncio.run(dd.check("newpkg", "pypi", DecisionAction.BLOCK))
    assert findings == []


# ── check — ALLOW → BLOCK (HIGH severity) ─────────────────────────────────


def test_check_allow_to_block_returns_high_finding(tmp_db: Path) -> None:
    dd = DriftDetector(tmp_db)
    asyncio.run(dd.record("vuln-pkg", "pypi", DecisionAction.ALLOW))

    findings = asyncio.run(dd.check("vuln-pkg", "pypi", DecisionAction.BLOCK))

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "D1.1"
    assert f.severity == Severity.HIGH
    assert f.source == "drift_detector"
    assert "BLOCKED" in f.title


def test_check_allow_to_block_finding_has_remediation(tmp_db: Path) -> None:
    dd = DriftDetector(tmp_db)
    asyncio.run(dd.record("pkg", "npm", DecisionAction.ALLOW))

    findings = asyncio.run(dd.check("pkg", "npm", DecisionAction.BLOCK))
    assert findings[0].remediation is not None


# ── check — ALLOW → NEEDS_CONFIRMATION (MEDIUM severity) ──────────────────


def test_check_allow_to_needs_confirmation_returns_medium(tmp_db: Path) -> None:
    dd = DriftDetector(tmp_db)
    asyncio.run(dd.record("semi-safe", "pypi", DecisionAction.ALLOW))

    findings = asyncio.run(dd.check("semi-safe", "pypi", DecisionAction.NEEDS_CONFIRMATION))

    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].rule_id == "D1.1"


def test_check_allow_to_log_async_returns_medium(tmp_db: Path) -> None:
    dd = DriftDetector(tmp_db)
    asyncio.run(dd.record("logpkg", "pypi", DecisionAction.ALLOW))

    findings = asyncio.run(dd.check("logpkg", "pypi", DecisionAction.LOG_ASYNC))

    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


# ── check — no drift when decision stays the same ─────────────────────────


def test_check_allow_to_allow_no_finding(tmp_db: Path) -> None:
    dd = DriftDetector(tmp_db)
    asyncio.run(dd.record("clean", "pypi", DecisionAction.ALLOW))

    findings = asyncio.run(dd.check("clean", "pypi", DecisionAction.ALLOW))
    assert findings == []


def test_check_block_to_block_no_finding(tmp_db: Path) -> None:
    dd = DriftDetector(tmp_db)
    asyncio.run(dd.record("bad", "pypi", DecisionAction.BLOCK))

    findings = asyncio.run(dd.check("bad", "pypi", DecisionAction.BLOCK))
    assert findings == []


def test_check_block_to_allow_no_finding(tmp_db: Path) -> None:
    """If a package moves from BLOCK to ALLOW that is good news, not a drift event."""
    dd = DriftDetector(tmp_db)
    asyncio.run(dd.record("fixed", "pypi", DecisionAction.BLOCK))

    findings = asyncio.run(dd.check("fixed", "pypi", DecisionAction.ALLOW))
    assert findings == []


# ── ecosystem isolation ────────────────────────────────────────────────────


def test_check_different_ecosystems_isolated(tmp_db: Path) -> None:
    dd = DriftDetector(tmp_db)
    asyncio.run(dd.record("mypkg", "pypi", DecisionAction.ALLOW))
    # npm ecosystem has no history for "mypkg" → no drift
    findings = asyncio.run(dd.check("mypkg", "npm", DecisionAction.BLOCK))
    assert findings == []


# ── get_previously_allowed integration ────────────────────────────────────


def test_get_previously_allowed_returns_allow_packages(tmp_db: Path, cache: ScanCache) -> None:
    dd = DriftDetector(tmp_db)
    asyncio.run(dd.record("pkg-a", "pypi", DecisionAction.ALLOW))
    asyncio.run(dd.record("pkg-b", "pypi", DecisionAction.BLOCK))
    asyncio.run(dd.record("pkg-c", "npm", DecisionAction.ALLOW))

    pairs = asyncio.run(cache.get_previously_allowed())
    names = {p for p, _ in pairs}
    assert "pkg-a" in names
    assert "pkg-c" in names
    assert "pkg-b" not in names


def test_get_previously_allowed_respects_latest_decision(tmp_db: Path, cache: ScanCache) -> None:
    """If a package was ALLOW then BLOCK, it should not appear as previously allowed."""
    dd = DriftDetector(tmp_db)
    asyncio.run(dd.record("flip", "pypi", DecisionAction.ALLOW))
    asyncio.run(dd.record("flip", "pypi", DecisionAction.BLOCK))

    pairs = asyncio.run(cache.get_previously_allowed())
    names = {p for p, _ in pairs}
    assert "flip" not in names
