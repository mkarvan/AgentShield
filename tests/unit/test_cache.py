"""Unit tests for the SQLite scan cache."""
import time

import pytest

from agentshield.core.cache import _TTL_BY_SEVERITY, ScanCache
from agentshield.core.config import CacheConfig
from agentshield.core.models import (
    Decision,
    DecisionAction,
    Ecosystem,
    ScanRequest,
    ScanResult,
    Severity,
)


def _make_cache(tmp_path) -> ScanCache:
    cfg = CacheConfig(db_path=tmp_path / "test_cache.db")
    return ScanCache(cfg)


def _make_request(package: str = "requests", version: str = "2.28.0") -> ScanRequest:
    return ScanRequest(package=package, version=version, ecosystem=Ecosystem.PYPI)


def _make_result(request: ScanRequest, severity: Severity = Severity.NONE) -> ScanResult:
    return ScanResult(
        request=request,
        findings=[],
        max_severity=severity,
        decision=Decision(action=DecisionAction.ALLOW, reason="clean"),
        scan_duration_ms=100,
    )


# ── Basic get/set ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_cache_miss_returns_none(tmp_path):
    cache = _make_cache(tmp_path)
    req = _make_request()
    result = await cache.get(req)
    assert result is None


@pytest.mark.asyncio
async def test_cache_set_then_get(tmp_path):
    cache = _make_cache(tmp_path)
    req = _make_request()
    result = _make_result(req)
    await cache.set(req, result)

    fetched = await cache.get(req)
    assert fetched is not None
    assert fetched.cache_hit is True
    assert fetched.request.package == "requests"


@pytest.mark.asyncio
async def test_cache_key_includes_version(tmp_path):
    cache = _make_cache(tmp_path)
    req1 = _make_request(version="2.28.0")
    req2 = _make_request(version="2.29.0")

    await cache.set(req1, _make_result(req1))
    # Different version should be a miss
    assert await cache.get(req2) is None


@pytest.mark.asyncio
async def test_cache_key_includes_ecosystem(tmp_path):
    cache = _make_cache(tmp_path)
    req_pypi = ScanRequest(package="requests", version="2.28.0", ecosystem=Ecosystem.PYPI)
    req_npm = ScanRequest(package="requests", version="2.28.0", ecosystem=Ecosystem.NPM)

    await cache.set(req_pypi, _make_result(req_pypi))
    assert await cache.get(req_npm) is None


# ── TTL behaviour ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_expired_entry_returns_none(tmp_path, monkeypatch):
    cache = _make_cache(tmp_path)
    req = _make_request()
    result = _make_result(req)

    # Store entry
    await cache.set(req, result)

    # Wind the clock forward past expiry
    future_time = int(time.time()) + _TTL_BY_SEVERITY["NONE"] + 1
    monkeypatch.setattr("agentshield.core.cache.time.time", lambda: future_time)

    fetched = await cache.get(req)
    assert fetched is None


@pytest.mark.asyncio
async def test_ttl_varies_by_severity(tmp_path):
    """Higher severities get shorter TTLs."""
    assert _TTL_BY_SEVERITY["NONE"] > _TTL_BY_SEVERITY["MEDIUM"]
    assert _TTL_BY_SEVERITY["MEDIUM"] > _TTL_BY_SEVERITY["CRITICAL"]


# ── Maintenance operations ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_clear_removes_all_entries(tmp_path):
    cache = _make_cache(tmp_path)
    for i in range(3):
        req = _make_request(package=f"pkg{i}")
        await cache.set(req, _make_result(req))

    deleted = await cache.clear()
    assert deleted == 3

    stats = await cache.stats()
    assert stats["total"] == 0


@pytest.mark.asyncio
async def test_clear_expired_only_removes_stale(tmp_path, monkeypatch):
    cache = _make_cache(tmp_path)

    # Add a "CRITICAL" entry (short TTL) and a "NONE" entry (long TTL)
    req_crit = _make_request(package="critical-pkg")
    req_clean = _make_request(package="clean-pkg")
    await cache.set(req_crit, _make_result(req_crit, Severity.CRITICAL))
    await cache.set(req_clean, _make_result(req_clean, Severity.NONE))

    # Wind clock forward by just past CRITICAL TTL but not NONE TTL
    future_time = int(time.time()) + _TTL_BY_SEVERITY["CRITICAL"] + 1
    monkeypatch.setattr("agentshield.core.cache.time.time", lambda: future_time)

    deleted = await cache.clear_expired()
    assert deleted == 1

    stats = await cache.stats()
    assert stats["live"] == 1
    assert stats["expired"] == 0


@pytest.mark.asyncio
async def test_stats_empty_cache(tmp_path):
    cache = _make_cache(tmp_path)
    stats = await cache.stats()
    assert stats == {"total": 0, "live": 0, "expired": 0}


@pytest.mark.asyncio
async def test_stats_mixed(tmp_path, monkeypatch):
    cache = _make_cache(tmp_path)

    req1 = _make_request(package="pkg1")
    req2 = _make_request(package="pkg2")
    await cache.set(req1, _make_result(req1, Severity.CRITICAL))
    await cache.set(req2, _make_result(req2, Severity.NONE))

    # Expire the CRITICAL entry
    future_time = int(time.time()) + _TTL_BY_SEVERITY["CRITICAL"] + 1
    monkeypatch.setattr("agentshield.core.cache.time.time", lambda: future_time)

    stats = await cache.stats()
    assert stats["total"] == 2
    assert stats["live"] == 1
    assert stats["expired"] == 1
