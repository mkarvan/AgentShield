"""Unit tests for rate_limiter.py."""

from __future__ import annotations

import asyncio
import time
import uuid
from pathlib import Path

import pytest

from agentshield.core.config import RateLimitsConfig
from agentshield.core.models import Severity
from agentshield.core.rate_limiter import _SESSION_ENV, RateLimiter


@pytest.fixture(autouse=True)
def isolate_session(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each test runs in its own session so counters don't bleed across tests."""
    monkeypatch.setenv(_SESSION_ENV, str(uuid.uuid4()))


@pytest.fixture
def tmp_db(tmp_path: Path) -> Path:
    return tmp_path / "test.db"


def _rl(tmp_db: Path, max_pkg: int = 5, max_mb: int = 100) -> RateLimiter:
    return RateLimiter(
        tmp_db, RateLimitsConfig(max_packages_per_hour=max_pkg, max_wheel_mb_per_session=max_mb)
    )


# ── basic pass-through ─────────────────────────────────────────────────────


def test_first_package_allowed(tmp_db: Path) -> None:
    rl = _rl(tmp_db)
    findings = asyncio.run(rl.check("requests"))
    assert findings == []


def test_within_limit_no_findings(tmp_db: Path) -> None:
    rl = _rl(tmp_db, max_pkg=3)
    for pkg in ("a", "b", "c"):
        findings = asyncio.run(rl.check(pkg))
        assert findings == [], f"Expected no findings for {pkg}"


# ── package-count limit ────────────────────────────────────────────────────


def test_exceeds_package_limit_returns_r11(tmp_db: Path) -> None:
    rl = _rl(tmp_db, max_pkg=2)
    asyncio.run(rl.check("pkg1"))
    asyncio.run(rl.check("pkg2"))

    findings = asyncio.run(rl.check("pkg3"))
    assert len(findings) == 1
    assert findings[0].rule_id == "R1.1"
    assert findings[0].severity == Severity.HIGH
    assert "2/2" in findings[0].title or "rate limit" in findings[0].title.lower()


def test_rate_limit_finding_has_remediation(tmp_db: Path) -> None:
    rl = _rl(tmp_db, max_pkg=1)
    asyncio.run(rl.check("first"))

    findings = asyncio.run(rl.check("second"))
    assert findings[0].remediation is not None
    assert "max_packages_per_hour" in findings[0].remediation


def test_blocked_package_not_counted(tmp_db: Path) -> None:
    """When rate limit is exceeded the counter must NOT be incremented."""
    from agentshield.core.cache import ScanCache
    from agentshield.core.config import CacheConfig
    from agentshield.core.rate_limiter import _session_id

    rl = _rl(tmp_db, max_pkg=1)
    asyncio.run(rl.check("first"))  # uses the 1 allowed slot

    # This is blocked — counter should stay at 1
    asyncio.run(rl.check("second"))

    cache = ScanCache(CacheConfig(db_path=tmp_db))
    state = asyncio.run(cache.get_session_state(_session_id()))
    assert state is not None
    assert state["package_count"] == 1


# ── wheel-size limit ───────────────────────────────────────────────────────


def test_wheel_size_within_limit_allowed(tmp_db: Path) -> None:
    rl = _rl(tmp_db, max_mb=10)
    mb = 5 * 1024 * 1024  # 5 MB
    findings = asyncio.run(rl.check("bigpkg", wheel_bytes=mb))
    assert findings == []


def test_wheel_size_exceeds_limit_returns_r11(tmp_db: Path) -> None:
    rl = _rl(tmp_db, max_mb=10)
    mb9 = 9 * 1024 * 1024
    asyncio.run(rl.check("first", wheel_bytes=mb9))  # 9 MB used

    mb5 = 5 * 1024 * 1024
    findings = asyncio.run(rl.check("second", wheel_bytes=mb5))  # would push to 14 MB
    assert len(findings) == 1
    assert findings[0].rule_id == "R1.1"
    assert findings[0].severity == Severity.HIGH


def test_wheel_size_finding_mentions_mb_limit(tmp_db: Path) -> None:
    rl = _rl(tmp_db, max_mb=10)
    asyncio.run(rl.check("first", wheel_bytes=9 * 1024 * 1024))

    findings = asyncio.run(rl.check("second", wheel_bytes=5 * 1024 * 1024))
    assert "10" in findings[0].title or "MB" in findings[0].title


# ── record_wheel_bytes (post-download accounting) ──────────────────────────


def test_record_wheel_bytes_accumulates_into_session_total(tmp_db: Path) -> None:
    rl = _rl(tmp_db, max_mb=10)
    # Simulate two --deep downloads totalling 12 MB (over the 10 MB budget).
    asyncio.run(rl.record_wheel_bytes(7 * 1024 * 1024))
    asyncio.run(rl.record_wheel_bytes(5 * 1024 * 1024))

    # The next check() (no bytes of its own) must see the session is over budget.
    findings = asyncio.run(rl.check("nextpkg"))
    rule_ids = [f.rule_id for f in findings]
    assert "R1.1" in rule_ids
    assert any("MB" in f.title for f in findings if f.rule_id == "R1.1")


def test_record_wheel_bytes_does_not_count_a_package(tmp_db: Path) -> None:
    rl = _rl(tmp_db, max_pkg=2, max_mb=1000)
    asyncio.run(rl.record_wheel_bytes(1024))
    # Recording bytes must not consume the package-count budget.
    assert asyncio.run(rl.check("a")) == []
    assert asyncio.run(rl.check("b")) == []


def test_record_wheel_bytes_ignores_nonpositive(tmp_db: Path) -> None:
    rl = _rl(tmp_db, max_mb=10)
    asyncio.run(rl.record_wheel_bytes(0))
    asyncio.run(rl.record_wheel_bytes(-100))
    # Nothing recorded → a normal small package still passes.
    assert asyncio.run(rl.check("clean")) == []


# ── window reset ──────────────────────────────────────────────────────────


def test_window_reset_clears_counter(tmp_db: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """After the 1-hour window expires, the package counter resets."""
    from agentshield.core.cache import ScanCache
    from agentshield.core.config import CacheConfig
    from agentshield.core.rate_limiter import _session_id

    rl = _rl(tmp_db, max_pkg=1)
    asyncio.run(rl.check("first"))

    # Manually back-date window_start by 2 hours
    sid = _session_id()
    cache = ScanCache(CacheConfig(db_path=tmp_db))
    state = asyncio.run(cache.get_session_state(sid))
    assert state is not None
    old_window = int(time.time()) - 2 * 3600
    asyncio.run(
        cache.upsert_session_state(sid, state["package_count"], state["total_bytes"], old_window)
    )

    # After reset the limit should not trigger
    findings = asyncio.run(rl.check("second"))
    assert findings == []


# ── session isolation ─────────────────────────────────────────────────────


def test_different_sessions_have_independent_counters(
    tmp_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_a = str(uuid.uuid4())
    session_b = str(uuid.uuid4())

    monkeypatch.setenv(_SESSION_ENV, session_a)
    rl_a = _rl(tmp_db, max_pkg=1)
    asyncio.run(rl_a.check("pkg"))

    # Switch session — counter should be fresh
    monkeypatch.setenv(_SESSION_ENV, session_b)
    rl_b = _rl(tmp_db, max_pkg=1)
    findings = asyncio.run(rl_b.check("pkg"))
    assert findings == []


# ── source field ──────────────────────────────────────────────────────────


def test_rate_limit_finding_source_is_rate_limiter(tmp_db: Path) -> None:
    rl = _rl(tmp_db, max_pkg=0)  # limit at 0 → always triggered
    findings = asyncio.run(rl.check("any"))
    assert findings[0].source == "rate_limiter"
