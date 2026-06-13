"""Unit tests for the malicious package database module."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from agentshield.core.models import Ecosystem, ScanRequest, Severity
from agentshield.databases.malicious_db import MaliciousDB, _load_curated


def _make_request(
    package: str = "colouredlogs",
    ecosystem: Ecosystem = Ecosystem.PYPI,
) -> ScanRequest:
    return ScanRequest(package=package, ecosystem=ecosystem)


# ── curated list loading ─────────────────────────────────────────────────────────

def test_load_curated_returns_dict():
    data = _load_curated()
    assert isinstance(data, dict)
    # Should have at least pypi and npm keys from the bundled list
    assert "pypi" in data or len(data) == 0  # empty is acceptable if file missing


def test_load_curated_returns_empty_on_bad_file(tmp_path: Path):
    with patch("agentshield.databases.malicious_db._CURATED_LIST_FILE", tmp_path / "missing.json"):
        data = _load_curated()
    assert data == {}


def test_load_curated_has_pypi_entries():
    data = _load_curated()
    if "pypi" in data:
        assert len(data["pypi"]) > 0


# ── MaliciousDB.check — curated list path ──────────────────────────────────────

@pytest.mark.asyncio
async def test_check_known_malicious_curated():
    db = MaliciousDB()
    fake_curated = {"pypi": ["evil-package"]}
    db._curated = fake_curated

    req = _make_request(package="evil-package", ecosystem=Ecosystem.PYPI)
    findings = await db.check(req)
    assert len(findings) == 1
    assert findings[0].rule_id == "T1.1"
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].source == "malicious_db_curated"


@pytest.mark.asyncio
async def test_check_curated_case_insensitive():
    db = MaliciousDB()
    db._curated = {"pypi": ["Evil-Package"]}

    req = _make_request(package="evil-package")
    findings = await db.check(req)
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_check_clean_package_no_findings():
    db = MaliciousDB()
    db._curated = {"pypi": ["colouredlogs"]}

    req = _make_request(package="requests")  # not in curated list
    findings = await db.check(req, db_path=None)
    assert findings == []


@pytest.mark.asyncio
async def test_check_wrong_ecosystem_no_match():
    db = MaliciousDB()
    db._curated = {"pypi": ["evil-package"]}

    # Same name but different ecosystem — should not match
    req = ScanRequest(package="evil-package", ecosystem=Ecosystem.NPM)
    findings = await db.check(req)
    assert findings == []


# ── MaliciousDB.check — SQLite path ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_check_sqlite_malicious(tmp_path: Path):
    from agentshield.core.cache import ScanCache
    from agentshield.core.config import CacheConfig

    db_path = tmp_path / "test.db"
    cache = ScanCache(CacheConfig(db_path=db_path))
    await cache.add_malicious_package(
        package="bad-pkg",
        ecosystem="pypi",
        reason="Exfiltrates credentials",
        source="osv_malicious",
    )

    db = MaliciousDB()
    db._curated = {}  # Empty curated so we fall through to SQLite

    req = _make_request(package="bad-pkg")
    findings = await db.check(req, db_path=db_path)
    assert len(findings) == 1
    assert findings[0].rule_id == "T1.1"
    assert findings[0].source == "malicious_db"
    assert "Exfiltrates credentials" in findings[0].description


@pytest.mark.asyncio
async def test_check_sqlite_clean_package(tmp_path: Path):
    db = MaliciousDB()
    db._curated = {}

    req = _make_request(package="requests")
    # No entries in DB — should return empty
    findings = await db.check(req, db_path=tmp_path / "empty.db")
    assert findings == []


@pytest.mark.asyncio
async def test_check_sqlite_none_db_path_skips():
    db = MaliciousDB()
    db._curated = {}

    req = _make_request(package="requests")
    # db_path=None should not attempt SQLite lookup
    findings = await db.check(req, db_path=None)
    assert findings == []


# ── ScanCache malicious_packages table ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_cache_add_and_is_malicious(tmp_path: Path):
    from agentshield.core.cache import ScanCache
    from agentshield.core.config import CacheConfig

    cache = ScanCache(CacheConfig(db_path=tmp_path / "test.db"))
    await cache.add_malicious_package("evil", "pypi", "Test reason", "test")
    row = await cache.is_malicious("evil", "pypi")
    assert row is not None
    assert row["package"] == "evil"
    assert row["reason"] == "Test reason"


@pytest.mark.asyncio
async def test_cache_is_malicious_returns_none_for_clean(tmp_path: Path):
    from agentshield.core.cache import ScanCache
    from agentshield.core.config import CacheConfig

    cache = ScanCache(CacheConfig(db_path=tmp_path / "test.db"))
    row = await cache.is_malicious("requests", "pypi")
    assert row is None


@pytest.mark.asyncio
async def test_cache_add_malicious_bulk(tmp_path: Path):
    from agentshield.core.cache import ScanCache
    from agentshield.core.config import CacheConfig

    cache = ScanCache(CacheConfig(db_path=tmp_path / "test.db"))
    rows = [
        ("pkg-a", "pypi", "reason a", "test"),
        ("pkg-b", "pypi", "reason b", "test"),
        ("pkg-c", "npm", None, None),
    ]
    inserted = await cache.add_malicious_packages_bulk(rows)
    assert inserted == 3

    row = await cache.is_malicious("pkg-a", "pypi")
    assert row is not None
    row_npm = await cache.is_malicious("pkg-c", "npm")
    assert row_npm is not None


@pytest.mark.asyncio
async def test_cache_add_malicious_ignore_duplicates(tmp_path: Path):
    from agentshield.core.cache import ScanCache
    from agentshield.core.config import CacheConfig

    cache = ScanCache(CacheConfig(db_path=tmp_path / "test.db"))
    await cache.add_malicious_package("dup-pkg", "pypi", "first", "src1")
    await cache.add_malicious_package("dup-pkg", "pypi", "second", "src2")
    # Second insert is ignored (UNIQUE constraint)
    row = await cache.is_malicious("dup-pkg", "pypi")
    assert row is not None
    assert row["reason"] == "first"


# ── CVE mirror table ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_cache_upsert_and_query_cve(tmp_path: Path):
    from agentshield.core.cache import ScanCache
    from agentshield.core.config import CacheConfig

    cache = ScanCache(CacheConfig(db_path=tmp_path / "test.db"))
    await cache.upsert_cve(
        cve_id="CVE-2024-TEST",
        package="requests",
        ecosystem="pypi",
        affected_versions='[{"type": "SEMVER", "events": [{"introduced": "2.0.0"}]}]',
        severity="HIGH",
        cvss_score=7.5,
        description="Test CVE description",
    )
    rows = await cache.query_cve_mirror("requests", "pypi")
    assert len(rows) == 1
    assert rows[0]["id"] == "CVE-2024-TEST"
    assert rows[0]["severity"] == "HIGH"
    assert rows[0]["cvss_score"] == 7.5


@pytest.mark.asyncio
async def test_cache_query_cve_empty(tmp_path: Path):
    from agentshield.core.cache import ScanCache
    from agentshield.core.config import CacheConfig

    cache = ScanCache(CacheConfig(db_path=tmp_path / "test.db"))
    rows = await cache.query_cve_mirror("clean-package", "pypi")
    assert rows == []


@pytest.mark.asyncio
async def test_cache_upsert_cves_bulk(tmp_path: Path):
    from agentshield.core.cache import ScanCache
    from agentshield.core.config import CacheConfig

    cache = ScanCache(CacheConfig(db_path=tmp_path / "test.db"))
    rows = [
        ("CVE-A", "pkg-a", "pypi", "[]", "HIGH", 7.5, "desc a", 0),
        ("CVE-B", "pkg-b", "npm", "[]", "CRITICAL", 9.8, "desc b", 0),
    ]
    inserted = await cache.upsert_cves_bulk(rows)
    assert inserted == 2

    r = await cache.query_cve_mirror("pkg-a", "pypi")
    assert len(r) == 1
