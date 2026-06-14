"""Local malicious-package database.

Sources:
  1. Local curated list (bundled JSON)  — checked first, instant, offline
  2. SQLite malicious_packages table    — populated by `agentshield cache warm`
  3. OSV API real-time filter           — the OSVClient already handles MALICIOUS type
     advisories; this module handles the offline path.

Use MaliciousDB.check() during a scan to get a T1.1 Finding if the package
is known-malicious.  Use MaliciousDB.warm() (called by `cache warm`) to
populate the SQLite table from the OSV bulk API.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
from pathlib import Path
from typing import Any

import httpx

from agentshield.core.models import Ecosystem, Finding, ScanRequest, Severity

logger = logging.getLogger(__name__)

_CURATED_LIST_FILE = Path(__file__).parent / "data" / "malicious_packages.json"

# OSV batch query endpoint
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
# OSV single query endpoint (for warm-up per-ecosystem bulk fetch)
OSV_QUERY_URL = "https://api.osv.dev/v1/query"

_ECOSYSTEM_MAP: dict[Ecosystem, str] = {
    Ecosystem.PYPI: "PyPI",
    Ecosystem.NPM: "npm",
    Ecosystem.CARGO: "crates.io",
}


def _load_curated() -> dict[str, list[str]]:
    """Load the bundled curated malicious package list."""
    if not _CURATED_LIST_FILE.exists():
        return {}
    try:
        result: dict[str, list[str]] = json.loads(_CURATED_LIST_FILE.read_text())
        return result
    except Exception:
        return {}


class MaliciousDB:
    """Check and manage the local malicious-package database."""

    def __init__(self) -> None:
        self._curated: dict[str, list[str]] | None = None
        self._curated_lower: dict[str, frozenset[str]] | None = None

    def _get_curated(self) -> dict[str, list[str]]:
        if self._curated is None:
            raw = _load_curated()
            self._curated = raw
            self._curated_lower = {
                eco: frozenset(p.lower() for p in pkgs) for eco, pkgs in raw.items()
            }
        return self._curated

    def _get_curated_lower(self) -> dict[str, frozenset[str]]:
        if self._curated_lower is None:
            # _get_curated() populates _curated_lower on a fresh load; rebuild
            # here for the case where _curated was set externally (e.g. tests).
            curated = self._get_curated()
            if self._curated_lower is None:
                self._curated_lower = {
                    eco: frozenset(p.lower() for p in pkgs) for eco, pkgs in curated.items()
                }
        return self._curated_lower

    async def check(self, request: ScanRequest, db_path: Path | None = None) -> list[Finding]:
        """Return a T1.1 Finding if the package is known-malicious (offline check only)."""
        findings: list[Finding] = []

        # 1. Curated list check (instant, always available)
        curated_lower = self._get_curated_lower()
        eco_key = request.ecosystem.value
        if request.package.lower() in curated_lower.get(eco_key, frozenset()):
            findings.append(
                Finding(
                    rule_id="T1.1",
                    title=f"Known-malicious package: {request.package}",
                    description=(
                        f"'{request.package}' is on the AgentShield curated malicious package list."
                    ),
                    severity=Severity.CRITICAL,
                    source="malicious_db_curated",
                    references=[],
                    remediation="Do not install this package.",
                )
            )
            return findings  # Curated hit is definitive

        # 2. SQLite table check (populated by cache warm)
        if db_path is not None:
            row = await _check_sqlite(request.package, eco_key, db_path)
            if row:
                findings.append(
                    Finding(
                        rule_id="T1.1",
                        title=f"Known-malicious package: {request.package}",
                        description=row.get("reason")
                        or (
                            f"'{request.package}' was flagged as malicious by "
                            f"{row.get('source', 'unknown source')}."
                        ),
                        severity=Severity.CRITICAL,
                        source="malicious_db",
                        references=[],
                        remediation="Do not install this package.",
                        metadata={"db_source": row.get("source")},
                    )
                )

        return findings

    async def warm(
        self,
        db_path: Path,
        ecosystems: list[Ecosystem] | None = None,
        progress_callback: object = None,
    ) -> int:
        """Fetch malicious advisories from OSV and populate the local SQLite table.

        Returns the total number of malicious packages recorded.
        """
        from agentshield.core.cache import ScanCache
        from agentshield.core.config import CacheConfig

        target_ecosystems = ecosystems or list(Ecosystem)
        cache = ScanCache(CacheConfig(db_path=db_path))

        total = 0
        for ecosystem in target_ecosystems:
            osv_eco = _ECOSYSTEM_MAP.get(ecosystem)
            if osv_eco is None:
                continue
            try:
                rows = await _fetch_malicious_from_osv(osv_eco, self)
                if rows:
                    inserted = await cache.add_malicious_packages_bulk(rows)
                    total += inserted
                    logger.info("Warmed %d malicious packages for %s", inserted, ecosystem.value)
                if progress_callback is not None and callable(progress_callback):
                    progress_callback(ecosystem.value, len(rows))
            except Exception as exc:
                logger.warning(
                    "Failed to fetch malicious packages for %s: %s", ecosystem.value, exc
                )

        return total


_OSV_ECO_TO_CURATED_KEY: dict[str, str] = {
    "PyPI": "pypi",
    "npm": "npm",
    "crates.io": "cargo",
}

_OSV_FETCH_CONCURRENCY = 5


async def _fetch_malicious_from_osv(
    ecosystem: str,
    db: MaliciousDB,
) -> list[tuple[str, str, str | None, str | None]]:
    """Query OSV for known-malicious advisories in a given ecosystem.

    Uses asyncio.gather with a semaphore to fetch all packages concurrently
    (up to _OSV_FETCH_CONCURRENCY simultaneous requests).
    """
    curated_key = _OSV_ECO_TO_CURATED_KEY.get(ecosystem)
    if curated_key is None:
        return []

    packages_to_check = db._get_curated().get(curated_key, [])
    if not packages_to_check:
        return []

    sem = asyncio.Semaphore(_OSV_FETCH_CONCURRENCY)

    async def _check_one(
        client: httpx.AsyncClient, pkg: str
    ) -> tuple[str, str, str | None, str | None] | None:
        async with sem:
            try:
                payload = {"package": {"name": pkg, "ecosystem": ecosystem}}
                resp = await client.post(OSV_QUERY_URL, json=payload)
                if resp.status_code != 200:
                    return None
                data = resp.json()
                vulns: list[dict[str, Any]] = data.get("vulns", [])
                malicious = [
                    v for v in vulns if v.get("database_specific", {}).get("type") == "MALICIOUS"
                ]
                reason = malicious[0].get("summary") if malicious else None
                return (pkg, curated_key, reason, "osv_malicious+curated")
            except Exception as exc:
                logger.debug("OSV check for %s/%s failed: %s", ecosystem, pkg, exc)
                return None

    async with httpx.AsyncClient(timeout=30.0) as client:
        raw = await asyncio.gather(*[_check_one(client, pkg) for pkg in packages_to_check])

    return [r for r in raw if r is not None]


async def _check_sqlite(package: str, ecosystem: str, db_path: Path) -> dict[str, Any] | None:
    """Check the malicious_packages SQLite table. Returns row dict or None."""
    try:
        import aiosqlite

        async with aiosqlite.connect(db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM malicious_packages WHERE package = ? AND ecosystem = ?",
                (package.lower(), ecosystem.lower()),
            ) as cur:
                row = await cur.fetchone()
        return dict(row) if row else None
    except (OSError, ValueError, KeyError, sqlite3.Error) as exc:
        logger.warning("SQLite malicious-package check failed for %s: %s", package, exc)
        return None
