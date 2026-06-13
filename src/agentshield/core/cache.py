from __future__ import annotations

import hashlib
import time
from typing import Any

import aiosqlite

from agentshield.core.config import CacheConfig
from agentshield.core.models import ScanRequest, ScanResult

_TTL_BY_SEVERITY: dict[str, int] = {
    "NONE": 7 * 24 * 3600,  # clean scan — 7 days
    "INFO": 24 * 3600,  # 24 h
    "LOW": 12 * 3600,  # 12 h
    "MEDIUM": 6 * 3600,  # 6 h
    "HIGH": 6 * 3600,  # 6 h
    "CRITICAL": 3 * 3600,  # 3 h — re-check critical packages often
}

_DDL = """
CREATE TABLE IF NOT EXISTS scan_cache (
    id          TEXT PRIMARY KEY,
    package     TEXT NOT NULL,
    version     TEXT NOT NULL,
    ecosystem   TEXT NOT NULL,
    result_json TEXT NOT NULL,
    scanned_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scan_cache_expires ON scan_cache(expires_at);

CREATE TABLE IF NOT EXISTS cve_mirror (
    id                TEXT PRIMARY KEY,
    package           TEXT NOT NULL,
    ecosystem         TEXT NOT NULL,
    affected_versions TEXT NOT NULL,
    severity          TEXT NOT NULL,
    cvss_score        REAL,
    description       TEXT,
    last_fetched      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cve_mirror_pkg ON cve_mirror(package, ecosystem);

CREATE TABLE IF NOT EXISTS malicious_packages (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    package   TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    reason    TEXT,
    source    TEXT,
    added_at  INTEGER NOT NULL,
    UNIQUE(package, ecosystem)
);
CREATE INDEX IF NOT EXISTS idx_malicious_pkg ON malicious_packages(package, ecosystem);

CREATE TABLE IF NOT EXISTS async_report_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    package       TEXT NOT NULL,
    version       TEXT,
    ecosystem     TEXT NOT NULL,
    findings_json TEXT NOT NULL,
    reason        TEXT NOT NULL,
    logged_at     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_async_log_logged ON async_report_log(logged_at);
"""


class ScanCache:
    def __init__(self, config: CacheConfig) -> None:
        self.config = config
        config.db_path.parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ helpers

    def _key(self, request: ScanRequest) -> str:
        raw = f"{request.ecosystem.value}:{request.package}:{request.version or ''}"
        return hashlib.sha256(raw.encode()).hexdigest()

    async def _ensure_schema(self, db: aiosqlite.Connection) -> None:
        for stmt in _DDL.strip().split(";"):
            stmt = stmt.strip()
            if stmt:
                await db.execute(stmt)

    # ------------------------------------------------------------------ public API

    async def get(self, request: ScanRequest) -> ScanResult | None:
        key = self._key(request)
        now = int(time.time())
        async with aiosqlite.connect(self.config.db_path) as db:
            await self._ensure_schema(db)
            async with db.execute(
                "SELECT result_json FROM scan_cache WHERE id = ? AND expires_at > ?",
                (key, now),
            ) as cur:
                row = await cur.fetchone()
        if row is None:
            return None
        result = ScanResult.model_validate_json(row[0])
        result.cache_hit = True
        return result

    async def set(self, request: ScanRequest, result: ScanResult) -> None:
        key = self._key(request)
        now = int(time.time())
        severity = result.max_severity.value
        ttl = _TTL_BY_SEVERITY.get(severity, self.config.ttl_hours * 3600)
        expires_at = now + ttl

        async with aiosqlite.connect(self.config.db_path) as db:
            await self._ensure_schema(db)
            await db.execute(
                "INSERT OR REPLACE INTO scan_cache VALUES (?,?,?,?,?,?,?)",
                (
                    key,
                    request.package,
                    request.version or "",
                    request.ecosystem.value,
                    result.model_dump_json(),
                    now,
                    expires_at,
                ),
            )
            await db.commit()

    async def clear(self) -> int:
        """Delete all cached entries. Returns the number of rows deleted."""
        async with aiosqlite.connect(self.config.db_path) as db:
            await self._ensure_schema(db)
            cur = await db.execute("DELETE FROM scan_cache")
            await db.commit()
            return cur.rowcount or 0

    async def clear_expired(self) -> int:
        """Delete only expired entries. Returns the number of rows deleted."""
        now = int(time.time())
        async with aiosqlite.connect(self.config.db_path) as db:
            await self._ensure_schema(db)
            cur = await db.execute("DELETE FROM scan_cache WHERE expires_at <= ?", (now,))
            await db.commit()
            return cur.rowcount or 0

    async def stats(self) -> dict[str, Any]:
        """Return cache statistics: total, live, expired counts."""
        now = int(time.time())
        async with aiosqlite.connect(self.config.db_path) as db:
            await self._ensure_schema(db)
            async with db.execute("SELECT COUNT(*) FROM scan_cache") as cur:
                total = (await cur.fetchone() or (0,))[0]
            async with db.execute(
                "SELECT COUNT(*) FROM scan_cache WHERE expires_at > ?", (now,)
            ) as cur:
                live = (await cur.fetchone() or (0,))[0]
            async with db.execute("SELECT COUNT(*) FROM cve_mirror") as cur:
                cve_count = (await cur.fetchone() or (0,))[0]
            async with db.execute("SELECT COUNT(*) FROM malicious_packages") as cur:
                mal_count = (await cur.fetchone() or (0,))[0]
        return {
            "total": total,
            "live": live,
            "expired": total - live,
            "cve_mirror": cve_count,
            "malicious_packages": mal_count,
        }

    # ------------------------------------------------------------------ cve_mirror

    async def upsert_cve(
        self,
        cve_id: str,
        package: str,
        ecosystem: str,
        affected_versions: str,
        severity: str,
        cvss_score: float | None,
        description: str | None,
    ) -> None:
        now = int(time.time())
        async with aiosqlite.connect(self.config.db_path) as db:
            await self._ensure_schema(db)
            await db.execute(
                """INSERT OR REPLACE INTO cve_mirror
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    cve_id,
                    package,
                    ecosystem,
                    affected_versions,
                    severity,
                    cvss_score,
                    description,
                    now,
                ),
            )
            await db.commit()

    async def upsert_cves_bulk(self, rows: list[tuple[Any, ...]]) -> int:
        """Insert many CVE mirror rows at once. Returns inserted count."""
        now = int(time.time())
        records = [(*r, now) if len(r) == 7 else r for r in rows]
        async with aiosqlite.connect(self.config.db_path) as db:
            await self._ensure_schema(db)
            await db.executemany(
                "INSERT OR REPLACE INTO cve_mirror VALUES (?,?,?,?,?,?,?,?)",
                records,
            )
            await db.commit()
        return len(records)

    async def query_cve_mirror(self, package: str, ecosystem: str) -> list[dict[str, Any]]:
        """Return all CVE mirror rows for a package/ecosystem."""
        async with aiosqlite.connect(self.config.db_path) as db:
            await self._ensure_schema(db)
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM cve_mirror WHERE package = ? AND ecosystem = ?",
                (package.lower(), ecosystem.lower()),
            ) as cur:
                rows = await cur.fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------ malicious_packages

    async def add_malicious_package(
        self,
        package: str,
        ecosystem: str,
        reason: str | None = None,
        source: str | None = None,
    ) -> None:
        now = int(time.time())
        async with aiosqlite.connect(self.config.db_path) as db:
            await self._ensure_schema(db)
            await db.execute(
                """INSERT OR IGNORE INTO malicious_packages
                   (package, ecosystem, reason, source, added_at)
                   VALUES (?,?,?,?,?)""",
                (package.lower(), ecosystem.lower(), reason, source, now),
            )
            await db.commit()

    async def add_malicious_packages_bulk(
        self, rows: list[tuple[str, str, str | None, str | None]]
    ) -> int:
        """Bulk-insert (package, ecosystem, reason, source) tuples. Returns inserted count."""
        now = int(time.time())
        records = [(p.lower(), e.lower(), r, s, now) for p, e, r, s in rows]
        async with aiosqlite.connect(self.config.db_path) as db:
            await self._ensure_schema(db)
            await db.executemany(
                "INSERT OR IGNORE INTO malicious_packages (package, ecosystem, reason, source, added_at) VALUES (?,?,?,?,?)",
                records,
            )
            await db.commit()
        return len(records)

    async def is_malicious(self, package: str, ecosystem: str) -> dict[str, Any] | None:
        """Return the malicious_packages row if the package is known-malicious, else None."""
        async with aiosqlite.connect(self.config.db_path) as db:
            await self._ensure_schema(db)
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM malicious_packages WHERE package = ? AND ecosystem = ?",
                (package.lower(), ecosystem.lower()),
            ) as cur:
                row = await cur.fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------ async_report_log

    async def append_async_log(
        self,
        package: str,
        version: str | None,
        ecosystem: str,
        findings_json: str,
        reason: str,
    ) -> None:
        """Append a LOG_ASYNC decision to the async report log."""
        now = int(time.time())
        async with aiosqlite.connect(self.config.db_path) as db:
            await self._ensure_schema(db)
            await db.execute(
                "INSERT INTO async_report_log (package, version, ecosystem, findings_json, reason, logged_at)"
                " VALUES (?,?,?,?,?,?)",
                (package.lower(), version, ecosystem.lower(), findings_json, reason, now),
            )
            await db.commit()

    async def get_async_log(self, since_ts: int = 0) -> list[dict[str, Any]]:
        """Return async report log entries logged after *since_ts* (unix timestamp)."""
        async with aiosqlite.connect(self.config.db_path) as db:
            await self._ensure_schema(db)
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM async_report_log WHERE logged_at > ? ORDER BY logged_at DESC",
                (since_ts,),
            ) as cur:
                rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def clear_async_log(self) -> int:
        """Delete all async report log entries. Returns row count deleted."""
        async with aiosqlite.connect(self.config.db_path) as db:
            await self._ensure_schema(db)
            cur = await db.execute("DELETE FROM async_report_log")
            await db.commit()
            return cur.rowcount or 0
