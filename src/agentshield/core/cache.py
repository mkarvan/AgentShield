from __future__ import annotations

import hashlib
import time
from typing import Any

import aiosqlite

from agentshield.core.config import CacheConfig
from agentshield.core.models import ScanRequest, ScanResult

_TTL_BY_SEVERITY: dict[str, int] = {
    "NONE": 7 * 24 * 3600,    # clean scan — 7 days
    "INFO": 24 * 3600,         # 24 h
    "LOW": 12 * 3600,          # 12 h
    "MEDIUM": 6 * 3600,        # 6 h
    "HIGH": 6 * 3600,          # 6 h
    "CRITICAL": 3 * 3600,      # 3 h — re-check critical packages often
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
        return {"total": total, "live": live, "expired": total - live}
