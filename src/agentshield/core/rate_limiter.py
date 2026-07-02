"""Agent behavior rate limits.

Tracks packages scanned per hour and total wheel bytes downloaded per session.
State is persisted in the SQLite DB so limits survive process restarts within
the same session (identified by AGENTSHIELD_SESSION_ID env var).

Semantics:

* ``max_packages_per_hour`` — a rolling 1-hour window; the package counter (and
  its window) resets when the window lapses.
* ``max_wheel_mb_per_session`` — a **per-session** byte budget; it accumulates
  for the lifetime of the session ID and is *not* reset by the hourly window.

Concurrency: scans run with concurrency up to 10, so the read-modify-write on
``session_state`` executes inside a single ``BEGIN IMMEDIATE`` transaction —
otherwise concurrent checkers read the same counter and lost updates undercount
the limits.
"""

from __future__ import annotations

import os
import time
import uuid
from pathlib import Path
from typing import Any

import aiosqlite

from agentshield.core.config import RateLimitsConfig
from agentshield.core.models import Finding, Severity

_SESSION_ENV = "AGENTSHIELD_SESSION_ID"
_HOUR = 3600


def _session_id() -> str:
    """Return the current session ID, creating and persisting one if necessary."""
    sid = os.environ.get(_SESSION_ENV)
    if not sid:
        sid = str(uuid.uuid4())
        os.environ[_SESSION_ENV] = sid
    return sid


def _resolve_counters(state: dict[str, Any] | None, now: int) -> tuple[int, int, int]:
    """Return ``(package_count, total_bytes, window_start)`` for *state*.

    The package counter (and its window) resets when there is no prior state or
    the previous 1-hour window has elapsed. ``total_bytes`` is a per-*session*
    budget and is never reset by the window.
    """
    if state is None:
        return 0, 0, now
    if state["window_start"] < now - _HOUR:
        return 0, state["total_bytes"], now
    return state["package_count"], state["total_bytes"], state["window_start"]


class RateLimiter:
    def __init__(self, db_path: Path, config: RateLimitsConfig) -> None:
        self._db_path = db_path
        self._config = config

    async def _connect(self) -> aiosqlite.Connection:
        from agentshield.core.cache import CacheConfig, ScanCache

        # ScanCache owns the schema; reuse it so the tables always exist.
        cache = ScanCache(CacheConfig(db_path=self._db_path))
        db = await aiosqlite.connect(self._db_path)
        try:
            await cache._ensure_schema(db)
        except BaseException:
            await db.close()
            raise
        return db

    async def check(self, package: str, wheel_bytes: int = 0) -> list[Finding]:
        """Check rate limits and update session counters.

        Returns R1.1 findings (severity HIGH) if a limit is exceeded.
        When limits are not exceeded the package and byte counters are
        incremented. The read-check-increment runs in one ``BEGIN IMMEDIATE``
        transaction so concurrent scans cannot lose updates.
        """
        sid = _session_id()
        now = int(time.time())

        db = await self._connect()
        try:
            await db.execute("BEGIN IMMEDIATE")
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM session_state WHERE session_id = ?", (sid,)
            ) as cur:
                row = await cur.fetchone()
            state = dict(row) if row else None
            pkg_count, total_bytes, window_start = _resolve_counters(state, now)

            findings = self._evaluate(pkg_count, total_bytes, wheel_bytes)

            if not findings:
                # Only count the package when it passes the rate limit check
                await db.execute(
                    """INSERT OR REPLACE INTO session_state
                       (session_id, package_count, total_bytes, window_start)
                       VALUES (?,?,?,?)""",
                    (sid, pkg_count + 1, total_bytes + wheel_bytes, window_start),
                )
            await db.commit()
        except BaseException:
            await db.rollback()
            raise
        finally:
            await db.close()

        return findings

    def _evaluate(self, pkg_count: int, total_bytes: int, wheel_bytes: int) -> list[Finding]:
        findings: list[Finding] = []

        if pkg_count >= self._config.max_packages_per_hour:
            findings.append(
                Finding(
                    rule_id="R1.1",
                    title=(
                        f"Rate limit exceeded: {pkg_count}/"
                        f"{self._config.max_packages_per_hour} packages this hour"
                    ),
                    description=(
                        f"The session has scanned {pkg_count} packages in the last hour, "
                        f"exceeding the configured limit of "
                        f"{self._config.max_packages_per_hour} packages/hour."
                    ),
                    severity=Severity.HIGH,
                    source="rate_limiter",
                    remediation=(
                        "Reduce the rate of package installations or increase "
                        "max_packages_per_hour in config.toml [rate_limits]."
                    ),
                )
            )

        total_mb = total_bytes / (1024 * 1024)
        new_mb = wheel_bytes / (1024 * 1024)
        max_mb = self._config.max_wheel_mb_per_session

        if total_mb + new_mb > max_mb:
            findings.append(
                Finding(
                    rule_id="R1.1",
                    title=(
                        f"Session wheel size limit exceeded: {total_mb + new_mb:.1f}MB/{max_mb}MB"
                    ),
                    description=(
                        f"This package would bring the session total to "
                        f"{total_mb + new_mb:.1f}MB, exceeding the configured "
                        f"limit of {max_mb}MB per session."
                    ),
                    severity=Severity.HIGH,
                    source="rate_limiter",
                    remediation=(
                        "Reduce wheel download size or increase "
                        "max_wheel_mb_per_session in config.toml [rate_limits]."
                    ),
                )
            )

        return findings

    async def record_wheel_bytes(self, wheel_bytes: int) -> None:
        """Add *wheel_bytes* downloaded during a --deep scan to the session total.

        Wheel sizes are only known after the artifact is downloaded, so they are
        recorded here rather than in :meth:`check`. A session that has already
        exceeded ``max_wheel_mb_per_session`` is then blocked by the next
        :meth:`check` call. Does not increment the package counter. The update
        is a single atomic UPSERT, safe under concurrent scans.
        """
        if wheel_bytes <= 0:
            return

        sid = _session_id()
        now = int(time.time())

        db = await self._connect()
        try:
            await db.execute(
                """INSERT INTO session_state (session_id, package_count, total_bytes, window_start)
                   VALUES (?, 0, ?, ?)
                   ON CONFLICT(session_id) DO UPDATE
                   SET total_bytes = total_bytes + excluded.total_bytes""",
                (sid, wheel_bytes, now),
            )
            await db.commit()
        finally:
            await db.close()
