"""Agent behavior rate limits.

Tracks packages scanned per hour and total wheel bytes downloaded per session.
State is persisted in the SQLite DB so limits survive process restarts within
the same session (identified by AGENTSHIELD_SESSION_ID env var).
"""

from __future__ import annotations

import os
import time
import uuid
from pathlib import Path

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


class RateLimiter:
    def __init__(self, db_path: Path, config: RateLimitsConfig) -> None:
        self._db_path = db_path
        self._config = config

    async def check(self, package: str, wheel_bytes: int = 0) -> list[Finding]:
        """Check rate limits and update session counters.

        Returns R1.1 findings (severity HIGH) if a limit is exceeded.
        When limits are not exceeded the package and byte counters are incremented.
        """
        from agentshield.core.cache import ScanCache
        from agentshield.core.config import CacheConfig

        sid = _session_id()
        now = int(time.time())
        cache = ScanCache(CacheConfig(db_path=self._db_path))

        state = await cache.get_session_state(sid)

        if state is None:
            # Brand-new session
            pkg_count = 0
            total_bytes = 0
            window_start = now
        else:
            # Reset counters if the 1-hour window has elapsed
            if state["window_start"] < now - _HOUR:
                pkg_count = 0
                total_bytes = 0
                window_start = now
            else:
                pkg_count = state["package_count"]
                total_bytes = state["total_bytes"]
                window_start = state["window_start"]

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

        if not findings:
            # Only count the package when it passes the rate limit check
            await cache.upsert_session_state(
                session_id=sid,
                package_count=pkg_count + 1,
                total_bytes=total_bytes + wheel_bytes,
                window_start=window_start,
            )

        return findings
