"""Trust Score / Reputation System (rule T5.1).

Aggregates signals from PyPI, npm, crates.io and local scan history to
compute a 0–100 trust score for a package.

Score bands:
  80–100  high-trust
  50–79   moderate
  20–49   low-trust
  0–19    suspicious
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from agentshield.core.models import Ecosystem, Finding, ScanRequest, Severity

logger = logging.getLogger(__name__)

_LABEL_THRESHOLDS: list[tuple[int, str]] = [
    (80, "high-trust"),
    (50, "moderate"),
    (20, "low-trust"),
    (0, "suspicious"),
]

_LOW_TRUST_THRESHOLD = 50


def _score_to_label(score: int) -> str:
    for threshold, label in _LABEL_THRESHOLDS:
        if score >= threshold:
            return label
    return "suspicious"


@dataclass
class TrustScoreResult:
    score: int
    label: str
    signals: dict[str, Any] = field(default_factory=dict)

    def to_finding(self, request: ScanRequest) -> Finding | None:
        """Return a T5.1 Finding if score is below the low-trust threshold."""
        if self.score >= _LOW_TRUST_THRESHOLD:
            return None
        sev = Severity.HIGH if self.score >= 20 else Severity.CRITICAL
        return Finding(
            rule_id="T5.1",
            title=f"Low trust score: {self.score}/100 ({self.label})",
            description=(
                f"Package '{request.package}' has a low reputation score of "
                f"{self.score}/100 ({self.label}). Signals: {self.signals}"
            ),
            severity=sev,
            source="trust_score",
            remediation=(
                "Review the package history and consider using a well-established alternative."
            ),
        )


async def compute_trust_score(
    request: ScanRequest,
    db_path: Path | None = None,
    *,
    timeout: float = 10.0,
) -> TrustScoreResult:
    """Fetch registry metadata and compute a 0–100 trust score for the package."""
    signals: dict[str, Any] = {}
    score_parts: list[tuple[int, int]] = []  # (earned_points, max_points)

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            if request.ecosystem == Ecosystem.PYPI:
                await _fetch_pypi_signals(client, request.package, signals, score_parts)
            elif request.ecosystem == Ecosystem.NPM:
                await _fetch_npm_signals(client, request.package, signals, score_parts)
            elif request.ecosystem == Ecosystem.CARGO:
                await _fetch_cargo_signals(client, request.package, signals, score_parts)
    except Exception as exc:
        logger.debug("Trust score fetch error for %s: %s", request.package, exc)

    if db_path is not None:
        await _fetch_history_signals(
            db_path, request.package, request.ecosystem.value, signals, score_parts
        )

    if not score_parts:
        return TrustScoreResult(score=50, label="moderate", signals=signals)

    total_points = sum(p for p, _ in score_parts)
    total_max = sum(m for _, m in score_parts)
    raw = int(total_points / total_max * 100) if total_max > 0 else 50
    score = max(0, min(100, raw))
    return TrustScoreResult(score=score, label=_score_to_label(score), signals=signals)


async def _fetch_pypi_signals(
    client: httpx.AsyncClient,
    package: str,
    signals: dict[str, Any],
    score_parts: list[tuple[int, int]],
) -> None:
    try:
        resp = await client.get(f"https://pypi.org/pypi/{package}/json")
        if resp.status_code != 200:
            return
        data: dict[str, Any] = resp.json()
        info: dict[str, Any] = data.get("info") or {}
        urls: list[dict[str, Any]] = data.get("urls") or []

        # Age: older packages score higher (max 30 points; 1 pt/month up to 2.5 years)
        if urls:
            upload_time_str = urls[-1].get("upload_time_iso_8601") or urls[-1].get("upload_time")
            if upload_time_str:
                try:
                    upload_dt = datetime.fromisoformat(str(upload_time_str).replace("Z", "+00:00"))
                    age_days = (datetime.now(UTC) - upload_dt).days
                    signals["age_days"] = age_days
                    score_parts.append((min(30, age_days // 30), 30))
                except (ValueError, TypeError):
                    pass

        # Version count: many releases → active maintenance (max 20 points)
        releases: dict[str, Any] = data.get("releases") or {}
        release_count = len(releases)
        signals["release_count"] = release_count
        score_parts.append((min(20, release_count * 2), 20))

        # Metadata completeness: homepage, summary, author (max 20 points)
        meta_points = 0
        if info.get("home_page") or info.get("project_urls"):
            meta_points += 7
        if info.get("summary"):
            meta_points += 7
        if info.get("author") or info.get("author_email"):
            meta_points += 6
        signals["has_metadata"] = meta_points > 0
        score_parts.append((meta_points, 20))

        # Download stats via pypistats.org (max 30 points)
        try:
            stats_resp = await client.get(
                f"https://pypistats.org/api/packages/{package.lower()}/recent",
                headers={"Accept": "application/json"},
            )
            if stats_resp.status_code == 200:
                stats_data: dict[str, Any] = stats_resp.json()
                monthly = (stats_data.get("data") or {}).get("last_month", 0)
                signals["monthly_downloads"] = monthly
                if monthly >= 1_000_000:
                    dl_points = 30
                elif monthly >= 100_000:
                    dl_points = 20
                elif monthly >= 10_000:
                    dl_points = 10
                elif monthly >= 1_000:
                    dl_points = 5
                else:
                    dl_points = 0
                score_parts.append((dl_points, 30))
        except Exception:
            pass

    except Exception as exc:
        logger.debug("PyPI trust signal fetch failed for %s: %s", package, exc)


async def _fetch_npm_signals(
    client: httpx.AsyncClient,
    package: str,
    signals: dict[str, Any],
    score_parts: list[tuple[int, int]],
) -> None:
    try:
        resp = await client.get(f"https://registry.npmjs.org/{package}")
        if resp.status_code != 200:
            return
        data: dict[str, Any] = resp.json()

        # Age
        time_data: dict[str, Any] = data.get("time") or {}
        created_str = time_data.get("created")
        if created_str:
            try:
                created = datetime.fromisoformat(str(created_str).replace("Z", "+00:00"))
                age_days = (datetime.now(UTC) - created).days
                signals["age_days"] = age_days
                score_parts.append((min(30, age_days // 30), 30))
            except (ValueError, TypeError):
                pass

        # Version count
        versions: dict[str, Any] = data.get("versions") or {}
        release_count = len(versions)
        signals["release_count"] = release_count
        score_parts.append((min(20, release_count * 2), 20))

        # Maintainer count (max 20 points; 5 pts each, up to 4 maintainers)
        maintainers: list[Any] = data.get("maintainers") or []
        maintainer_count = len(maintainers)
        signals["maintainer_count"] = maintainer_count
        score_parts.append((min(20, maintainer_count * 5), 20))

        # Download count via npm downloads API (max 30 points)
        try:
            dl_resp = await client.get(
                f"https://api.npmjs.org/downloads/point/last-month/{package}"
            )
            if dl_resp.status_code == 200:
                dl_data: dict[str, Any] = dl_resp.json()
                downloads = int(dl_data.get("downloads") or 0)
                signals["monthly_downloads"] = downloads
                if downloads >= 1_000_000:
                    dl_points = 30
                elif downloads >= 100_000:
                    dl_points = 20
                elif downloads >= 10_000:
                    dl_points = 10
                elif downloads >= 1_000:
                    dl_points = 5
                else:
                    dl_points = 0
                score_parts.append((dl_points, 30))
        except Exception:
            pass

    except Exception as exc:
        logger.debug("npm trust signal fetch failed for %s: %s", package, exc)


async def _fetch_cargo_signals(
    client: httpx.AsyncClient,
    package: str,
    signals: dict[str, Any],
    score_parts: list[tuple[int, int]],
) -> None:
    try:
        resp = await client.get(
            f"https://crates.io/api/v1/crates/{package}",
            headers={"User-Agent": "agentshield/0.7.0 (security scanner)"},
        )
        if resp.status_code != 200:
            return
        data: dict[str, Any] = resp.json()
        crate: dict[str, Any] = data.get("crate") or {}

        # Age
        created_str = crate.get("created_at")
        if created_str:
            try:
                created = datetime.fromisoformat(str(created_str).replace("Z", "+00:00"))
                age_days = (datetime.now(UTC) - created).days
                signals["age_days"] = age_days
                score_parts.append((min(30, age_days // 30), 30))
            except (ValueError, TypeError):
                pass

        # Version count
        versions: list[Any] = data.get("versions") or []
        release_count = len(versions)
        signals["release_count"] = release_count
        score_parts.append((min(20, release_count * 2), 20))

        # Total downloads (max 30 points)
        downloads = int(crate.get("downloads") or 0)
        signals["total_downloads"] = downloads
        if downloads >= 1_000_000:
            dl_points = 30
        elif downloads >= 100_000:
            dl_points = 20
        elif downloads >= 10_000:
            dl_points = 10
        elif downloads >= 1_000:
            dl_points = 5
        else:
            dl_points = 0
        score_parts.append((dl_points, 30))

    except Exception as exc:
        logger.debug("crates.io trust signal fetch failed for %s: %s", package, exc)


async def _fetch_history_signals(
    db_path: Path,
    package: str,
    ecosystem: str,
    signals: dict[str, Any],
    score_parts: list[tuple[int, int]],
) -> None:
    """Penalise packages with prior BLOCK decisions in local scan history."""
    try:
        import aiosqlite

        async with (
            aiosqlite.connect(db_path) as db,
            db.execute(
                "SELECT decision FROM scan_history "
                "WHERE package = ? AND ecosystem = ? "
                "ORDER BY scanned_at DESC LIMIT 10",
                (package.lower(), ecosystem),
            ) as cursor,
        ):
            rows = list(await cursor.fetchall())

        if not rows:
            return

        block_count = sum(1 for r in rows if r[0] == "BLOCK")
        signals["past_block_count"] = block_count
        signals["past_scan_count"] = len(rows)

        if block_count == 0:
            history_points = 20
        elif block_count <= 1:
            history_points = 10
        else:
            history_points = 0
        score_parts.append((history_points, 20))

    except Exception as exc:
        logger.debug("Scan history trust signal fetch failed: %s", exc)
