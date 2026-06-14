"""Cache warm-up logic for `agentshield cache warm`.

Downloads OSV bulk advisory exports for each ecosystem, parses them, and
populates the local SQLite database with:
  • cve_mirror   — CVE/GHSA advisories for offline CVE lookup
  • malicious_packages — packages flagged as type=MALICIOUS in OSV

OSV bulk exports are available at:
  https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip

Each zip contains one JSON file per advisory (e.g. GHSA-xxxx-xxxx-xxxx.json,
PYSEC-2024-123.json, MAL-2024-456.json).

Exit criterion from PLAN.md: warm-up completes in < 5 minutes.
"""

from __future__ import annotations

import io
import json
import logging
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from agentshield.core.models import Ecosystem

logger = logging.getLogger(__name__)

_OSV_BULK_URL = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"

_ECOSYSTEM_OSV_MAP: dict[Ecosystem, str] = {
    Ecosystem.PYPI: "PyPI",
    Ecosystem.NPM: "npm",
    Ecosystem.CARGO: "crates.io",
}

_SEVERITY_MAP: dict[str, str] = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MODERATE": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "NONE": "INFO",
}

# Only cache MEDIUM+ CVEs in the mirror to keep DB size manageable
_MIN_SEVERITY_TO_MIRROR = {"CRITICAL", "HIGH", "MEDIUM"}


@dataclass
class WarmStats:
    ecosystems_processed: list[str] = field(default_factory=list)
    cve_rows_inserted: int = 0
    malicious_rows_inserted: int = 0
    advisories_scanned: int = 0
    errors: list[str] = field(default_factory=list)


async def warm_cache(
    db_path: Path,
    ecosystems: list[Ecosystem] | None = None,
    progress_callback: Any | None = None,
) -> WarmStats:
    """Download OSV bulk exports and populate the local SQLite cache.

    Args:
        db_path: Path to the SQLite database file.
        ecosystems: Which ecosystems to warm. Defaults to all.
        progress_callback: Optional callable(ecosystem, phase, count) for progress reporting.

    Returns:
        WarmStats summarising what was inserted.
    """
    from agentshield.core.cache import ScanCache
    from agentshield.core.config import CacheConfig

    target = ecosystems or list(Ecosystem)
    cache = ScanCache(CacheConfig(db_path=db_path))
    stats = WarmStats()

    async with httpx.AsyncClient(timeout=300.0, follow_redirects=True) as client:
        for ecosystem in target:
            osv_name = _ECOSYSTEM_OSV_MAP.get(ecosystem)
            if osv_name is None:
                continue

            try:
                cve_rows, mal_rows, count = await _process_ecosystem(
                    client, osv_name, ecosystem, progress_callback
                )
                stats.advisories_scanned += count
                stats.ecosystems_processed.append(ecosystem.value)

                if cve_rows:
                    n = await cache.upsert_cves_bulk(cve_rows)
                    stats.cve_rows_inserted += n
                    logger.info("Inserted %d CVE mirror rows for %s", n, ecosystem.value)

                if mal_rows:
                    n = await cache.add_malicious_packages_bulk(mal_rows)
                    stats.malicious_rows_inserted += n
                    logger.info("Inserted %d malicious package rows for %s", n, ecosystem.value)

                if progress_callback is not None and callable(progress_callback):
                    progress_callback(ecosystem.value, "done", count)

            except Exception as exc:
                msg = f"{ecosystem.value}: {exc}"
                stats.errors.append(msg)
                logger.warning("Warm-up failed for %s: %s", ecosystem.value, exc)

    return stats


async def _process_ecosystem(
    client: httpx.AsyncClient,
    osv_name: str,
    ecosystem: Ecosystem,
    progress_callback: Any | None,
) -> tuple[list[tuple[Any, ...]], list[tuple[Any, ...]], int]:
    """Download and parse the OSV bulk zip for one ecosystem.

    Returns (cve_rows, malicious_rows, total_advisories_scanned).
    """
    url = _OSV_BULK_URL.format(ecosystem=osv_name)
    logger.info("Downloading OSV bulk export: %s", url)

    if progress_callback is not None and callable(progress_callback):
        progress_callback(ecosystem.value, "downloading", 0)

    resp = await client.get(url)
    resp.raise_for_status()
    zip_bytes = resp.content

    if progress_callback is not None and callable(progress_callback):
        progress_callback(ecosystem.value, "parsing", 0)

    cve_rows: list[tuple[Any, ...]] = []
    mal_rows: list[tuple[Any, ...]] = []
    count = 0

    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            try:
                raw = zf.read(name)
                adv = json.loads(raw)
                count += 1
                _parse_advisory(adv, ecosystem, cve_rows, mal_rows)
            except Exception as exc:
                logger.debug("Failed to parse %s: %s", name, exc)

    return cve_rows, mal_rows, count


def _parse_advisory(
    adv: dict[str, Any],
    ecosystem: Ecosystem,
    cve_rows: list[tuple[Any, ...]],
    mal_rows: list[tuple[Any, ...]],
) -> None:
    adv_id: str = adv.get("id", "")
    if not adv_id:
        return

    db_specific = adv.get("database_specific", {})
    adv_type = db_specific.get("type", "")

    # Identify all affected packages in this ecosystem
    packages: list[str] = []
    for affected in adv.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem", "").lower() == _ECOSYSTEM_OSV_MAP[ecosystem].lower():
            name = pkg.get("name", "")
            if name:
                packages.append(name)

    if not packages:
        return

    # Malicious package handling
    if adv_type == "MALICIOUS":
        for pkg_name in packages:
            reason = adv.get("summary") or adv_id
            mal_rows.append((pkg_name, ecosystem.value, reason, "osv_malicious"))
        return

    # CVE/advisory mirror for offline lookup
    severity_str, cvss_score = _extract_severity(adv)
    if severity_str not in _MIN_SEVERITY_TO_MIRROR:
        return  # Skip LOW/INFO to keep DB manageable

    description = adv.get("details") or adv.get("summary") or ""
    affected_versions = _extract_affected_versions(adv)

    for pkg_name in packages:
        cve_rows.append(
            (
                adv_id,
                pkg_name.lower(),
                ecosystem.value,
                affected_versions,
                severity_str,
                cvss_score,
                description[:2000] if description else None,
            )
        )


def _extract_severity(adv: dict[str, Any]) -> tuple[str, float | None]:
    """Return (severity_string, cvss_score) from an OSV advisory."""
    db_sev = adv.get("database_specific", {}).get("severity", "")
    if db_sev:
        mapped = _SEVERITY_MAP.get(db_sev.upper(), "MEDIUM")
        return mapped, None

    for sev_entry in adv.get("severity", []):
        if sev_entry.get("type") in ("CVSS_V3", "CVSS_V3_1"):
            score = _cvss3_score(sev_entry.get("score", ""))
            if score is not None:
                sev = _severity_from_score(score)
                return sev, score

    return "MEDIUM", None


def _severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "INFO"


def _cvss3_score(vector: str) -> float | None:
    """Parse a CVSS v3.x vector string and return the base score."""
    import math

    try:
        if not vector.startswith("CVSS:3"):
            return None
        parts = dict(p.split(":") for p in vector.split("/")[1:])
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}[parts["AV"]]
        ac = {"L": 0.77, "H": 0.44}[parts["AC"]]
        scope_changed = parts["S"] == "C"
        pr_table = {"N": (0.85, 0.85), "L": (0.62, 0.68), "H": (0.27, 0.50)}
        pr = pr_table[parts["PR"]][1 if scope_changed else 0]
        ui = {"N": 0.85, "R": 0.62}[parts["UI"]]
        cia = {"N": 0.0, "L": 0.22, "H": 0.56}
        c_v, i_v, a_v = cia[parts["C"]], cia[parts["I"]], cia[parts["A"]]
        iss = 1.0 - (1.0 - c_v) * (1.0 - i_v) * (1.0 - a_v)
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
        exploitability = 8.22 * av * ac * pr * ui
        if impact <= 0:
            return 0.0
        raw = (
            min(impact + exploitability, 10.0)
            if not scope_changed
            else min(1.08 * (impact + exploitability), 10.0)
        )
        return math.ceil(raw * 10) / 10
    except (KeyError, ValueError):
        return None


def _extract_affected_versions(adv: dict[str, Any]) -> str:
    """Build a compact JSON string summarising affected version ranges."""
    ranges: list[dict[str, Any]] = []
    for affected in adv.get("affected", []):
        for rng in affected.get("ranges", []):
            events = rng.get("events", [])
            ranges.append({"type": rng.get("type"), "events": events})
    return json.dumps(ranges)
