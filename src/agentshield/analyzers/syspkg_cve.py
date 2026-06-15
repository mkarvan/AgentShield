"""CVE scanning for system packages.

Queries OSV (primary) and distro-specific security trackers (supplementary)
to find known vulnerabilities in system packages detected by syspkg_detector.

v0.9.0 — integrates with the existing cache infrastructure and severity policy.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any

import aiosqlite
import httpx

from agentshield.analyzers.syspkg_detector import SysPkgWarning
from agentshield.core.models import Finding, Severity
from agentshield.core.retry import with_retry

logger = logging.getLogger(__name__)

OSV_API = "https://api.osv.dev/v1/query"

# ── manager → OSV ecosystem mapping ─────────────────────────────────────────

_MANAGER_ECOSYSTEMS: dict[str, list[str]] = {
    "apt-get": ["Debian", "Ubuntu"],
    "apt": ["Debian", "Ubuntu"],
    "yum": ["AlmaLinux", "Rocky Linux"],
    "dnf": ["AlmaLinux", "Rocky Linux"],
    "brew": [],  # no OSV ecosystem; supplementary Homebrew audit only
    "apk": ["Alpine"],
    "pacman": [],  # Arch Linux not in OSV
    "zypper": ["SUSE"],
    "pkg": [],  # FreeBSD not in OSV
    "emerge": [],  # Gentoo not in OSV
    "snap": ["Ubuntu"],
    "flatpak": [],  # no direct OSV ecosystem
}

# OSV uses MODERATE; NVD uses MEDIUM — normalise both
_SEVERITY_RATING_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "NONE": Severity.INFO,
}

# ── supplementary tracker URLs ───────────────────────────────────────────────

_UBUNTU_CVE_API = "https://ubuntu.com/security/cves.json"
_REDHAT_CVE_API = "https://access.redhat.com/hydra/rest/securitydata/cve.json"
_HOMEBREW_FORMULAE_API = "https://formulae.brew.sh/api/formula/{pkg}.json"

# ── cache DDL ────────────────────────────────────────────────────────────────

_SYSPKG_CVE_DDL = """\
CREATE TABLE IF NOT EXISTS syspkg_cve_cache (
    id            TEXT PRIMARY KEY,
    package       TEXT NOT NULL,
    manager       TEXT NOT NULL,
    findings_json TEXT NOT NULL,
    cached_at     INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_syspkg_cve_expires ON syspkg_cve_cache(expires_at);
"""

# Default cache TTL: 6 hours (system packages change less frequently)
_DEFAULT_TTL = 6 * 3600


class SysPkgCVEScanner:
    """Scan system packages for known CVEs via OSV + distro trackers."""

    def __init__(self, db_path: Path, *, ttl: int = _DEFAULT_TTL) -> None:
        self.db_path = db_path
        self.ttl = ttl

    async def scan_warnings(self, warnings: list[SysPkgWarning]) -> list[Finding]:
        """Scan all packages from syspkg warnings for CVEs.

        Returns deduplicated findings across all packages and sources.
        """
        tasks: list[Any] = []
        for w in warnings:
            for pkg in w.packages:
                tasks.append(self._scan_package(pkg, w.manager))

        if not tasks:
            return []

        results = await asyncio.gather(*tasks, return_exceptions=True)
        all_findings: list[Finding] = []
        for r in results:
            if isinstance(r, list):
                all_findings.extend(r)
            elif isinstance(r, Exception):
                logger.warning("SysPkg CVE scan failed: %s", r)

        return _dedupe_findings(all_findings)

    async def _scan_package(self, package: str, manager: str) -> list[Finding]:
        """Scan a single package across all applicable sources."""
        # Check cache first
        cached = await self._cache_get(package, manager)
        if cached is not None:
            logger.debug("SysPkg CVE cache hit for %s (%s)", package, manager)
            return cached

        findings: list[Finding] = []

        # ── Primary: OSV queries ─────────────────────────────────────────
        ecosystems = _MANAGER_ECOSYSTEMS.get(manager, [])
        if ecosystems:
            osv_tasks = [self._query_osv(package, eco) for eco in ecosystems]
            osv_results = await asyncio.gather(*osv_tasks, return_exceptions=True)
            for r in osv_results:
                if isinstance(r, list):
                    findings.extend(r)
                elif isinstance(r, Exception):
                    logger.debug("OSV query failed for %s: %s", package, r)

        # ── Supplementary: distro-specific trackers ──────────────────────
        supplementary_tasks: list[Any] = []

        if manager in ("apt-get", "apt", "snap"):
            supplementary_tasks.append(self._query_ubuntu_cve(package))

        if manager in ("yum", "dnf"):
            supplementary_tasks.append(self._query_redhat_cve(package))

        if manager == "brew":
            supplementary_tasks.append(self._query_homebrew_audit(package))

        if supplementary_tasks:
            sup_results = await asyncio.gather(*supplementary_tasks, return_exceptions=True)
            for r in sup_results:
                if isinstance(r, list):
                    findings.extend(r)
                elif isinstance(r, Exception):
                    logger.debug("Supplementary tracker query failed for %s: %s", package, r)

        deduped = _dedupe_findings(findings)
        await self._cache_set(package, manager, deduped)
        return deduped

    # ── OSV (primary) ────────────────────────────────────────────────────────

    async def _query_osv(self, package: str, ecosystem: str) -> list[Finding]:
        """Query OSV for a package in a specific ecosystem."""
        payload: dict[str, Any] = {
            "package": {
                "name": package,
                "ecosystem": ecosystem,
            }
        }

        async def _do() -> list[Finding]:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(OSV_API, json=payload)
                resp.raise_for_status()
                data = resp.json()
            return [_osv_vuln_to_finding(v, ecosystem) for v in data.get("vulns", [])]

        return await with_retry(_do, label=f"OSV syspkg {package}@{ecosystem}")

    # ── Ubuntu CVE tracker (supplementary) ───────────────────────────────────

    async def _query_ubuntu_cve(self, package: str) -> list[Finding]:
        """Query Ubuntu Security CVE API for a package."""

        async def _do() -> list[Finding]:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    _UBUNTU_CVE_API,
                    params={"package": package, "limit": "20"},
                )
                resp.raise_for_status()
                data = resp.json()

            findings: list[Finding] = []
            for entry in data.get("cves", []):
                cve_id = entry.get("id", "")
                if not cve_id:
                    continue
                priority = entry.get("ubuntu_priority", "medium").upper()
                severity = _SEVERITY_RATING_MAP.get(priority, Severity.MEDIUM)
                findings.append(
                    Finding(
                        rule_id=cve_id,
                        title=entry.get("description", cve_id)[:200],
                        description=entry.get("description", ""),
                        severity=severity,
                        source="ubuntu_cve",
                        references=[f"https://ubuntu.com/security/{cve_id}"],
                        cvss_score=_safe_float(entry.get("cvss3")),
                        remediation=entry.get("ubuntu_description"),
                    )
                )
            return findings

        return await with_retry(_do, label=f"Ubuntu CVE {package}")

    # ── Red Hat CVE tracker (supplementary) ──────────────────────────────────

    async def _query_redhat_cve(self, package: str) -> list[Finding]:
        """Query Red Hat Security Data API for a package."""

        async def _do() -> list[Finding]:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    _REDHAT_CVE_API,
                    params={"package": package, "per_page": "20"},
                )
                resp.raise_for_status()
                data = resp.json()

            findings: list[Finding] = []
            if not isinstance(data, list):
                return findings

            for entry in data:
                cve_id = entry.get("CVE", "")
                if not cve_id:
                    continue
                severity_str = entry.get("severity", "moderate").upper()
                severity = _SEVERITY_RATING_MAP.get(severity_str, Severity.MEDIUM)
                findings.append(
                    Finding(
                        rule_id=cve_id,
                        title=entry.get("bugzilla_description", cve_id)[:200],
                        description=entry.get("bugzilla_description", ""),
                        severity=severity,
                        source="redhat_cve",
                        references=[
                            r
                            for r in [
                                entry.get("resource_url"),
                                entry.get("bugzilla"),
                            ]
                            if r
                        ],
                        cvss_score=_safe_float(entry.get("cvss3_score")),
                    )
                )
            return findings

        return await with_retry(_do, label=f"Red Hat CVE {package}")

    # ── Homebrew audit (supplementary) ───────────────────────────────────────

    async def _query_homebrew_audit(self, package: str) -> list[Finding]:
        """Check Homebrew Formulae API for deprecation/disability notices.

        Homebrew doesn't have a dedicated CVE API, but the formulae API
        exposes deprecation and disability metadata that can signal issues.
        """

        async def _do() -> list[Finding]:
            url = _HOMEBREW_FORMULAE_API.format(pkg=package)
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url)
                if resp.status_code == 404:
                    return []  # formula not found — not an error
                resp.raise_for_status()
                data = resp.json()

            findings: list[Finding] = []
            if data.get("deprecated"):
                findings.append(
                    Finding(
                        rule_id=f"BREW-DEPRECATED-{package}",
                        title=f"Homebrew formula '{package}' is deprecated",
                        description=data.get("deprecation_reason", "Formula is deprecated"),
                        severity=Severity.MEDIUM,
                        source="homebrew_audit",
                        references=[f"https://formulae.brew.sh/formula/{package}"],
                    )
                )
            if data.get("disabled"):
                findings.append(
                    Finding(
                        rule_id=f"BREW-DISABLED-{package}",
                        title=f"Homebrew formula '{package}' is disabled",
                        description=data.get("disable_reason", "Formula is disabled"),
                        severity=Severity.HIGH,
                        source="homebrew_audit",
                        references=[f"https://formulae.brew.sh/formula/{package}"],
                    )
                )
            return findings

        try:
            return await with_retry(_do, label=f"Homebrew audit {package}")
        except httpx.HTTPStatusError:
            return []

    # ── Cache layer ──────────────────────────────────────────────────────────

    async def _ensure_table(self, db: aiosqlite.Connection) -> None:
        for stmt in _SYSPKG_CVE_DDL.strip().split(";"):
            stmt = stmt.strip()
            if stmt:
                await db.execute(stmt)

    async def _cache_get(self, package: str, manager: str) -> list[Finding] | None:
        key = _cache_key(package, manager)
        now = int(time.time())
        async with aiosqlite.connect(self.db_path) as db:
            await self._ensure_table(db)
            async with db.execute(
                "SELECT findings_json FROM syspkg_cve_cache WHERE id = ? AND expires_at > ?",
                (key, now),
            ) as cur:
                row = await cur.fetchone()
        if row is None:
            return None
        try:
            return [Finding.model_validate(f) for f in json.loads(row[0])]
        except Exception:
            return None  # corrupted cache entry — re-scan

    async def _cache_set(self, package: str, manager: str, findings: list[Finding]) -> None:
        key = _cache_key(package, manager)
        now = int(time.time())
        findings_json = json.dumps([f.model_dump(mode="json") for f in findings])
        async with aiosqlite.connect(self.db_path) as db:
            await self._ensure_table(db)
            await db.execute(
                "INSERT OR REPLACE INTO syspkg_cve_cache VALUES (?,?,?,?,?,?)",
                (key, package, manager, findings_json, now, now + self.ttl),
            )
            await db.commit()


# ── helpers ──────────────────────────────────────────────────────────────────


def _cache_key(package: str, manager: str) -> str:
    raw = f"syspkg:{manager}:{package}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _osv_vuln_to_finding(vuln: dict[str, Any], ecosystem: str) -> Finding:
    """Convert an OSV vulnerability object to a Finding."""
    severity, cvss_score = _extract_osv_severity(vuln)

    vuln_type = vuln.get("database_specific", {}).get("type", "")
    if vuln_type == "MALICIOUS":
        severity = Severity.CRITICAL
        rule_id = f"SP-MAL-{vuln.get('id', 'UNKNOWN')}"
    else:
        rule_id = vuln.get("id", "UNKNOWN")

    return Finding(
        rule_id=rule_id,
        title=vuln.get("summary", "Unknown vulnerability"),
        description=vuln.get("details", ""),
        severity=severity,
        source=f"osv/{ecosystem.lower()}",
        references=[r.get("url", "") for r in vuln.get("references", []) if r.get("url")],
        cvss_score=cvss_score,
        remediation=_extract_remediation(vuln),
        metadata={"ecosystem": ecosystem, "manager": "syspkg"},
    )


def _extract_osv_severity(vuln: dict[str, Any]) -> tuple[Severity, float | None]:
    """Return (severity, cvss_score) for an OSV vuln object."""
    cvss_score: float | None = None
    severity = Severity.MEDIUM  # safe default

    # database_specific.severity is the most reliable field
    db_sev = vuln.get("database_specific", {}).get("severity", "")
    if db_sev:
        severity = _SEVERITY_RATING_MAP.get(db_sev.upper(), Severity.MEDIUM)

    # Walk severity[] array for CVSS vector
    for sev_entry in vuln.get("severity", []):
        if sev_entry.get("type") in ("CVSS_V3", "CVSS_V3_1"):
            score = _parse_cvss3_score(sev_entry.get("score", ""))
            if score is not None:
                cvss_score = score
                if not db_sev:
                    severity = _severity_from_cvss(score)

    return severity, cvss_score


def _severity_from_cvss(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


def _parse_cvss3_score(vector: str) -> float | None:
    """Extract the numeric base score from a CVSS v3 vector string.

    Falls back to computing the score from vector components if the
    score is not directly embedded. Uses the same algorithm as osv.py.
    """
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
    except (KeyError, ValueError, TypeError):
        return None


def _extract_remediation(vuln: dict[str, Any]) -> str | None:
    for affected in vuln.get("affected", []):
        for r in affected.get("ranges", []):
            for event in r.get("events", []):
                if "fixed" in event:
                    return f"Upgrade to >= {event['fixed']}"
    return None


def _safe_float(val: Any) -> float | None:
    """Safely convert a value to float, returning None on failure."""
    if val is None:
        return None
    try:
        f = float(val)
        return f if 0.0 <= f <= 10.0 else None
    except (ValueError, TypeError):
        return None


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Deduplicate by rule_id, keeping the highest severity."""
    seen: dict[str, Finding] = {}
    for f in findings:
        existing = seen.get(f.rule_id)
        if existing is None or f.severity > existing.severity:
            seen[f.rule_id] = f
    return list(seen.values())
