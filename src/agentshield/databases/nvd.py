"""NVD API v2 client for CVE enrichment.

Rate limits (rolling 30-second window):
  • Without API key : 5 requests
  • With API key    : 50 requests

Pass an API key via the [api] section of config.toml or the NVD_API_KEY
environment variable to get the higher limit.

Reference: https://nvd.nist.gov/developers/vulnerabilities
"""

from __future__ import annotations

import asyncio
import logging
import time

import httpx

from agentshield.core.models import Ecosystem, Finding, ScanRequest, Severity

logger = logging.getLogger(__name__)

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_ECOSYSTEM_MAP = {
    Ecosystem.PYPI: "PyPI",
    Ecosystem.NPM: "npm",
    Ecosystem.CARGO: "crates.io",
}

_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "NONE": Severity.INFO,
}

# Rolling window parameters
_WINDOW_SECS = 30
_LIMIT_NO_KEY = 5
_LIMIT_WITH_KEY = 50

# Max results to request per query (NVD API cap is 2000)
_RESULTS_PER_PAGE = 100


class NVDRateLimiter:
    """Token-bucket style sliding-window rate limiter."""

    def __init__(self, limit: int, window: float = _WINDOW_SECS) -> None:
        self._limit = limit
        self._window = window
        self._calls: list[float] = []
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            cutoff = now - self._window
            self._calls = [t for t in self._calls if t > cutoff]

            if len(self._calls) >= self._limit:
                # Wait until the oldest call falls out of the window
                wait = self._calls[0] - cutoff
                if wait > 0:
                    await asyncio.sleep(wait)
                # Remove calls that have now expired
                now2 = time.monotonic()
                self._calls = [t for t in self._calls if t > now2 - self._window]

            self._calls.append(time.monotonic())


class NVDClient:
    """Queries the NVD CVE API v2 to find vulnerabilities for a package."""

    def __init__(self, api_key: str | None = None) -> None:
        self._api_key = api_key
        limit = _LIMIT_WITH_KEY if api_key else _LIMIT_NO_KEY
        self._limiter = NVDRateLimiter(limit)

    async def scan(self, request: ScanRequest) -> list[Finding]:
        try:
            return await self._fetch_findings(request)
        except Exception as exc:
            logger.warning("NVD scan failed for %s: %s", request.package, exc)
            return []

    async def _fetch_findings(self, request: ScanRequest) -> list[Finding]:
        await self._limiter.acquire()

        headers: dict[str, str] = {}
        if self._api_key:
            headers["apiKey"] = self._api_key

        params: dict[str, str | int] = {
            "keywordSearch": request.package,
            "keywordExactMatch": "",
            "resultsPerPage": _RESULTS_PER_PAGE,
        }

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(NVD_CVE_URL, params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()

        vulns = data.get("vulnerabilities", [])
        findings: list[Finding] = []

        for item in vulns:
            cve = item.get("cve", {})
            finding = _cve_to_finding(cve, request.package)
            if finding is not None:
                findings.append(finding)

        return findings


def _cve_to_finding(cve: dict, package: str) -> Finding | None:
    cve_id: str = cve.get("id", "")
    if not cve_id:
        return None

    descriptions = cve.get("descriptions", [])
    description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

    # Only include CVEs where the package name appears in the description
    # This reduces false positives from broad keyword searches
    if package.lower() not in description.lower():
        return None

    severity, cvss_score = _extract_metrics(cve)
    if severity == Severity.INFO:
        return None  # Skip noise-level NVD results

    summary = description[:200].rstrip() if description else cve_id
    references = [r["url"] for r in cve.get("references", []) if r.get("url")]

    return Finding(
        rule_id=cve_id,
        title=summary,
        description=description,
        severity=severity,
        source="nvd",
        references=references,
        cvss_score=cvss_score,
        remediation=None,
    )


def _extract_metrics(cve: dict) -> tuple[Severity, float | None]:
    metrics = cve.get("metrics", {})

    # Prefer CVSSv3.1, then 3.0, then 2.0
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if not entries:
            continue
        cvss_data = entries[0].get("cvssData", {})
        score = cvss_data.get("baseScore")
        severity_str = cvss_data.get("baseSeverity", "")
        severity = _SEVERITY_MAP.get(severity_str.upper(), Severity.MEDIUM)
        return severity, float(score) if score is not None else None

    return Severity.MEDIUM, None
