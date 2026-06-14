"""License compliance checker — fetches license metadata from PyPI, npm, and crates.io."""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any

import httpx

from agentshield.core.models import Ecosystem, Finding, ScanRequest, Severity
from agentshield.core.retry import with_retry

if TYPE_CHECKING:
    from agentshield.core.config import LicensePolicy

logger = logging.getLogger(__name__)

_TIMEOUT = 10.0
_PYPI_BASE = "https://pypi.org/pypi"
_NPM_BASE = "https://registry.npmjs.org"
_CRATES_BASE = "https://crates.io/api/v1/crates"

# Common non-SPDX strings → canonical SPDX identifiers (lowercased keys).
_SPDX_ALIASES: dict[str, str] = {
    # GPL-2.0
    "gpl-2.0": "GPL-2.0-only",
    "gpl2": "GPL-2.0-only",
    "gplv2": "GPL-2.0-only",
    "gpl v2": "GPL-2.0-only",
    "gnu general public license v2": "GPL-2.0-only",
    "gnu general public license v2 (gplv2)": "GPL-2.0-only",
    "gnu general public license version 2": "GPL-2.0-only",
    "gpl-2.0+": "GPL-2.0-or-later",
    "gpl2+": "GPL-2.0-or-later",
    "gpl-2.0-or-later": "GPL-2.0-or-later",
    # GPL-3.0
    "gpl-3.0": "GPL-3.0-only",
    "gpl3": "GPL-3.0-only",
    "gplv3": "GPL-3.0-only",
    "gpl v3": "GPL-3.0-only",
    "gnu general public license v3": "GPL-3.0-only",
    "gnu general public license v3 (gplv3)": "GPL-3.0-only",
    "gnu general public license version 3": "GPL-3.0-only",
    "gpl-3.0+": "GPL-3.0-or-later",
    "gpl3+": "GPL-3.0-or-later",
    "gpl-3.0-or-later": "GPL-3.0-or-later",
    # AGPL-3.0
    "agpl-3.0": "AGPL-3.0-only",
    "agpl3": "AGPL-3.0-only",
    "agplv3": "AGPL-3.0-only",
    "agpl v3": "AGPL-3.0-only",
    "gnu affero general public license v3": "AGPL-3.0-only",
    "agpl-3.0+": "AGPL-3.0-or-later",
    "agpl-3.0-or-later": "AGPL-3.0-or-later",
    # LGPL
    "lgpl-2.0": "LGPL-2.0-only",
    "lgpl-2.1": "LGPL-2.1-only",
    "lgpl-3.0": "LGPL-3.0-only",
    # MIT
    "mit license": "MIT",
    "the mit license": "MIT",
    # Apache
    "apache 2.0": "Apache-2.0",
    "apache2": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    # BSD
    "bsd": "BSD-2-Clause",
    "bsd license": "BSD-2-Clause",
    "bsd 2-clause": "BSD-2-Clause",
    "bsd 3-clause": "BSD-3-Clause",
    "new bsd": "BSD-3-Clause",
    "simplified bsd": "BSD-2-Clause",
    # SSPL
    "sspl": "SSPL-1.0",
    "server side public license": "SSPL-1.0",
    # OSL
    "osl-3.0": "OSL-3.0",
    "open software license 3.0": "OSL-3.0",
    # EUPL
    "eupl-1.1": "EUPL-1.1",
    "european union public licence v1.1": "EUPL-1.1",
    "eupl-1.2": "EUPL-1.2",
    "european union public licence v1.2": "EUPL-1.2",
}

# PyPI Trove classifier → SPDX identifier.
_CLASSIFIER_MAP: dict[str, str] = {
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: GNU General Public License v2 (GPLv2)": "GPL-2.0-only",
    "License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)": "GPL-2.0-or-later",
    "License :: OSI Approved :: GNU General Public License v3 (GPLv3)": "GPL-3.0-only",
    "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)": "GPL-3.0-or-later",
    "License :: OSI Approved :: GNU Affero General Public License v3": "AGPL-3.0-only",
    "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)": "AGPL-3.0-or-later",
    "License :: OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)": "LGPL-2.0-only",
    "License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)": "LGPL-2.1-or-later",
    "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0-only",
    "License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)": "LGPL-3.0-or-later",
    "License :: OSI Approved :: BSD License": "BSD-2-Clause",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: European Union Public Licence 1.1 (EUPL 1.1)": "EUPL-1.1",
    "License :: OSI Approved :: European Union Public Licence 1.2 (EUPL 1.2)": "EUPL-1.2",
}

# Severity by license family.
_CRITICAL_LICENSES: frozenset[str] = frozenset(
    {
        "GPL-2.0-only",
        "GPL-2.0-or-later",
        "GPL-3.0-only",
        "GPL-3.0-or-later",
        "AGPL-3.0-only",
        "AGPL-3.0-or-later",
        "SSPL-1.0",
    }
)

_HIGH_LICENSES: frozenset[str] = frozenset(
    {
        "EUPL-1.1",
        "EUPL-1.2",
        "OSL-3.0",
        "LGPL-2.0-only",
        "LGPL-2.0-or-later",
        "LGPL-2.1-only",
        "LGPL-2.1-or-later",
        "LGPL-3.0-only",
        "LGPL-3.0-or-later",
        "MPL-2.0",
    }
)

# Strings that indicate the license is unknown or not machine-readable.
_UNKNOWN_MARKERS: frozenset[str] = frozenset(
    {
        "unknown",
        "see license",
        "see license in file",
        "see license in license",
        "see license file",
        "proprietary",
        "commercial",
        "other",
        "",
    }
)

# Regex to split SPDX expressions on OR / AND / WITH operators or Cargo's "/" separator.
_SPDX_SPLIT_RE = re.compile(r"\s+(?:OR|AND|WITH)\s+|/", re.IGNORECASE)


def normalize_spdx(raw: str) -> list[str]:
    """Normalize a raw license string to a list of SPDX identifiers.

    Handles:
    - SPDX expressions: "MIT OR Apache-2.0" → ["MIT", "Apache-2.0"]
    - Cargo "/" style: "MIT/Apache-2.0" → ["MIT", "Apache-2.0"]
    - Common aliases: "GPLv2" → ["GPL-2.0-only"]
    - Empty / unknown inputs → []
    """
    stripped = raw.strip()
    if stripped.lower() in _UNKNOWN_MARKERS:
        return []

    parts = [p.strip("() \t\n") for p in _SPDX_SPLIT_RE.split(stripped)]
    ids: list[str] = []
    for part in parts:
        part = part.strip()
        if not part:
            continue
        # Try alias table first (lowercased lookup).
        normalized = _SPDX_ALIASES.get(part.lower())
        ids.append(normalized if normalized is not None else part)

    return ids


def _severity_for_license(spdx_id: str) -> Severity:
    if spdx_id in _CRITICAL_LICENSES:
        return Severity.CRITICAL
    if spdx_id in _HIGH_LICENSES:
        return Severity.HIGH
    return Severity.MEDIUM


class LicenseChecker:
    """Checks a package's license against a configured LicensePolicy."""

    def __init__(self, policy: LicensePolicy) -> None:
        self.policy = policy

    async def check(self, request: ScanRequest) -> list[Finding]:
        """Fetch license metadata and return findings per policy. Never raises."""
        if self.policy.mode == "disabled":
            return []

        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            try:
                licenses = await self._fetch_licenses(request, client)
            except Exception as exc:
                logger.debug(
                    "License fetch failed for %s/%s: %s",
                    request.ecosystem.value,
                    request.package,
                    exc,
                )
                return []

        if not licenses:
            return []

        return self._evaluate(request, licenses)

    # ── fetchers ─────────────────────────────────────────────────────────────

    async def _fetch_licenses(self, request: ScanRequest, client: httpx.AsyncClient) -> list[str]:
        if request.ecosystem == Ecosystem.PYPI:
            return await _fetch_pypi_license(request.package, request.version, client)
        if request.ecosystem == Ecosystem.NPM:
            return await _fetch_npm_license(request.package, request.version, client)
        if request.ecosystem == Ecosystem.CARGO:
            return await _fetch_cargo_license(request.package, request.version, client)
        return []

    # ── policy evaluation ─────────────────────────────────────────────────────

    def _evaluate(self, request: ScanRequest, licenses: list[str]) -> list[Finding]:
        denied_lower = {lic.lower() for lic in self.policy.denied}
        allowed_lower = {lic.lower() for lic in self.policy.allowed}

        findings: list[Finding] = []
        for spdx_id in licenses:
            spdx_lower = spdx_id.lower()

            if self.policy.mode == "denylist":
                if spdx_lower in denied_lower:
                    findings.append(_make_finding(request, spdx_id))

            elif self.policy.mode == "allowlist":
                if spdx_lower not in allowed_lower:
                    findings.append(_make_finding(request, spdx_id, not_in_allowlist=True))

            elif self.policy.mode == "permissive-only":
                is_copyleft = (
                    spdx_lower in denied_lower
                    or spdx_id in _CRITICAL_LICENSES
                    or spdx_id in _HIGH_LICENSES
                )
                if is_copyleft:
                    findings.append(_make_finding(request, spdx_id))

        # Dedup per spdx_id, keeping highest severity.
        seen: dict[str, Finding] = {}
        for f in findings:
            key = str(f.metadata.get("spdx_id", f.rule_id))
            existing = seen.get(key)
            if existing is None or f.severity > existing.severity:
                seen[key] = f
        return list(seen.values())


# ── module-level helpers ──────────────────────────────────────────────────────


async def _fetch_pypi_license(
    package: str, version: str | None, client: httpx.AsyncClient
) -> list[str]:
    url = f"{_PYPI_BASE}/{package}/{version}/json" if version else f"{_PYPI_BASE}/{package}/json"

    async def _do() -> dict[str, Any]:
        resp = await client.get(url)
        resp.raise_for_status()
        result: dict[str, Any] = resp.json()
        return result

    data = await with_retry(_do, label=f"PyPI license {package}")
    info: dict[str, Any] = data.get("info") or {}

    # Trove classifiers are more reliable than the free-text info.license field.
    classifiers: list[Any] = info.get("classifiers") or []
    spdx_from_classifiers: list[str] = [
        _CLASSIFIER_MAP[c] for c in classifiers if c in _CLASSIFIER_MAP
    ]
    if spdx_from_classifiers:
        return spdx_from_classifiers

    raw_license = str(info.get("license") or "").strip()
    return normalize_spdx(raw_license) if raw_license else []


async def _fetch_npm_license(
    package: str, version: str | None, client: httpx.AsyncClient
) -> list[str]:
    ver = version or "latest"
    url = f"{_NPM_BASE}/{package}/{ver}"

    async def _do() -> dict[str, Any]:
        resp = await client.get(url)
        resp.raise_for_status()
        result: dict[str, Any] = resp.json()
        return result

    data = await with_retry(_do, label=f"npm license {package}")
    raw: Any = data.get("license") or ""

    # npm sometimes encodes license as {"type": "MIT", "url": "..."}.
    if isinstance(raw, dict):
        raw = raw.get("type") or ""

    return normalize_spdx(str(raw)) if raw else []


async def _fetch_cargo_license(
    package: str, version: str | None, client: httpx.AsyncClient
) -> list[str]:
    if version is None:
        url = f"{_CRATES_BASE}/{package}"

        async def _do_meta() -> dict[str, Any]:
            resp = await client.get(url, headers={"User-Agent": "agentshield/0.3"})
            resp.raise_for_status()
            result: dict[str, Any] = resp.json()
            return result

        meta = await with_retry(_do_meta, label=f"Cargo license meta {package}")
        crate_info: dict[str, Any] = meta.get("crate") or {}
        raw_license = str(crate_info.get("license") or "").strip()
    else:
        url = f"{_CRATES_BASE}/{package}/{version}"

        async def _do_ver() -> dict[str, Any]:
            resp = await client.get(url, headers={"User-Agent": "agentshield/0.3"})
            resp.raise_for_status()
            result: dict[str, Any] = resp.json()
            return result

        ver_data = await with_retry(_do_ver, label=f"Cargo license {package}")
        version_info: dict[str, Any] = ver_data.get("version") or {}
        raw_license = str(version_info.get("license") or "").strip()

    return normalize_spdx(raw_license) if raw_license else []


def _make_finding(
    request: ScanRequest,
    spdx_id: str,
    *,
    not_in_allowlist: bool = False,
) -> Finding:
    severity = _severity_for_license(spdx_id)

    if not_in_allowlist:
        title = f"License '{spdx_id}' not in allowlist"
        description = (
            f"Package '{request.package}' uses license '{spdx_id}', "
            f"which is not in the configured allowlist."
        )
    else:
        title = f"Denied license: {spdx_id}"
        description = (
            f"Package '{request.package}' uses license '{spdx_id}', which is on the denied list."
        )

    return Finding(
        rule_id="L1.1",
        title=title,
        description=description,
        severity=severity,
        source="license_checker",
        references=[f"https://spdx.org/licenses/{spdx_id}.html"],
        metadata={"spdx_id": spdx_id, "package": request.package},
    )
