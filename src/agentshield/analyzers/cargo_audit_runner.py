"""cargo audit runner for AgentShield static analysis.

Runs 'cargo audit --json' against a package directory containing a Cargo.lock.
Gracefully degrades when cargo is not installed or no Cargo.lock is present.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
from pathlib import Path

from agentshield.core.models import Finding, ScanRequest, Severity

logger = logging.getLogger(__name__)

_CVSS_TO_SEVERITY = [
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (0.1, Severity.LOW),
]


def _cvss_to_severity(score: float | None) -> Severity:
    if score is None:
        return Severity.MEDIUM
    for threshold, sev in _CVSS_TO_SEVERITY:
        if score >= threshold:
            return sev
    return Severity.INFO


def _cargo_audit_available() -> str | None:
    # cargo-audit installs as a cargo subcommand; 'cargo audit' is the invocation
    return shutil.which("cargo")


async def run_cargo_audit(package_dir: Path, request: ScanRequest) -> list[Finding]:
    """Run 'cargo audit --json' on *package_dir* and return findings.

    Returns an empty list if cargo is not installed or no Cargo.lock is found.
    """
    cargo_bin = _cargo_audit_available()
    if cargo_bin is None:
        logger.info("cargo not found on PATH — skipping cargo audit")
        return []

    # cargo audit requires a Cargo.lock file
    lockfile = package_dir / "Cargo.lock"
    if not lockfile.exists():
        # Check one level deep (sdist unpacks into a subdirectory)
        for subdir in package_dir.iterdir():
            if subdir.is_dir() and (subdir / "Cargo.lock").exists():
                lockfile = subdir / "Cargo.lock"
                package_dir = subdir
                break
        else:
            logger.debug("No Cargo.lock found in %s — skipping cargo audit", package_dir)
            return []

    cmd = [cargo_bin, "audit", "--json", "--file", str(lockfile)]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(package_dir),
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=90)
    except TimeoutError:
        logger.warning("cargo audit timed out for %s", package_dir)
        return []
    except Exception as exc:
        logger.warning("cargo audit failed: %s", exc)
        return []

    if not stdout:
        return []

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        logger.warning("Could not parse cargo audit JSON: %s", exc)
        return []

    return _parse_cargo_audit(data, request)


def _parse_cargo_audit(data: dict, request: ScanRequest) -> list[Finding]:
    findings: list[Finding] = []
    vulnerabilities: list[dict] = data.get("vulnerabilities", {}).get("list", [])

    for vuln in vulnerabilities:
        advisory: dict = vuln.get("advisory", {})
        vuln_id: str = advisory.get("id", "UNKNOWN")
        title: str = advisory.get("title", vuln_id)
        description: str = advisory.get("description", "")
        cvss_str: str | None = advisory.get("cvss")
        url: str = advisory.get("url", "")

        cvss_score: float | None = None
        if cvss_str:
            import contextlib

            with contextlib.suppress(ValueError, AttributeError):
                cvss_score = float(cvss_str.split("/")[-1]) if "/" in cvss_str else float(cvss_str)

        severity = _cvss_to_severity(cvss_score)

        affected: dict = vuln.get("package", {})
        pkg_name = affected.get("name", request.package)
        pkg_version = affected.get("version", "")

        patched: list[str] = advisory.get("patched_versions", [])
        remediation = f"Upgrade to {patched[0]}" if patched else None

        findings.append(
            Finding(
                rule_id=vuln_id,
                title=f"{vuln_id}: {title}",
                description=description,
                severity=severity,
                source="cargo_audit",
                references=[url] if url else [],
                cvss_score=cvss_score,
                remediation=remediation,
                metadata={
                    "package": pkg_name,
                    "version": pkg_version,
                    "aliases": advisory.get("aliases", []),
                },
            )
        )

    return findings
