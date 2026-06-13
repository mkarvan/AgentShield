"""npm audit runner for AgentShield static analysis.

Runs 'npm audit --json' against a package directory containing a package-lock.json
or node_modules. Gracefully degrades when npm is not installed.
"""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
from pathlib import Path

from agentshield.core.models import Finding, ScanRequest, Severity

logger = logging.getLogger(__name__)

_NPM_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def _npm_available() -> str | None:
    return shutil.which("npm")


async def run_npm_audit(package_dir: Path, request: ScanRequest) -> list[Finding]:
    """Run 'npm audit --json' on *package_dir* and return findings.

    Returns an empty list if npm is not installed or no lockfile is found.
    """
    npm_bin = _npm_available()
    if npm_bin is None:
        logger.info("npm not found on PATH — skipping npm audit")
        return []

    # npm audit requires package-lock.json or yarn.lock
    has_lockfile = (
        (package_dir / "package-lock.json").exists()
        or (package_dir / "yarn.lock").exists()
        or (package_dir / "package.json").exists()
    )
    if not has_lockfile:
        logger.debug("No npm lockfile found in %s — skipping npm audit", package_dir)
        return []

    cmd = [npm_bin, "audit", "--json", "--prefix", str(package_dir)]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(package_dir),
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
    except asyncio.TimeoutError:
        logger.warning("npm audit timed out for %s", package_dir)
        return []
    except Exception as exc:
        logger.warning("npm audit failed: %s", exc)
        return []

    if not stdout:
        return []

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        logger.warning("Could not parse npm audit JSON: %s", exc)
        return []

    return _parse_npm_audit(data, request)


def _parse_npm_audit(data: dict, request: ScanRequest) -> list[Finding]:
    findings: list[Finding] = []
    vulnerabilities: dict = data.get("vulnerabilities", {})

    for pkg_name, vuln_info in vulnerabilities.items():
        severity_str: str = vuln_info.get("severity", "low").lower()
        severity = _NPM_SEVERITY_MAP.get(severity_str, Severity.LOW)

        via: list = vuln_info.get("via", [])
        cve_ids: list[str] = []
        for item in via:
            if isinstance(item, dict):
                source_id = item.get("source") or item.get("name") or ""
                cve = item.get("cve") or ""
                if cve:
                    cve_ids.append(str(cve))
                elif source_id:
                    cve_ids.append(str(source_id))

        rule_id = cve_ids[0] if cve_ids else f"npm:{pkg_name}"
        title = f"npm vulnerability in {pkg_name}"
        if cve_ids:
            title = f"{cve_ids[0]} in {pkg_name}"

        fix_info = vuln_info.get("fixAvailable")
        remediation: str | None = None
        if isinstance(fix_info, dict):
            remediation = f"Upgrade to {fix_info.get('name')} {fix_info.get('version')}"
        elif fix_info is True:
            remediation = "Run 'npm audit fix'"

        findings.append(Finding(
            rule_id=rule_id,
            title=title,
            description=vuln_info.get("url") or title,
            severity=severity,
            source="npm_audit",
            references=list({
                item.get("url", "") for item in via if isinstance(item, dict) and item.get("url")
            }),
            remediation=remediation,
            metadata={
                "package": pkg_name,
                "cves": cve_ids,
                "via": [v for v in via if isinstance(v, str)],
            },
        ))

    return findings
