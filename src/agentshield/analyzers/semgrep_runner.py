"""Semgrep runner for AgentShield static analysis.

Runs semgrep CLI against an extracted package directory using AgentShield's
custom YAML rules (T3.1–T3.5). Gracefully degrades if semgrep is not installed.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
from pathlib import Path

from agentshield.core.models import Finding, ScanRequest, Severity

logger = logging.getLogger(__name__)

_RULES_DIR = Path(__file__).parent / "rules"

_SEMGREP_SEVERITY_MAP = {
    "ERROR": Severity.CRITICAL,
    "WARNING": Severity.HIGH,
    "INFO": Severity.MEDIUM,
}

_AGENTSHIELD_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}


def _semgrep_available() -> str | None:
    """Return the path to the semgrep binary, or None if not found."""
    return shutil.which("semgrep")


async def run_semgrep(package_dir: Path, request: ScanRequest) -> list[Finding]:
    """Run semgrep on *package_dir* and return AgentShield findings.

    Returns an empty list (no findings) if semgrep is not installed — the caller
    should not treat this as a clean bill of health.
    """
    semgrep_bin = _semgrep_available()
    if semgrep_bin is None:
        logger.info("semgrep not found on PATH — skipping semgrep analysis")
        return []

    if not _RULES_DIR.exists():
        logger.warning("AgentShield semgrep rules directory not found: %s", _RULES_DIR)
        return []

    cmd = [
        semgrep_bin,
        "scan",
        "--config",
        str(_RULES_DIR),
        "--json",
        "--no-rewrite-rule-ids",
        "--quiet",
        str(package_dir),
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
    except TimeoutError:
        logger.warning("semgrep timed out scanning %s", package_dir)
        return []
    except Exception as exc:
        logger.warning("semgrep failed: %s", exc)
        return []

    if stderr:
        logger.debug("semgrep stderr: %s", stderr.decode(errors="replace")[:500])

    if not stdout:
        return []

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        logger.warning("Could not parse semgrep JSON output: %s", exc)
        return []

    return _parse_semgrep_output(data, request)


def _parse_semgrep_output(data: dict, request: ScanRequest) -> list[Finding]:
    findings: list[Finding] = []
    results = data.get("results", [])

    seen_rules: set[str] = set()

    for result in results:
        check_id: str = result.get("check_id", "unknown")
        message: str = result.get("extra", {}).get("message", check_id)
        meta: dict = result.get("extra", {}).get("metadata", {})

        # Extract AgentShield rule ID from metadata (e.g. "T3.1")
        rule_id = meta.get("agentshield_rule", check_id)

        # Determine severity — prefer agentshield_severity metadata, then semgrep severity
        as_sev = meta.get("agentshield_severity")
        if as_sev and as_sev in _AGENTSHIELD_SEVERITY_MAP:
            severity = _AGENTSHIELD_SEVERITY_MAP[as_sev]
        else:
            semgrep_sev = result.get("extra", {}).get("severity", "WARNING").upper()
            severity = _SEMGREP_SEVERITY_MAP.get(semgrep_sev, Severity.MEDIUM)

        path = result.get("path", "")
        start_line = result.get("start", {}).get("line", 0)

        # Deduplicate by rule_id (one finding per rule per package)
        if rule_id in seen_rules:
            continue
        seen_rules.add(rule_id)

        _RULE_TITLES = {
            "T3.1": "Shell execution detected at install time",
            "T3.2": "Network call detected at install time",
            "T3.3": "Filesystem write detected at install time",
            "T3.4": "Obfuscated/encoded payload detected",
            "T3.5": "Credential harvesting pattern detected",
        }
        title = _RULE_TITLES.get(rule_id, message[:120])

        findings.append(
            Finding(
                rule_id=rule_id,
                title=title,
                description=message,
                severity=severity,
                source="semgrep",
                references=[],
                remediation=None,
                metadata={
                    "check_id": check_id,
                    "file": path,
                    "line": start_line,
                    "category": meta.get("category", ""),
                },
            )
        )

    return findings
