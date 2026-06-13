"""Bandit runner for AgentShield static analysis.

Runs bandit against Python source in an extracted package directory, focusing on
security-relevant tests. Gracefully degrades if bandit is not installed.
"""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
from pathlib import Path

from agentshield.core.models import Finding, ScanRequest, Severity

logger = logging.getLogger(__name__)

# Bandit test IDs most relevant to install-time threats
_RELEVANT_TESTS = [
    "B102",  # exec used
    "B103",  # setting permissions
    "B104",  # hardcoded bind all interfaces
    "B105",  # hardcoded password string
    "B106",  # hardcoded password funcarg
    "B107",  # hardcoded password default
    "B108",  # probable insecure usage of temp file/directory
    "B301",  # pickle
    "B302",  # marshal
    "B303",  # MD5
    "B307",  # eval
    "B310",  # urllib.urlopen
    "B311",  # random
    "B312",  # telnetlib
    "B314",  # xml.etree.ElementTree
    "B315",  # xml.etree.cElementTree
    "B316",  # xml.etree.ElementTree
    "B317",  # xml.etree.cElementTree
    "B318",  # xml.dom.minidom
    "B319",  # xml.sax
    "B320",  # xml.etree.ElementTree
    "B321",  # ftplib
    "B322",  # input
    "B323",  # unverified_context
    "B401",  # import_telnetlib
    "B402",  # import_ftplib
    "B403",  # import_pickle
    "B404",  # import_subprocess
    "B405",  # import_xml_etree
    "B406",  # import_xml_sax
    "B407",  # import_xml_expat
    "B408",  # import_xml_minidom
    "B409",  # import_xml_pulldom
    "B411",  # import_xmlrpclib
    "B412",  # import_httpoxy
    "B502",  # ssl_with_bad_version
    "B503",  # ssl_with_bad_defaults
    "B504",  # ssl_with_no_version
    "B505",  # weak_cryptographic_key
    "B506",  # yaml_load
    "B601",  # paramiko_calls
    "B602",  # subprocess_popen_with_shell_equals_true
    "B603",  # subprocess_without_shell_equals_true
    "B604",  # any_other_function_with_shell_equals_true
    "B605",  # start_process_with_a_shell
    "B606",  # start_process_with_no_shell
    "B607",  # start_process_with_partial_path
    "B608",  # hardcoded_sql_expressions
    "B609",  # linux_commands_wildcard_injection
    "B610",  # django_extra_used
    "B611",  # django_rawsql_used
]

_BANDIT_SEVERITY_MAP: dict[str, Severity] = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNDEFINED": Severity.INFO,
}

_RULE_ID_FOR_BANDIT: dict[str, str] = {
    "B102": "T3.1",  # exec
    "B307": "T3.1",  # eval
    "B602": "T3.1",  # subprocess with shell=True
    "B603": "T3.1",  # subprocess
    "B605": "T3.1",  # start_process_with_a_shell
    "B310": "T3.2",  # urllib.urlopen
    "B312": "T3.2",  # telnetlib (network)
    "B321": "T3.2",  # ftplib
}


def _bandit_available() -> str | None:
    return shutil.which("bandit")


async def run_bandit(package_dir: Path, request: ScanRequest) -> list[Finding]:
    """Run bandit on *package_dir* and return AgentShield findings.

    Returns an empty list if bandit is not installed.
    """
    bandit_bin = _bandit_available()
    if bandit_bin is None:
        logger.info("bandit not found on PATH — skipping bandit analysis")
        return []

    tests_arg = ",".join(_RELEVANT_TESTS)
    cmd = [
        bandit_bin,
        "-r",
        "--format", "json",
        "--tests", tests_arg,
        "--exit-zero",
        str(package_dir),
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
    except asyncio.TimeoutError:
        logger.warning("bandit timed out scanning %s", package_dir)
        return []
    except Exception as exc:
        logger.warning("bandit failed: %s", exc)
        return []

    if not stdout:
        return []

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        logger.warning("Could not parse bandit JSON output: %s", exc)
        return []

    return _parse_bandit_output(data)


def _parse_bandit_output(data: dict) -> list[Finding]:
    findings: list[Finding] = []
    results: list[dict] = data.get("results", [])

    seen: set[str] = set()

    for issue in results:
        test_id: str = issue.get("test_id", "")
        test_name: str = issue.get("test_name", test_id)
        issue_text: str = issue.get("issue_text", "")
        issue_sev: str = issue.get("issue_severity", "UNDEFINED").upper()
        filename: str = issue.get("filename", "")
        line: int = issue.get("line_number", 0)

        # Map bandit test ID to AgentShield rule ID where possible
        rule_id = _RULE_ID_FOR_BANDIT.get(test_id, f"bandit:{test_id}")
        severity = _BANDIT_SEVERITY_MAP.get(issue_sev, Severity.LOW)

        # Suppress INFO-level bandit findings to reduce noise
        if severity == Severity.INFO:
            continue

        # Deduplicate by rule_id
        if rule_id in seen:
            continue
        seen.add(rule_id)

        findings.append(Finding(
            rule_id=rule_id,
            title=test_name.replace("_", " ").title(),
            description=issue_text,
            severity=severity,
            source="bandit",
            references=[],
            remediation=None,
            metadata={
                "bandit_test_id": test_id,
                "file": filename,
                "line": line,
            },
        ))

    return findings
