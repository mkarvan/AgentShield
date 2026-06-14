"""Unit tests for the CLI layer.

All network calls are mocked via respx.
"""

from __future__ import annotations

from unittest.mock import patch

import respx
from httpx import Response
from typer.testing import CliRunner

from agentshield.cli import app

OSV_URL = "https://api.osv.dev/v1/query"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
runner = CliRunner()


# ── scan command ──────────────────────────────────────────────────────────────


@respx.mock
def test_scan_clean_package_exits_0(tmp_path):
    respx.post(OSV_URL).mock(return_value=Response(200, json={"vulns": []}))
    with patch("agentshield.analyzers.typosquatting.TyposquattingChecker._load", return_value=[]):
        result = runner.invoke(
            app,
            [
                "scan",
                "clean-pkg",
                "--ecosystem",
                "pypi",
                "--config",
                str(tmp_path / "nonexistent.toml"),
            ],
        )
    assert result.exit_code == 0
    assert "ALLOW" in result.output or "LOG_ASYNC" in result.output


@respx.mock
def test_scan_critical_vuln_exits_1(tmp_path):
    respx.post(OSV_URL).mock(
        return_value=Response(
            200,
            json={
                "vulns": [
                    {
                        "id": "CVE-2024-TEST",
                        "summary": "Critical vuln",
                        "details": "",
                        "severity": [],
                        "database_specific": {"severity": "CRITICAL"},
                        "references": [],
                        "affected": [],
                    }
                ]
            },
        )
    )
    with patch("agentshield.analyzers.typosquatting.TyposquattingChecker._load", return_value=[]):
        result = runner.invoke(
            app,
            [
                "scan",
                "vuln-pkg==1.0.0",
                "--ecosystem",
                "pypi",
                "--config",
                str(tmp_path / "nonexistent.toml"),
            ],
        )
    assert result.exit_code == 1
    assert "BLOCK" in result.output


@respx.mock
def test_scan_parses_package_version(tmp_path):
    """Verify that 'name==version' is parsed correctly."""
    respx.post(OSV_URL).mock(return_value=Response(200, json={"vulns": []}))
    respx.get(NVD_URL).mock(return_value=Response(200, json={"vulnerabilities": []}))
    with patch("agentshield.analyzers.typosquatting.TyposquattingChecker._load", return_value=[]):
        result = runner.invoke(
            app,
            [
                "scan",
                "requests==2.28.0",
                "--ecosystem",
                "pypi",
                "--config",
                str(tmp_path / "nonexistent.toml"),
            ],
        )
    assert result.exit_code == 0
    # 2.28.0 shows in output (cache hit or duration line)
    assert "2.28.0" in result.output or "ALLOW" in result.output or "LOG_ASYNC" in result.output


def test_scan_denylist_exits_1(tmp_path):
    import textwrap

    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text(
        textwrap.dedent("""
        [denylist]
        packages = ["evil-pkg"]
    """)
    )
    result = runner.invoke(
        app,
        [
            "scan",
            "evil-pkg",
            "--ecosystem",
            "pypi",
            "--config",
            str(cfg_path),
        ],
    )
    assert result.exit_code == 1
    assert "BLOCK" in result.output


def test_scan_allowlist_exits_0(tmp_path):
    import textwrap

    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text(
        textwrap.dedent("""
        [allowlist]
        packages = ["safe-pkg"]
    """)
    )
    result = runner.invoke(
        app,
        [
            "scan",
            "safe-pkg",
            "--ecosystem",
            "pypi",
            "--config",
            str(cfg_path),
        ],
    )
    assert result.exit_code == 0
    assert "ALLOW" in result.output


# ── cache command ─────────────────────────────────────────────────────────────


def test_cache_stats_shows_counts(tmp_path):
    result = runner.invoke(app, ["cache", "stats"])
    assert result.exit_code == 0
    assert "Cache stats" in result.output or "Scan results" in result.output


def test_cache_clear_shows_count(tmp_path):
    result = runner.invoke(app, ["cache", "clear"])
    assert result.exit_code == 0
    assert "Cleared" in result.output or "cleared" in result.output.lower()


def test_cache_unknown_action(tmp_path):
    result = runner.invoke(app, ["cache", "turbo-warm"])
    assert result.exit_code == 1
    assert "unknown action" in result.output.lower()


# ── posture command ───────────────────────────────────────────────────────────


def test_posture_command_runs():
    result = runner.invoke(app, ["posture"])
    assert result.exit_code == 0


def test_posture_json_format_is_valid_json():
    """posture --format json must produce parseable JSON even when descriptions contain newlines."""
    import json

    result = runner.invoke(app, ["posture", "--format", "json", "--skip-packages"])
    assert result.exit_code == 0
    # Extract the JSON object from the output (ignoring any leading/trailing log noise).
    start = result.output.find("{")
    end = result.output.rfind("}") + 1
    assert start != -1, f"No JSON object found in output: {result.output!r}"
    parsed = json.loads(result.output[start:end])
    assert "risk_score" in parsed
    assert "critical_count" in parsed


# ── help ──────────────────────────────────────────────────────────────────────


def test_help_shows_commands():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.output


# ── --version ─────────────────────────────────────────────────────────────────


def test_version_flag_exits_0():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "agentshield" in result.output


def test_version_flag_shows_version_number():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    # Output should contain a version string (digits and dots)
    import re

    assert re.search(r"\d+\.\d+", result.output)


# ── cache stats curated count ─────────────────────────────────────────────────


def test_cache_stats_shows_curated_and_cached():
    result = runner.invoke(app, ["cache", "stats"])
    assert result.exit_code == 0
    assert "curated" in result.output
    assert "cached from OSV" in result.output
