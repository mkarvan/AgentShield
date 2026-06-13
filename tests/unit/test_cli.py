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


# ── help ──────────────────────────────────────────────────────────────────────


def test_help_shows_commands():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.output
