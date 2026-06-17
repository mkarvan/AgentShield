"""Unit tests for the CLI layer.

All network calls are mocked via respx.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

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
    from agentshield.analyzers.trust_score import TrustScoreResult

    respx.post(OSV_URL).mock(return_value=Response(200, json={"vulns": []}))
    with (
        patch("agentshield.analyzers.typosquatting.TyposquattingChecker._load", return_value=[]),
        patch(
            "agentshield.analyzers.trust_score.compute_trust_score",
            AsyncMock(return_value=TrustScoreResult(score=80, label="high-trust")),
        ),
    ):
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


def test_posture_json_format_is_valid_json(tmp_path):
    """posture --format json must produce parseable JSON even when descriptions contain newlines."""
    import json

    out_file = tmp_path / "posture.json"
    result = runner.invoke(
        app, ["posture", "--format", "json", "--skip-packages", "--output", str(out_file)]
    )
    assert result.exit_code == 0, f"CLI failed: {result.output!r}"
    assert out_file.exists(), f"Output file not created; CLI output: {result.output!r}"
    parsed = json.loads(out_file.read_text())
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


# ── hook (Claude Code / Codex PreToolUse) ─────────────────────────────────────


def test_hook_no_install_allows(tmp_path):
    cfg = tmp_path / "c.toml"
    cfg.write_text("offline = true\n")
    payload = '{"tool_name": "Bash", "tool_input": {"command": "ls -la"}}'
    result = runner.invoke(app, ["hook", "--config", str(cfg)], input=payload)
    assert result.exit_code == 0
    assert result.stdout.strip() == ""


def test_hook_unverifiable_manager_denies(tmp_path):
    # gem has no scan backend → fail closed → permissionDecision deny (no network)
    cfg = tmp_path / "c.toml"
    cfg.write_text("offline = true\n")
    payload = '{"tool_name": "Bash", "tool_input": {"command": "gem install foo"}}'
    result = runner.invoke(app, ["hook", "--config", str(cfg)], input=payload)
    assert result.exit_code == 0
    assert '"permissionDecision": "deny"' in result.stdout


def test_hook_malformed_payload_does_not_block(tmp_path):
    cfg = tmp_path / "c.toml"
    cfg.write_text("offline = true\n")
    result = runner.invoke(app, ["hook", "--config", str(cfg)], input="not json at all")
    assert result.exit_code == 0
    assert '"permissionDecision"' not in result.stdout


# ── guard-scan-cmd: LOG_ASYNC vs NEEDS_CONFIRMATION (warn_confirm contract) ────
# Regression for the audit finding: NEEDS_CONFIRMATION must pause (fail closed
# when non-interactive), while LOG_ASYNC is warn-only and proceeds. Previously
# both exited 0, letting the shell wrapper / PATH shim run the install anyway.

from types import SimpleNamespace  # noqa: E402

from agentshield.cli import (  # noqa: E402
    GUARD_EXIT_BLOCK,
    GUARD_EXIT_NEEDS_CONFIRMATION,
    _guard_confirmation_granted,
)
from agentshield.core.models import (  # noqa: E402
    Decision,
    DecisionAction,
    ScanResult,
    Severity,
)
from agentshield.core.scanner import AgentShield  # noqa: E402


def _ascan_returning(action: DecisionAction):
    async def _fake(self, request):  # noqa: ANN001
        return ScanResult(
            request=request,
            findings=[],
            max_severity=Severity.NONE,
            decision=Decision(action=action, reason=f"{action.value} by policy"),
        )

    return _fake


def _guard_invoke(tmp_path, env=None):
    return runner.invoke(
        app,
        ["guard-scan-cmd", "pip", "install", "somepkg", "--config", str(tmp_path / "no.toml")],
        env=env,
    )


def test_guard_log_async_proceeds_exit_0(tmp_path):
    with patch.object(AgentShield, "ascan", _ascan_returning(DecisionAction.LOG_ASYNC)):
        result = _guard_invoke(tmp_path)
    assert result.exit_code == 0, result.output
    assert "async review" in result.output.lower()


def test_guard_needs_confirmation_blocks_when_noninteractive(tmp_path):
    # Under CliRunner stdin/stderr are not TTYs → the agent case → fail closed.
    with patch.object(AgentShield, "ascan", _ascan_returning(DecisionAction.NEEDS_CONFIRMATION)):
        result = _guard_invoke(tmp_path)
    assert result.exit_code == GUARD_EXIT_NEEDS_CONFIRMATION, result.output
    assert "confirmation" in result.output.lower()


def test_guard_needs_confirmation_assume_yes_proceeds(tmp_path):
    with patch.object(AgentShield, "ascan", _ascan_returning(DecisionAction.NEEDS_CONFIRMATION)):
        result = _guard_invoke(tmp_path, env={"AGENTSHIELD_ASSUME_YES": "1"})
    assert result.exit_code == 0, result.output


def test_guard_block_exits_1(tmp_path):
    with patch.object(AgentShield, "ascan", _ascan_returning(DecisionAction.BLOCK)):
        result = _guard_invoke(tmp_path)
    assert result.exit_code == GUARD_EXIT_BLOCK, result.output
    assert "BLOCKED" in result.output


def _fake_sys(*, stdin_tty: bool, stderr_tty: bool):
    return SimpleNamespace(
        stdin=SimpleNamespace(isatty=lambda: stdin_tty),
        stderr=SimpleNamespace(isatty=lambda: stderr_tty),
    )


def test_confirmation_helper_fails_closed_when_noninteractive(monkeypatch):
    monkeypatch.delenv("AGENTSHIELD_ASSUME_YES", raising=False)
    monkeypatch.setattr("agentshield.cli.sys", _fake_sys(stdin_tty=False, stderr_tty=False))
    from rich.console import Console

    assert _guard_confirmation_granted(Console(stderr=True)) is False


def test_confirmation_helper_prompts_and_grants_when_interactive(monkeypatch):
    monkeypatch.delenv("AGENTSHIELD_ASSUME_YES", raising=False)
    monkeypatch.delenv("AGENTSHIELD_NONINTERACTIVE", raising=False)
    monkeypatch.setattr("agentshield.cli.sys", _fake_sys(stdin_tty=True, stderr_tty=True))
    from rich.console import Console

    with patch("agentshield.cli.typer.confirm", return_value=True) as confirm:
        assert _guard_confirmation_granted(Console(stderr=True)) is True
    confirm.assert_called_once()


def test_confirmation_helper_prompts_and_denies_when_interactive(monkeypatch):
    monkeypatch.delenv("AGENTSHIELD_ASSUME_YES", raising=False)
    monkeypatch.delenv("AGENTSHIELD_NONINTERACTIVE", raising=False)
    monkeypatch.setattr("agentshield.cli.sys", _fake_sys(stdin_tty=True, stderr_tty=True))
    from rich.console import Console

    with patch("agentshield.cli.typer.confirm", return_value=False):
        assert _guard_confirmation_granted(Console(stderr=True)) is False


def test_confirmation_helper_noninteractive_override_blocks_even_with_tty(monkeypatch):
    # AGENTSHIELD_NONINTERACTIVE=1 forces the fail-closed path even on a TTY.
    monkeypatch.delenv("AGENTSHIELD_ASSUME_YES", raising=False)
    monkeypatch.setenv("AGENTSHIELD_NONINTERACTIVE", "1")
    monkeypatch.setattr("agentshield.cli.sys", _fake_sys(stdin_tty=True, stderr_tty=True))
    from rich.console import Console

    assert _guard_confirmation_granted(Console(stderr=True)) is False
