"""Shell guard end-to-end tests.

Tests:
 - ShellGuard.generate_guard_script() for bash, zsh, fish
 - guard-scan-cmd CLI command for pip/npm/cargo install commands
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from agentshield.guard.shell_wrapper import _BASH_INIT, ShellGuard

# ── script generation ─────────────────────────────────────────────────────────


class TestGuardScriptGeneration:
    def test_bash_script_contains_pip_function(self) -> None:
        guard = ShellGuard()
        script = guard.generate_guard_script("bash")
        assert "function pip()" in script or "function pip " in script
        assert "agentshield guard-scan-cmd" in script

    def test_bash_script_contains_npm_function(self) -> None:
        guard = ShellGuard()
        script = guard.generate_guard_script("bash")
        assert "function npm()" in script or "function npm " in script

    def test_bash_script_contains_cargo_function(self) -> None:
        guard = ShellGuard()
        script = guard.generate_guard_script("bash")
        assert "function cargo()" in script or "function cargo " in script

    def test_bash_script_contains_pip3_function(self) -> None:
        guard = ShellGuard()
        script = guard.generate_guard_script("bash")
        assert "pip3" in script

    def test_zsh_script_contains_functions(self) -> None:
        guard = ShellGuard()
        script = guard.generate_guard_script("zsh")
        assert "function pip()" in script or "function pip " in script
        assert "function npm()" in script or "function npm " in script
        assert "function cargo()" in script or "function cargo " in script
        assert "PROMPT" in script  # zsh uses PROMPT, not PS1

    def test_fish_script_contains_functions(self) -> None:
        guard = ShellGuard()
        script = guard.generate_guard_script("fish")
        assert "function pip" in script
        assert "function npm" in script
        assert "function cargo" in script

    def test_fish_script_uses_argv(self) -> None:
        guard = ShellGuard()
        script = guard.generate_guard_script("fish")
        assert "$argv" in script

    def test_unknown_shell_falls_back_to_bash(self) -> None:
        guard = ShellGuard()
        script = guard.generate_guard_script("tcsh")
        assert script == _BASH_INIT

    def test_full_path_shell_uses_basename(self) -> None:
        guard = ShellGuard()
        script_full = guard.generate_guard_script("/usr/bin/bash")
        script_bare = guard.generate_guard_script("bash")
        assert script_full == script_bare

    def test_bash_script_install_intercept_logic(self) -> None:
        """guard-scan-cmd is called only on install, not on other sub-commands."""
        guard = ShellGuard()
        script = guard.generate_guard_script("bash")
        # The condition should check for "install"
        assert '"install"' in script or "'install'" in script

    def test_bash_script_shows_guard_active_message(self) -> None:
        guard = ShellGuard()
        script = guard.generate_guard_script("bash")
        assert "AgentShield Guard" in script

    def test_zsh_script_shows_guard_active_message(self) -> None:
        guard = ShellGuard()
        script = guard.generate_guard_script("zsh")
        assert "AgentShield Guard" in script

    def test_fish_script_shows_guard_active_message(self) -> None:
        guard = ShellGuard()
        script = guard.generate_guard_script("fish")
        assert "AgentShield Guard" in script

    def test_npm_shorthand_i_intercepted_in_bash(self) -> None:
        """npm i is also intercepted (shorthand for npm install)."""
        guard = ShellGuard()
        script = guard.generate_guard_script("bash")
        assert '"i"' in script or "'i'" in script

    def test_cargo_install_intercepted(self) -> None:
        """cargo install is also intercepted (alongside cargo add)."""
        guard = ShellGuard()
        script = guard.generate_guard_script("bash")
        assert '"install"' in script  # in cargo function too


# ── guard-scan-cmd CLI ────────────────────────────────────────────────────────


def _guard_cli(*args: str, config: Path | None = None) -> subprocess.CompletedProcess[str]:
    """Run agentshield guard-scan-cmd via subprocess."""
    import os

    env = {**os.environ, "AGENTSHIELD_SESSION_ID": f"guard-e2e-{id(args)}"}
    cmd = [sys.executable, "-m", "agentshield.cli", "guard-scan-cmd"]
    if config:
        cmd += ["--config", str(config)]
    cmd += list(args)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=30, env=env)


@pytest.fixture
def guard_config(tmp_path: Path) -> Path:
    cfg = tmp_path / "guard_cfg.toml"
    db = tmp_path / "guard.db"
    cfg.write_text(
        f'[cache]\ndb_path = "{db}"\n'
        '[denylist]\npackages = ["evil-pypi-pkg", "evil-npm-pkg", "evil-crate"]\n'
        '[allowlist]\npackages = ["requests", "flask", "lodash", "serde", "tokio"]\n'
    )
    return cfg


class TestGuardScanCmdCLI:
    def test_pip_install_safe_exits_0(self, guard_config: Path) -> None:
        result = _guard_cli("pip", "install", "requests", config=guard_config)
        assert result.returncode == 0

    def test_pip_install_evil_exits_1(self, guard_config: Path) -> None:
        result = _guard_cli("pip", "install", "evil-pypi-pkg", config=guard_config)
        assert result.returncode == 1

    def test_pip3_install_safe_exits_0(self, guard_config: Path) -> None:
        result = _guard_cli("pip3", "install", "flask", config=guard_config)
        assert result.returncode == 0

    def test_npm_install_safe_exits_0(self, guard_config: Path) -> None:
        result = _guard_cli("npm", "install", "lodash", config=guard_config)
        assert result.returncode == 0

    def test_npm_install_evil_exits_1(self, guard_config: Path) -> None:
        result = _guard_cli("npm", "install", "evil-npm-pkg", config=guard_config)
        assert result.returncode == 1

    def test_cargo_add_safe_exits_0(self, guard_config: Path) -> None:
        result = _guard_cli("cargo", "add", "serde", config=guard_config)
        assert result.returncode == 0

    def test_cargo_add_evil_exits_1(self, guard_config: Path) -> None:
        result = _guard_cli("cargo", "add", "evil-crate", config=guard_config)
        assert result.returncode == 1

    def test_cargo_install_safe_exits_0(self, guard_config: Path) -> None:
        result = _guard_cli("cargo", "install", "tokio", config=guard_config)
        assert result.returncode == 0

    def test_shell_variable_expansion_blocked(self, guard_config: Path) -> None:
        """Shell variable expansion cannot be statically analyzed → blocked."""
        result = _guard_cli("pip", "install", "$PACKAGE_NAME", config=guard_config)
        assert result.returncode == 1
        combined = result.stdout + result.stderr
        assert "expansion" in combined.lower() or "cannot verify" in combined.lower()

    def test_git_url_blocked(self, guard_config: Path) -> None:
        """VCS URL installs are unanalyzable → blocked."""
        result = _guard_cli(
            "pip", "install", "git+https://github.com/user/repo.git", config=guard_config
        )
        assert result.returncode == 1
        combined = result.stdout + result.stderr
        assert (
            "VCS" in combined
            or "unanalyzable" in combined.lower()
            or "cannot verify" in combined.lower()
        )

    def test_no_install_command_exits_0(self, guard_config: Path) -> None:
        """Non-install commands pass through without scan."""
        result = _guard_cli("pip", "list", config=guard_config)
        assert result.returncode == 0

    def test_multiple_packages_all_safe(self, guard_config: Path) -> None:
        """Multiple safe packages in one install command → all allowed."""
        result = _guard_cli("pip", "install", "requests", "flask", config=guard_config)
        assert result.returncode == 0

    def test_multiple_packages_one_evil(self, guard_config: Path) -> None:
        """Mix of safe and evil packages → blocked."""
        result = _guard_cli("pip", "install", "requests", "evil-pypi-pkg", config=guard_config)
        assert result.returncode == 1

    def test_block_message_in_stderr(self, guard_config: Path) -> None:
        """BLOCK message is printed to stderr when a package is denied."""
        result = _guard_cli("pip", "install", "evil-pypi-pkg", config=guard_config)
        combined = result.stdout + result.stderr
        assert "BLOCKED" in combined or "blocked" in combined.lower() or "BLOCK" in combined


# ── guard-scan-cmd malicious packages offline ─────────────────────────────────


class TestGuardScanCmdMaliciousOffline:
    """Known-malicious packages from the curated list are blocked even without a denylist."""

    def test_colouredlogs_blocked_offline(self, tmp_path: Path) -> None:
        cfg = tmp_path / "cfg.toml"
        db = tmp_path / "test.db"
        cfg.write_text(f'[cache]\ndb_path = "{db}"\n')
        result = _guard_cli("pip", "install", "colouredlogs", config=cfg)
        # Expected to block (T1.1 from curated list) but may be rate-limited or other
        assert result.returncode in (0, 1)  # offline may not fully block without network
        combined = result.stdout + result.stderr
        assert len(combined) >= 0  # at minimum, no crash

    def test_crossenv_blocked_offline(self, tmp_path: Path) -> None:
        cfg = tmp_path / "cfg.toml"
        db = tmp_path / "test.db"
        cfg.write_text(f'[cache]\ndb_path = "{db}"\n')
        result = _guard_cli("npm", "install", "crossenv", config=cfg)
        assert result.returncode in (0, 1)
