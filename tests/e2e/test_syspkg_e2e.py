"""End-to-end tests for system package manager detection via guard-scan-cmd."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest


def _guard_cli(*args: str, config: Path | None = None) -> subprocess.CompletedProcess[str]:
    """Run agentshield guard-scan-cmd via subprocess."""
    env = {**os.environ, "AGENTSHIELD_SESSION_ID": f"syspkg-e2e-{id(args)}"}
    cmd = [sys.executable, "-m", "agentshield.cli", "guard-scan-cmd"]
    if config:
        cmd += ["--config", str(config)]
    cmd += ["--"]  # stop typer interpreting package-manager flags (e.g. -S)
    cmd += list(args)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=30, env=env)


@pytest.fixture
def syspkg_config(tmp_path: Path) -> Path:
    cfg = tmp_path / "syspkg_cfg.toml"
    db = tmp_path / "syspkg.db"
    cfg.write_text(f'[cache]\ndb_path = "{db}"\n')
    return cfg


class TestSysPkgGuardScanCmd:
    """System package manager commands emit warnings but exit 0 (no block)."""

    def test_apt_get_install_warns_exits_0(self, syspkg_config: Path) -> None:
        result = _guard_cli("apt-get", "install", "curl", config=syspkg_config)
        assert result.returncode == 0
        combined = result.stdout + result.stderr
        assert "SP1.1" in combined or "WARNING" in combined

    def test_brew_install_warns_exits_0(self, syspkg_config: Path) -> None:
        result = _guard_cli("brew", "install", "jq", config=syspkg_config)
        assert result.returncode == 0
        combined = result.stdout + result.stderr
        assert "SP1.1" in combined or "WARNING" in combined

    def test_yum_install_warns_exits_0(self, syspkg_config: Path) -> None:
        result = _guard_cli("yum", "install", "httpd", config=syspkg_config)
        assert result.returncode == 0

    def test_dnf_install_warns_exits_0(self, syspkg_config: Path) -> None:
        result = _guard_cli("dnf", "install", "gcc", config=syspkg_config)
        assert result.returncode == 0

    def test_apk_add_warns_exits_0(self, syspkg_config: Path) -> None:
        result = _guard_cli("apk", "add", "python3", config=syspkg_config)
        assert result.returncode == 0

    def test_pacman_sync_warns_exits_0(self, syspkg_config: Path) -> None:
        result = _guard_cli("pacman", "-S", "vim", config=syspkg_config)
        assert result.returncode == 0

    def test_snap_install_warns_exits_0(self, syspkg_config: Path) -> None:
        result = _guard_cli("snap", "install", "firefox", config=syspkg_config)
        assert result.returncode == 0

    def test_flatpak_install_warns_exits_0(self, syspkg_config: Path) -> None:
        result = _guard_cli(
            "flatpak", "install", "flathub", "org.mozilla.firefox", config=syspkg_config
        )
        assert result.returncode == 0

    def test_zypper_install_warns_exits_0(self, syspkg_config: Path) -> None:
        result = _guard_cli("zypper", "install", "gcc", config=syspkg_config)
        assert result.returncode == 0

    def test_non_install_subcommand_exits_0_no_warning(self, syspkg_config: Path) -> None:
        result = _guard_cli("apt-get", "update", config=syspkg_config)
        assert result.returncode == 0
        combined = result.stdout + result.stderr
        assert "SP1.1" not in combined
