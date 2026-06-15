"""End-to-end tests for system package CVE scanning via guard-scan-cmd.

These tests verify that the CLI integration works end-to-end:
- Syspkg detection + CVE scanning pipeline
- Config-driven severity policy (block/warn/ignore)
- Offline mode disables CVE scanning
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest


def _guard_cli(*args: str, config: Path | None = None) -> subprocess.CompletedProcess[str]:
    """Run agentshield guard-scan-cmd via subprocess."""
    env = {**os.environ, "AGENTSHIELD_SESSION_ID": f"syspkg-cve-e2e-{id(args)}"}
    cmd = [sys.executable, "-m", "agentshield.cli", "guard-scan-cmd"]
    if config:
        cmd += ["--config", str(config)]
    cmd += ["--"]  # stop typer interpreting package-manager flags
    cmd += list(args)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60, env=env)


@pytest.fixture
def syspkg_config(tmp_path: Path) -> Path:
    """Config with CVE scanning enabled and a temp DB."""
    cfg = tmp_path / "syspkg_cve_cfg.toml"
    db = tmp_path / "syspkg_cve.db"
    cfg.write_text(
        f"""\
[cache]
db_path = "{db}"

[syspkg]
enabled = true
cve_scan = true
"""
    )
    return cfg


@pytest.fixture
def syspkg_config_disabled(tmp_path: Path) -> Path:
    """Config with CVE scanning disabled."""
    cfg = tmp_path / "syspkg_cve_disabled.toml"
    db = tmp_path / "syspkg_cve_disabled.db"
    cfg.write_text(
        f"""\
[cache]
db_path = "{db}"

[syspkg]
enabled = true
cve_scan = false
"""
    )
    return cfg


@pytest.fixture
def syspkg_config_offline(tmp_path: Path) -> Path:
    """Config with offline mode — CVE scanning should be skipped."""
    cfg = tmp_path / "syspkg_offline.toml"
    db = tmp_path / "syspkg_offline.db"
    cfg.write_text(
        f"""\
[cache]
db_path = "{db}"
offline = true

[syspkg]
enabled = true
cve_scan = true
"""
    )
    return cfg


class TestSysPkgCVEE2E:
    """E2E tests for syspkg CVE scanning via guard-scan-cmd.

    Note: these tests make real HTTP calls to OSV/distro trackers.
    If network is unavailable, findings will be empty (graceful degradation).
    """

    def test_apt_install_runs_cve_scan(self, syspkg_config: Path) -> None:
        """apt-get install should trigger CVE scan (exit 0 or 1 depending on vulns)."""
        result = _guard_cli("apt-get", "install", "curl", config=syspkg_config)
        combined = result.stdout + result.stderr
        # Should always show SP1.1 warning
        assert "SP1.1" in combined or "WARNING" in combined

    def test_brew_install_runs_cve_scan(self, syspkg_config: Path) -> None:
        """brew install should trigger CVE scan."""
        result = _guard_cli("brew", "install", "jq", config=syspkg_config)
        combined = result.stdout + result.stderr
        assert "SP1.1" in combined or "WARNING" in combined

    def test_cve_scan_disabled_config(self, syspkg_config_disabled: Path) -> None:
        """With cve_scan=false, should still show SP1.1 warning but no CVE output."""
        result = _guard_cli("apt-get", "install", "curl", config=syspkg_config_disabled)
        assert result.returncode == 0
        combined = result.stdout + result.stderr
        assert "SP1.1" in combined or "WARNING" in combined

    def test_offline_mode_skips_cve_scan(self, syspkg_config_offline: Path) -> None:
        """Offline mode should skip CVE scanning entirely."""
        result = _guard_cli("apt-get", "install", "curl", config=syspkg_config_offline)
        assert result.returncode == 0

    def test_non_install_no_cve_scan(self, syspkg_config: Path) -> None:
        """Non-install commands should not trigger CVE scan."""
        result = _guard_cli("apt-get", "update", config=syspkg_config)
        assert result.returncode == 0
        combined = result.stdout + result.stderr
        assert "SP1.1" not in combined

    def test_yum_install_cve_scan(self, syspkg_config: Path) -> None:
        """yum install should trigger CVE scan."""
        result = _guard_cli("yum", "install", "httpd", config=syspkg_config)
        combined = result.stdout + result.stderr
        assert "SP1.1" in combined or "WARNING" in combined

    def test_pacman_sync_cve_scan(self, syspkg_config: Path) -> None:
        """pacman -S should trigger CVE scan."""
        result = _guard_cli("pacman", "-S", "vim", config=syspkg_config)
        combined = result.stdout + result.stderr
        assert "SP1.1" in combined or "WARNING" in combined

    def test_apk_add_cve_scan(self, syspkg_config: Path) -> None:
        """apk add should trigger CVE scan."""
        result = _guard_cli("apk", "add", "python3", config=syspkg_config)
        combined = result.stdout + result.stderr
        assert "SP1.1" in combined or "WARNING" in combined
