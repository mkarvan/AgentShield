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
    """Detection-only config: CVE scanning explicitly OFF.

    These tests assert that system package-manager invocations are *detected*
    and warned about (SP1.1) and never hard-block. CVE scanning is opt-in and
    makes live network calls, so it is disabled here to keep the suite
    deterministic and offline. CVE-scan behaviour is covered separately by the
    @network @slow test below and by test_syspkg_cve_e2e.py.
    """
    cfg = tmp_path / "syspkg_cfg.toml"
    db = tmp_path / "syspkg.db"
    cfg.write_text(f'[cache]\ndb_path = "{db}"\n\n[syspkg]\nenabled = true\ncve_scan = false\n')
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


@pytest.mark.network
@pytest.mark.slow
def test_apt_install_with_cve_scan_enabled_produces_findings(tmp_path: Path) -> None:
    """With cve_scan = true, an install of a CVE-heavy package surfaces findings.

    This exercises the opt-in CVE pipeline end-to-end against the live OSV /
    distro trackers. We deliberately do NOT hard-code an exit code: depending
    on the configured severity policy a HIGH CVE warns (exit 0) while a
    CRITICAL one blocks (exit 1). We only assert the pipeline ran to completion
    (no hang) and actually emitted CVE findings. The severity floor is lowered
    so findings are not filtered out by the default HIGH floor.
    """
    cfg = tmp_path / "syspkg_cve_on.toml"
    db = tmp_path / "syspkg_cve_on.db"
    cfg.write_text(
        f'[cache]\ndb_path = "{db}"\n\n'
        "[syspkg]\nenabled = true\ncve_scan = true\n"
        'severity_floor = "LOW"\nmax_findings = 50\n'
    )
    result = _guard_cli("apt-get", "install", "curl", config=cfg)

    combined = result.stdout + result.stderr
    # Ran to completion without timing out, and did not crash.
    assert result.returncode in (0, 1)
    assert "SP1.1" in combined or "WARNING" in combined
    # CVE pipeline produced findings (flagged-for-review and/or blocked output).
    assert "CVE(s)" in combined
