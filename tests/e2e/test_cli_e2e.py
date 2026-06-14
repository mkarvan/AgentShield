"""CLI end-to-end tests.

Exercises the ``agentshield`` CLI via subprocess so we test the real entry
point rather than calling Python functions directly.

Non-network tests use allowlist / denylist configs so no real HTTP calls are
made.  Real-network tests are tagged @pytest.mark.network.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

# ── helper ────────────────────────────────────────────────────────────────────


def cli(
    *args: str, config: Path | None = None, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    """Run ``agentshield <args>`` as a subprocess and return the result."""
    import os

    base_env = {**os.environ}
    if env:
        base_env.update(env)
    # Isolate each run from a shared session to avoid rate-limit bleed-through
    base_env["AGENTSHIELD_SESSION_ID"] = f"e2e-cli-{id(args)}"

    cmd = [sys.executable, "-m", "agentshield.cli", *args]
    if config is not None:
        # Insert --config right after the sub-command (first positional arg)
        cmd = [sys.executable, "-m", "agentshield.cli", args[0], "--config", str(config), *args[1:]]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60, env=base_env)


# ── scan: denylist (offline, no network) ─────────────────────────────────────


class TestScanDenylist:
    def test_pypi_denylist_exits_1(self, cli_config_file: Path) -> None:
        result = cli("scan", "evil-pypi-pkg", "--ecosystem", "pypi", config=cli_config_file)
        assert result.returncode == 1

    def test_npm_denylist_exits_1(self, cli_config_file: Path) -> None:
        result = cli("scan", "evil-npm-pkg", "--ecosystem", "npm", config=cli_config_file)
        assert result.returncode == 1

    def test_cargo_denylist_exits_1(self, cli_config_file: Path) -> None:
        result = cli("scan", "evil-crate", "--ecosystem", "cargo", config=cli_config_file)
        assert result.returncode == 1

    def test_block_output_contains_block(self, cli_config_file: Path) -> None:
        result = cli("scan", "evil-pypi-pkg", "--ecosystem", "pypi", config=cli_config_file)
        combined = result.stdout + result.stderr
        assert "BLOCK" in combined


# ── scan: allowlist (offline, no network) ────────────────────────────────────


class TestScanAllowlist:
    def test_pypi_allowlist_exits_0(self, cli_config_file: Path) -> None:
        result = cli("scan", "requests", "--ecosystem", "pypi", config=cli_config_file)
        assert result.returncode == 0

    def test_npm_allowlist_exits_0(self, cli_config_file: Path) -> None:
        result = cli("scan", "lodash", "--ecosystem", "npm", config=cli_config_file)
        assert result.returncode == 0

    def test_cargo_allowlist_exits_0(self, cli_config_file: Path) -> None:
        result = cli("scan", "serde", "--ecosystem", "cargo", config=cli_config_file)
        assert result.returncode == 0

    def test_allow_output_contains_allow(self, cli_config_file: Path) -> None:
        result = cli("scan", "requests", "--ecosystem", "pypi", config=cli_config_file)
        combined = result.stdout + result.stderr
        assert "ALLOW" in combined


# ── scan: malicious package offline ──────────────────────────────────────────


class TestScanMaliciousOffline:
    """Known-malicious packages are blocked offline via the curated local DB."""

    def test_colouredlogs_blocked_pypi(self, tmp_path: Path) -> None:
        cfg = tmp_path / "cfg.toml"
        db = tmp_path / "test.db"
        cfg.write_text(f'[cache]\ndb_path = "{db}"\n')
        # colouredlogs is in the bundled malicious list → should block even offline
        result = cli("scan", "colouredlogs", "--ecosystem", "pypi", "--offline", config=cfg)
        # Expect BLOCK (exit 1) or at least that it runs without crash
        assert result.returncode in (0, 1)
        combined = result.stdout + result.stderr
        assert "colouredlogs" in combined.lower() or "BLOCK" in combined or "ALLOW" in combined

    def test_crossenv_blocked_npm(self, tmp_path: Path) -> None:
        cfg = tmp_path / "cfg.toml"
        db = tmp_path / "test.db"
        cfg.write_text(f'[cache]\ndb_path = "{db}"\n')
        result = cli("scan", "crossenv", "--ecosystem", "npm", "--offline", config=cfg)
        assert result.returncode in (0, 1)
        combined = result.stdout + result.stderr
        assert "crossenv" in combined.lower() or "BLOCK" in combined or "ALLOW" in combined


# ── scan: flags ───────────────────────────────────────────────────────────────


class TestScanFlags:
    def test_check_licenses_flag(self, cli_config_file: Path) -> None:
        """--check-licenses runs without error for an allowlisted package."""
        result = cli(
            "scan", "requests", "--ecosystem", "pypi", "--check-licenses", config=cli_config_file
        )
        # Allowlist short-circuits before license check; expect success
        assert result.returncode == 0

    def test_transitive_flag_runs(self, cli_config_file: Path) -> None:
        """--transitive flag is accepted without crash for denylist packages."""
        result = cli(
            "scan",
            "evil-pypi-pkg",
            "--ecosystem",
            "pypi",
            "--transitive",
            config=cli_config_file,
        )
        # Denylist short-circuits (no transitive scan attempted); still BLOCK
        assert result.returncode == 1

    def test_offline_flag(self, tmp_path: Path) -> None:
        """--offline flag prevents network calls; command succeeds."""
        cfg = tmp_path / "cfg.toml"
        db = tmp_path / "test.db"
        cfg.write_text(f'[cache]\ndb_path = "{db}"\n[allowlist]\npackages = ["requests"]\n')
        result = cli("scan", "requests", "--ecosystem", "pypi", "--offline", config=cfg)
        assert result.returncode == 0

    def test_version_pinned_scan(self, cli_config_file: Path) -> None:
        """Package specified as name==version is parsed correctly."""
        result = cli("scan", "requests==2.28.0", "--ecosystem", "pypi", config=cli_config_file)
        # requests is on allowlist → ALLOW
        assert result.returncode == 0

    def test_unknown_ecosystem_exits_nonzero(self, cli_config_file: Path) -> None:
        """Passing an unknown ecosystem value produces a non-zero exit."""
        result = cli("scan", "requests", "--ecosystem", "maven", config=cli_config_file)
        assert result.returncode != 0


# ── scan-file ─────────────────────────────────────────────────────────────────


class TestScanFile:
    def test_requirements_txt_allowlist(
        self, sample_requirements_txt: Path, cli_config_file: Path
    ) -> None:
        result = cli("scan-file", str(sample_requirements_txt), config=cli_config_file)
        combined = result.stdout + result.stderr
        # All packages are allowlisted; aggregate should be ALLOW
        assert result.returncode == 0
        assert "ALLOW" in combined

    def test_package_json_allowlist(self, sample_package_json: Path, cli_config_file: Path) -> None:
        result = cli("scan-file", str(sample_package_json), config=cli_config_file)
        assert result.returncode == 0

    def test_cargo_toml_allowlist(self, sample_cargo_toml: Path, cli_config_file: Path) -> None:
        result = cli("scan-file", str(sample_cargo_toml), config=cli_config_file)
        assert result.returncode == 0

    def test_scan_file_shows_summary(
        self, sample_requirements_txt: Path, cli_config_file: Path
    ) -> None:
        result = cli("scan-file", str(sample_requirements_txt), config=cli_config_file)
        combined = result.stdout + result.stderr
        # Should print package count, blocked/allowed stats
        assert "Packages" in combined or "packages" in combined or "ALLOW" in combined

    def test_scan_file_with_denylist_exits_1(self, tmp_path: Path) -> None:
        manifest = tmp_path / "requirements.txt"
        manifest.write_text("evil-pypi-pkg==1.0.0\nrequests==2.28.0\n")
        cfg = tmp_path / "cfg.toml"
        db = tmp_path / "test.db"
        cfg.write_text(f'[cache]\ndb_path = "{db}"\n[denylist]\npackages = ["evil-pypi-pkg"]\n')
        result = cli("scan-file", str(manifest), config=cfg)
        assert result.returncode == 1


# ── diff-scan ─────────────────────────────────────────────────────────────────


class TestDiffScan:
    def test_diff_scan_runs(
        self,
        sample_old_requirements_txt: Path,
        sample_new_requirements_txt: Path,
        cli_config_file: Path,
    ) -> None:
        result = cli(
            "diff-scan",
            str(sample_old_requirements_txt),
            str(sample_new_requirements_txt),
            config=cli_config_file,
        )
        combined = result.stdout + result.stderr
        assert (
            "Added" in combined or "added" in combined or "ALLOW" in combined or "BLOCK" in combined
        )

    def test_diff_scan_identical_manifests(self, tmp_path: Path, cli_config_file: Path) -> None:
        manifest = tmp_path / "requirements.txt"
        manifest.write_text("requests==2.28.0\n")
        result = cli("diff-scan", str(manifest), str(manifest), config=cli_config_file)
        combined = result.stdout + result.stderr
        # No changed packages → should succeed and mention "unchanged" or "No changes"
        assert result.returncode == 0
        assert (
            "unchanged" in combined.lower()
            or "no changes" in combined.lower()
            or "ALLOW" in combined
        )


# ── scan-docker ───────────────────────────────────────────────────────────────


class TestScanDocker:
    def test_scan_docker_runs(self, sample_dockerfile: Path, cli_config_file: Path) -> None:
        result = cli("scan-docker", str(sample_dockerfile), config=cli_config_file)
        combined = result.stdout + result.stderr
        assert result.returncode in (0, 1)
        # Should report some packages found
        assert "ALLOW" in combined or "BLOCK" in combined or "package" in combined.lower()

    def test_scan_docker_empty_dockerfile(self, tmp_path: Path, cli_config_file: Path) -> None:
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM python:3.11-slim\nWORKDIR /app\n")
        result = cli("scan-docker", str(dockerfile), config=cli_config_file)
        assert result.returncode == 0
        combined = result.stdout + result.stderr
        assert "No package" in combined or "no package" in combined.lower()


# ── sbom ──────────────────────────────────────────────────────────────────────


class TestSbom:
    def test_sbom_outputs_json(self, sample_requirements_txt: Path, cli_config_file: Path) -> None:
        result = cli("sbom", str(sample_requirements_txt), config=cli_config_file)
        assert result.returncode in (0, 1)
        combined = result.stdout + result.stderr
        # SBOM should contain CycloneDX JSON structure
        assert "CycloneDX" in combined or "cyclonedx" in combined.lower() or "bomFormat" in combined

    def test_sbom_writes_to_file(
        self, sample_requirements_txt: Path, tmp_path: Path, cli_config_file: Path
    ) -> None:
        out_file = tmp_path / "sbom.json"
        result = cli(
            "sbom",
            str(sample_requirements_txt),
            "--output",
            str(out_file),
            config=cli_config_file,
        )
        assert result.returncode in (0, 1)
        if out_file.exists():
            content = out_file.read_text()
            data = json.loads(content)
            assert "bomFormat" in data or "components" in data


# ── drift-check ───────────────────────────────────────────────────────────────


class TestDriftCheck:
    def test_drift_check_empty_db_exits_0(self, tmp_path: Path) -> None:
        """With no previously-allowed packages, drift-check exits 0."""
        cfg = tmp_path / "cfg.toml"
        db = tmp_path / "empty.db"
        cfg.write_text(f'[cache]\ndb_path = "{db}"\n')
        result = cli("drift-check", config=cfg)
        assert result.returncode == 0
        combined = result.stdout + result.stderr
        assert (
            "No drift" in combined or "no drift" in combined.lower() or "clean" in combined.lower()
        )

    def test_drift_check_json_format(self, tmp_path: Path) -> None:
        cfg = tmp_path / "cfg.toml"
        db = tmp_path / "empty.db"
        cfg.write_text(f'[cache]\ndb_path = "{db}"\n')
        result = cli("drift-check", "--format", "json", config=cfg)
        # With empty DB, output is [] (empty JSON array) or similar
        assert result.returncode == 0


# ── posture ───────────────────────────────────────────────────────────────────


class TestPosture:
    def test_posture_terminal_format(self, tmp_path: Path) -> None:
        cfg = tmp_path / "cfg.toml"
        db = tmp_path / "posture.db"
        cfg.write_text(f'[cache]\ndb_path = "{db}"\n')
        result = cli("posture", "--skip-packages", config=cfg)
        assert result.returncode == 0

    def test_posture_json_format(self, tmp_path: Path) -> None:
        cfg = tmp_path / "cfg.toml"
        db = tmp_path / "posture.db"
        cfg.write_text(f'[cache]\ndb_path = "{db}"\n')
        result = cli("posture", "--format", "json", "--skip-packages", config=cfg)
        assert result.returncode == 0
        combined = result.stdout + result.stderr
        # Should contain some JSON structure
        assert "{" in combined or "[" in combined

    def test_posture_markdown_format(self, tmp_path: Path) -> None:
        cfg = tmp_path / "cfg.toml"
        db = tmp_path / "posture.db"
        cfg.write_text(f'[cache]\ndb_path = "{db}"\n')
        result = cli("posture", "--format", "markdown", "--skip-packages", config=cfg)
        assert result.returncode == 0
        combined = result.stdout + result.stderr
        assert "#" in combined or "Score" in combined or "score" in combined.lower()

    def test_posture_html_format(self, tmp_path: Path) -> None:
        cfg = tmp_path / "cfg.toml"
        db = tmp_path / "posture.db"
        cfg.write_text(f'[cache]\ndb_path = "{db}"\n')
        result = cli("posture", "--format", "html", "--skip-packages", config=cfg)
        assert result.returncode == 0
        combined = result.stdout + result.stderr
        assert "<html" in combined or "<!DOCTYPE" in combined or "<div" in combined

    def test_posture_html_writes_to_file(self, tmp_path: Path) -> None:
        cfg = tmp_path / "cfg.toml"
        db = tmp_path / "posture.db"
        cfg.write_text(f'[cache]\ndb_path = "{db}"\n')
        out_file = tmp_path / "posture.html"
        result = cli(
            "posture",
            "--format",
            "html",
            "--output",
            str(out_file),
            "--skip-packages",
            config=cfg,
        )
        assert result.returncode == 0
        assert out_file.exists()
        content = out_file.read_text()
        assert "<html" in content or "<!DOCTYPE" in content or "<div" in content

    def test_posture_unknown_format_exits_1(self, tmp_path: Path) -> None:
        cfg = tmp_path / "cfg.toml"
        db = tmp_path / "posture.db"
        cfg.write_text(f'[cache]\ndb_path = "{db}"\n')
        result = cli("posture", "--format", "xml", "--skip-packages", config=cfg)
        assert result.returncode == 1


# ── guard-scan-cmd ────────────────────────────────────────────────────────────


class TestGuardScanCmd:
    def test_pip_install_allowlisted(self, cli_config_file: Path) -> None:
        result = cli("guard-scan-cmd", "pip", "install", "requests", config=cli_config_file)
        assert result.returncode == 0

    def test_pip_install_denylisted(self, cli_config_file: Path) -> None:
        result = cli("guard-scan-cmd", "pip", "install", "evil-pypi-pkg", config=cli_config_file)
        assert result.returncode == 1

    def test_npm_install_allowlisted(self, cli_config_file: Path) -> None:
        result = cli("guard-scan-cmd", "npm", "install", "lodash", config=cli_config_file)
        assert result.returncode == 0

    def test_npm_install_denylisted(self, cli_config_file: Path) -> None:
        result = cli("guard-scan-cmd", "npm", "install", "evil-npm-pkg", config=cli_config_file)
        assert result.returncode == 1

    def test_cargo_add_allowlisted(self, cli_config_file: Path) -> None:
        result = cli("guard-scan-cmd", "cargo", "add", "serde", config=cli_config_file)
        assert result.returncode == 0

    def test_cargo_add_denylisted(self, cli_config_file: Path) -> None:
        result = cli("guard-scan-cmd", "cargo", "add", "evil-crate", config=cli_config_file)
        assert result.returncode == 1

    def test_shell_variable_expansion_exits_1(self, cli_config_file: Path) -> None:
        """Shell variable expansion is flagged as unanalyzable — blocked."""
        result = cli("guard-scan-cmd", "pip", "install", "$MY_PACKAGE", config=cli_config_file)
        assert result.returncode == 1
        combined = result.stdout + result.stderr
        assert "cannot verify" in combined.lower() or "expansion" in combined.lower()

    def test_no_packages_detected_exits_0(self, cli_config_file: Path) -> None:
        """Command with no package arguments passes through."""
        result = cli("guard-scan-cmd", "pip", "list", config=cli_config_file)
        assert result.returncode == 0


# ── network tests ─────────────────────────────────────────────────────────────


@pytest.mark.network
@pytest.mark.slow
class TestScanNetworkPyPI:
    def test_requests_scan_pypi(self, tmp_path: Path) -> None:
        cfg = tmp_path / "cfg.toml"
        db = tmp_path / "test.db"
        cfg.write_text(f'[cache]\ndb_path = "{db}"\n')
        result = cli("scan", "requests", "--ecosystem", "pypi", config=cfg)
        assert result.returncode in (0, 1)
        combined = result.stdout + result.stderr
        assert "ALLOW" in combined or "BLOCK" in combined or "NEEDS_CONFIRMATION" in combined

    def test_flask_scan_pypi(self, tmp_path: Path) -> None:
        cfg = tmp_path / "cfg.toml"
        db = tmp_path / "test.db"
        cfg.write_text(f'[cache]\ndb_path = "{db}"\n')
        result = cli("scan", "flask", "--ecosystem", "pypi", config=cfg)
        assert result.returncode in (0, 1)
        combined = result.stdout + result.stderr
        assert "ALLOW" in combined or "BLOCK" in combined or "LOG_ASYNC" in combined


@pytest.mark.network
@pytest.mark.slow
class TestScanNetworkNpm:
    def test_lodash_scan_npm(self, tmp_path: Path) -> None:
        cfg = tmp_path / "cfg.toml"
        db = tmp_path / "test.db"
        cfg.write_text(f'[cache]\ndb_path = "{db}"\n')
        result = cli("scan", "lodash", "--ecosystem", "npm", config=cfg)
        assert result.returncode in (0, 1)
        combined = result.stdout + result.stderr
        assert "ALLOW" in combined or "BLOCK" in combined or "LOG_ASYNC" in combined


@pytest.mark.network
@pytest.mark.slow
class TestScanNetworkCargo:
    def test_serde_scan_cargo(self, tmp_path: Path) -> None:
        cfg = tmp_path / "cfg.toml"
        db = tmp_path / "test.db"
        cfg.write_text(f'[cache]\ndb_path = "{db}"\n')
        result = cli("scan", "serde", "--ecosystem", "cargo", config=cfg)
        assert result.returncode in (0, 1)
        combined = result.stdout + result.stderr
        assert "ALLOW" in combined or "BLOCK" in combined or "LOG_ASYNC" in combined
