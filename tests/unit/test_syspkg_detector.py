"""Unit tests for analyzers/syspkg_detector.py."""

from __future__ import annotations

from agentshield.analyzers.syspkg_detector import SysPkgWarning, detect_syspkg_commands

# ── apt-get ──────────────────────────────────────────────────────────────────


class TestAptGet:
    def test_apt_get_install_single(self) -> None:
        warnings = detect_syspkg_commands("apt-get install curl")
        assert len(warnings) == 1
        assert warnings[0].manager == "apt-get"
        assert "curl" in warnings[0].packages

    def test_apt_get_install_multiple(self) -> None:
        warnings = detect_syspkg_commands("apt-get install curl wget git")
        assert len(warnings) == 1
        assert set(warnings[0].packages) == {"curl", "wget", "git"}

    def test_apt_get_with_yes_flag(self) -> None:
        warnings = detect_syspkg_commands("apt-get install -y nginx")
        assert len(warnings) == 1
        assert "nginx" in warnings[0].packages

    def test_apt_get_update_ignored(self) -> None:
        warnings = detect_syspkg_commands("apt-get update")
        assert len(warnings) == 0

    def test_apt_install(self) -> None:
        warnings = detect_syspkg_commands("apt install vim")
        assert len(warnings) == 1
        assert warnings[0].manager == "apt"
        assert "vim" in warnings[0].packages


# ── sudo prefix ──────────────────────────────────────────────────────────────


class TestSudo:
    def test_sudo_apt_get_install(self) -> None:
        warnings = detect_syspkg_commands("sudo apt-get install curl")
        assert len(warnings) == 1
        assert warnings[0].manager == "apt-get"
        assert "curl" in warnings[0].packages

    def test_sudo_brew_install(self) -> None:
        # brew doesn't normally use sudo, but test the prefix stripping
        warnings = detect_syspkg_commands("sudo brew install node")
        assert len(warnings) == 1
        assert warnings[0].manager == "brew"
        assert "node" in warnings[0].packages

    def test_sudo_with_env(self) -> None:
        warnings = detect_syspkg_commands(
            "sudo DEBIAN_FRONTEND=noninteractive apt-get install curl"
        )
        assert len(warnings) == 1
        assert "curl" in warnings[0].packages


# ── yum ──────────────────────────────────────────────────────────────────────


class TestYum:
    def test_yum_install(self) -> None:
        warnings = detect_syspkg_commands("yum install httpd")
        assert len(warnings) == 1
        assert warnings[0].manager == "yum"
        assert "httpd" in warnings[0].packages

    def test_yum_install_with_y(self) -> None:
        warnings = detect_syspkg_commands("yum install -y gcc make")
        assert len(warnings) == 1
        assert "gcc" in warnings[0].packages
        assert "make" in warnings[0].packages


# ── dnf ──────────────────────────────────────────────────────────────────────


class TestDnf:
    def test_dnf_install(self) -> None:
        warnings = detect_syspkg_commands("dnf install python3-devel")
        assert len(warnings) == 1
        assert warnings[0].manager == "dnf"
        assert "python3-devel" in warnings[0].packages


# ── brew ─────────────────────────────────────────────────────────────────────


class TestBrew:
    def test_brew_install(self) -> None:
        warnings = detect_syspkg_commands("brew install jq")
        assert len(warnings) == 1
        assert warnings[0].manager == "brew"
        assert "jq" in warnings[0].packages

    def test_brew_install_multiple(self) -> None:
        warnings = detect_syspkg_commands("brew install node python@3.11 jq")
        assert len(warnings) == 1
        assert set(warnings[0].packages) == {"node", "python@3.11", "jq"}

    def test_brew_update_ignored(self) -> None:
        warnings = detect_syspkg_commands("brew update")
        assert len(warnings) == 0


# ── apk ──────────────────────────────────────────────────────────────────────


class TestApk:
    def test_apk_add(self) -> None:
        warnings = detect_syspkg_commands("apk add curl")
        assert len(warnings) == 1
        assert warnings[0].manager == "apk"
        assert "curl" in warnings[0].packages

    def test_apk_add_no_cache(self) -> None:
        warnings = detect_syspkg_commands("apk add --no-cache python3 py3-pip")
        assert len(warnings) == 1
        assert "python3" in warnings[0].packages
        assert "py3-pip" in warnings[0].packages

    def test_apk_del_ignored(self) -> None:
        warnings = detect_syspkg_commands("apk del curl")
        assert len(warnings) == 0


# ── pacman ───────────────────────────────────────────────────────────────────


class TestPacman:
    def test_pacman_sync(self) -> None:
        warnings = detect_syspkg_commands("pacman -S vim")
        assert len(warnings) == 1
        assert warnings[0].manager == "pacman"
        assert "vim" in warnings[0].packages

    def test_pacman_sync_update(self) -> None:
        warnings = detect_syspkg_commands("pacman -Syu base-devel")
        assert len(warnings) == 1
        assert "base-devel" in warnings[0].packages

    def test_pacman_query_ignored(self) -> None:
        warnings = detect_syspkg_commands("pacman -Q vim")
        assert len(warnings) == 0


# ── zypper ───────────────────────────────────────────────────────────────────


class TestZypper:
    def test_zypper_install(self) -> None:
        warnings = detect_syspkg_commands("zypper install gcc")
        assert len(warnings) == 1
        assert warnings[0].manager == "zypper"
        assert "gcc" in warnings[0].packages

    def test_zypper_in_shorthand(self) -> None:
        warnings = detect_syspkg_commands("zypper in vim nano")
        assert len(warnings) == 1
        assert "vim" in warnings[0].packages
        assert "nano" in warnings[0].packages


# ── pkg ──────────────────────────────────────────────────────────────────────


class TestPkg:
    def test_pkg_install(self) -> None:
        warnings = detect_syspkg_commands("pkg install nginx")
        assert len(warnings) == 1
        assert warnings[0].manager == "pkg"
        assert "nginx" in warnings[0].packages


# ── emerge ───────────────────────────────────────────────────────────────────


class TestEmerge:
    def test_emerge_package(self) -> None:
        warnings = detect_syspkg_commands("emerge dev-libs/openssl")
        assert len(warnings) == 1
        assert warnings[0].manager == "emerge"
        assert "dev-libs/openssl" in warnings[0].packages

    def test_emerge_with_ask(self) -> None:
        warnings = detect_syspkg_commands("emerge --ask vim")
        assert len(warnings) == 1
        assert "vim" in warnings[0].packages


# ── snap ─────────────────────────────────────────────────────────────────────


class TestSnap:
    def test_snap_install(self) -> None:
        warnings = detect_syspkg_commands("snap install firefox")
        assert len(warnings) == 1
        assert warnings[0].manager == "snap"
        assert "firefox" in warnings[0].packages

    def test_snap_install_classic(self) -> None:
        warnings = detect_syspkg_commands("snap install --classic code")
        assert len(warnings) == 1
        assert "code" in warnings[0].packages


# ── flatpak ──────────────────────────────────────────────────────────────────


class TestFlatpak:
    def test_flatpak_install(self) -> None:
        warnings = detect_syspkg_commands("flatpak install flathub org.mozilla.firefox")
        assert len(warnings) == 1
        assert warnings[0].manager == "flatpak"
        assert "flathub" in warnings[0].packages or "org.mozilla.firefox" in warnings[0].packages


# ── compound commands ────────────────────────────────────────────────────────


class TestCompoundCommands:
    def test_semicolon_separated(self) -> None:
        warnings = detect_syspkg_commands("apt-get update ; apt-get install curl")
        assert len(warnings) == 1
        assert warnings[0].manager == "apt-get"

    def test_and_separated(self) -> None:
        warnings = detect_syspkg_commands("apt-get update && apt-get install -y curl wget")
        assert len(warnings) == 1
        assert "curl" in warnings[0].packages

    def test_pipe_separated(self) -> None:
        warnings = detect_syspkg_commands("echo yes | apt-get install curl")
        assert len(warnings) == 1

    def test_multiple_managers(self) -> None:
        warnings = detect_syspkg_commands("brew install jq && snap install firefox")
        assert len(warnings) == 2
        managers = {w.manager for w in warnings}
        assert managers == {"brew", "snap"}

    def test_mixed_pip_and_apt(self) -> None:
        """pip install is NOT detected by syspkg (it's a language package manager)."""
        warnings = detect_syspkg_commands("apt-get install curl && pip install requests")
        assert len(warnings) == 1
        assert warnings[0].manager == "apt-get"


# ── edge cases ───────────────────────────────────────────────────────────────


class TestEdgeCases:
    def test_empty_string(self) -> None:
        assert detect_syspkg_commands("") == []

    def test_no_package_manager(self) -> None:
        assert detect_syspkg_commands("ls -la") == []

    def test_pip_not_detected(self) -> None:
        """pip is a language package manager, not a system one."""
        assert detect_syspkg_commands("pip install requests") == []

    def test_npm_not_detected(self) -> None:
        assert detect_syspkg_commands("npm install lodash") == []

    def test_cargo_not_detected(self) -> None:
        assert detect_syspkg_commands("cargo add serde") == []

    def test_rule_id(self) -> None:
        warnings = detect_syspkg_commands("brew install jq")
        assert warnings[0].rule_id == "SP1.1"

    def test_severity(self) -> None:
        warnings = detect_syspkg_commands("brew install jq")
        assert warnings[0].severity == "INFO"

    def test_title_with_packages(self) -> None:
        warnings = detect_syspkg_commands("brew install jq")
        assert "jq" in warnings[0].title
        assert "brew" in warnings[0].title

    def test_title_without_packages(self) -> None:
        w = SysPkgWarning(manager="brew")
        assert "brew" in w.title
        assert "invoked" in w.title

    def test_raw_fragment_captured(self) -> None:
        warnings = detect_syspkg_commands("sudo apt-get install curl")
        assert warnings[0].raw_fragment != ""
