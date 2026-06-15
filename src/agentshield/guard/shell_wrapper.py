"""AgentShield Guard — interactive shell wrapper.

Wraps the user's shell session and intercepts package-install commands in
real-time before they execute.

Implementation strategy
-----------------------
Shell function shadowing: the guard generates a shell init-script that defines
wrapper functions shadowing every supported package-manager binary (pip, pip3,
``python``/``python3`` for ``-m pip``, uv, npm, yarn, pnpm, bun, cargo, poetry,
pipx, conda, gem, go).  Each wrapper calls ``agentshield guard-scan-cmd
"<full command>"`` before delegating to the real binary with ``command pip …``.
A non-zero exit from the guard command aborts the install.

The set of shadowed binaries and their install-trigger tokens is derived from
:mod:`agentshield.enforce.registry` (the single source of truth) so coverage is
defined in exactly one place.  System package managers (apt-get, brew, etc.)
are additionally shadowed for CVE-scan warnings.

Shell support: bash, zsh, fish (defaults to bash-compatible for unknown shells).

Usage:
    agentshield guard             # wraps $SHELL
    agentshield guard --shell zsh # wraps a specific shell
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from agentshield.enforce.registry import MANAGERS

# ── derive the shadow set + gating tokens from the registry ───────────────────


def _language_gates() -> dict[str, list[str]]:
    """Map each managed binary -> sorted list of first-token install triggers."""
    gates: dict[str, set[str]] = {}
    for spec in MANAGERS:
        for binary in spec.binaries:
            gates.setdefault(binary, set()).update(spec.trigger_tokens)
    return {b: sorted(t) for b, t in sorted(gates.items())}


# System package managers — warn-only (CVE scan may block). Kept explicit
# because they are detected by syspkg_detector, not the registry, and use the
# ``--`` separator so typer does not interpret manager flags (e.g. ``pacman -S``).
# A value of ``None`` means "always scan" (no sub-command gate).
_SYSPKG_GATES: dict[str, list[str] | None] = {
    "apt-get": ["install"],
    "apt": ["install"],
    "yum": ["install"],
    "dnf": ["install"],
    "brew": ["install"],
    "apk": ["add"],
    "pacman": None,
    "zypper": ["in", "install"],
    "snap": ["install"],
    "flatpak": ["install"],
}

_GUARD_MSG_LANG = (
    "[AgentShield Guard] Active — pip, npm, cargo, and other package "
    "install commands are protected."
)
_GUARD_MSG_SYS = (
    "[AgentShield Guard] System package managers (apt-get, brew, etc.) "
    "are monitored with CVE scanning."
)


# ── POSIX (bash/zsh) generation ───────────────────────────────────────────────


def _posix_lang_fn(binary: str, triggers: list[str]) -> str:
    call = f'agentshield guard-scan-cmd {binary} "$@" || return 1'
    if triggers:
        cond = " || ".join(f'"$1" == "{t}"' for t in triggers)
        body = f"    if [[ {cond} ]]; then\n        {call}\n    fi\n"
    else:
        body = f"    {call}\n"
    return f"function {binary}() {{\n{body}    command {binary} \"$@\"\n}}\n"


def _posix_sys_fn(binary: str, triggers: list[str] | None) -> str:
    call = f'agentshield guard-scan-cmd -- {binary} "$@" || return 1'
    if triggers:
        cond = " || ".join(f'"$1" == "{t}"' for t in triggers)
        body = f"    if [[ {cond} ]]; then\n        {call}\n    fi\n"
    else:
        body = f"    {call}\n"
    return f"function {binary}() {{\n{body}    command {binary} \"$@\"\n}}\n"


def _build_posix(prompt_line: str) -> str:
    parts = [
        "# AgentShield Guard — POSIX shell integration\n",
        "# Wrapper functions shadow package managers. Install commands are checked\n",
        "# by AgentShield before execution; the install is aborted on BLOCK.\n\n",
    ]
    for binary, triggers in _language_gates().items():
        parts.append(_posix_lang_fn(binary, triggers))
    parts.append(
        "\n# System package managers — CVE scan may block if critical vulns found.\n"
        "# Note: -- stops typer from interpreting package-manager flags (e.g. pacman -S)\n"
    )
    for binary, triggers in _SYSPKG_GATES.items():
        parts.append(_posix_sys_fn(binary, triggers))
    parts.append(f"\n{prompt_line}\n")
    parts.append(f'echo "{_GUARD_MSG_LANG}"\n')
    parts.append(f'echo "{_GUARD_MSG_SYS}"\n')
    return "".join(parts)


# ── fish generation ───────────────────────────────────────────────────────────


def _fish_fn(binary: str, triggers: list[str] | None, *, sep: str) -> str:
    call = f"agentshield guard-scan-cmd {sep}{binary} $argv; or return 1"
    if triggers:
        cond = "; or ".join(f'test "$argv[1]" = "{t}"' for t in triggers)
        body = f"    if {cond}\n        {call}\n    end\n"
    else:
        body = f"    {call}\n"
    return f"function {binary}\n{body}    command {binary} $argv\nend\n"


def _build_fish() -> str:
    parts = ["# AgentShield Guard — fish integration\n\n"]
    for binary, triggers in _language_gates().items():
        parts.append(_fish_fn(binary, triggers, sep=""))
    parts.append(
        "\n# System package managers — CVE scan may block if critical vulns found.\n"
        "# Note: -- stops fish/typer from interpreting package-manager flags.\n"
    )
    for binary, triggers in _SYSPKG_GATES.items():
        parts.append(_fish_fn(binary, triggers, sep="-- "))
    parts.append(f'\necho "{_GUARD_MSG_LANG}"\n')
    parts.append(f'echo "{_GUARD_MSG_SYS}"\n')
    return "".join(parts)


# ── generated init scripts ────────────────────────────────────────────────────

_BASH_INIT = _build_posix('export PS1="[guard] $PS1"')
_ZSH_INIT = _build_posix('export PROMPT="[guard] $PROMPT"')
_FISH_INIT = _build_fish()

_SHELL_SCRIPTS: dict[str, str] = {
    "bash": _BASH_INIT,
    "zsh": _ZSH_INIT,
    "fish": _FISH_INIT,
}


class ShellGuard:
    """Generate and launch a guarded shell session."""

    def generate_guard_script(self, shell: str) -> str:
        """Return the init-script content appropriate for *shell*.

        Falls back to bash-compatible syntax for unrecognised shell names.
        """
        shell_name = Path(shell).name
        return _SHELL_SCRIPTS.get(shell_name, _BASH_INIT)

    def start(self, shell: str | None = None) -> int:
        """Write the guard init-script and launch the shell.

        Returns the shell's exit code.  The temporary init file is removed
        after the shell session ends.
        """
        resolved_shell = shell or os.environ.get("SHELL") or shutil.which("bash") or "/bin/bash"
        script = self.generate_guard_script(resolved_shell)
        shell_name = Path(resolved_shell).name

        if shell_name == "zsh":
            return self._start_zsh(resolved_shell, script)
        if shell_name == "fish":
            return self._start_fish(resolved_shell, script)
        return self._start_bash_compatible(resolved_shell, script)

    # ── per-shell launchers ───────────────────────────────────────────────────

    def _start_bash_compatible(self, shell: str, script: str) -> int:
        init_file = self._write_temp_script(script, suffix=".sh")
        try:
            result = subprocess.run([shell, "--rcfile", init_file])
            return result.returncode
        finally:
            _unlink(init_file)

    def _start_zsh(self, shell: str, script: str) -> int:
        zsh_dir = tempfile.mkdtemp(prefix="agentshield_zsh_")
        try:
            zshrc = Path(zsh_dir) / ".zshrc"
            zshrc.write_text(script)
            env = {**os.environ, "ZDOTDIR": zsh_dir}
            result = subprocess.run([shell], env=env)
            return result.returncode
        finally:
            _rmtree(zsh_dir)

    def _start_fish(self, shell: str, script: str) -> int:
        init_file = self._write_temp_script(script, suffix=".fish")
        try:
            result = subprocess.run([shell, "--init-command", Path(init_file).read_text()])
            return result.returncode
        finally:
            _unlink(init_file)

    # ── helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _write_temp_script(content: str, suffix: str = ".sh") -> str:
        fd, path = tempfile.mkstemp(prefix="agentshield_guard_", suffix=suffix)
        try:
            os.write(fd, content.encode())
        finally:
            os.close(fd)
        return path


def _unlink(path: str) -> None:
    import contextlib

    with contextlib.suppress(OSError):
        os.unlink(path)


def _rmtree(path: str) -> None:
    import contextlib
    import shutil as _shutil

    with contextlib.suppress(OSError):
        _shutil.rmtree(path)
