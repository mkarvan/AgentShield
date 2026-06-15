"""AgentShield Guard — interactive shell wrapper.

Wraps the user's shell session and intercepts ``pip install``, ``npm install``,
and ``cargo add``/``cargo install`` commands in real-time before they execute.

Implementation strategy
-----------------------
Shell function shadowing: the guard generates a shell init-script that defines
wrapper functions (``pip``, ``npm``, ``cargo``) which call
``agentshield guard-scan-cmd "<full command>"`` before delegating to the real
binary with ``command pip …``.  A non-zero exit from the guard command causes
the wrapper to abort the install.

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

# ── shell init scripts ────────────────────────────────────────────────────────

_BASH_INIT = """\
# AgentShield Guard — bash integration
# Wrapper functions shadow pip, npm, and cargo.  Install commands are
# checked by AgentShield before execution; the install is aborted on BLOCK.
# System package managers (apt-get, brew, etc.) emit warnings but do not block.

function pip() {
    if [[ "$1" == "install" ]]; then
        agentshield guard-scan-cmd pip "$@" || return 1
    fi
    command pip "$@"
}

function pip3() {
    if [[ "$1" == "install" ]]; then
        agentshield guard-scan-cmd pip3 "$@" || return 1
    fi
    command pip3 "$@"
}

function npm() {
    if [[ "$1" == "install" || "$1" == "i" ]]; then
        agentshield guard-scan-cmd npm "$@" || return 1
    fi
    command npm "$@"
}

function cargo() {
    if [[ "$1" == "add" || "$1" == "install" ]]; then
        agentshield guard-scan-cmd cargo "$@" || return 1
    fi
    command cargo "$@"
}

# System package managers — CVE scan may block if critical vulns found (v0.9.0)
# Note: -- stops typer from interpreting package-manager flags (e.g. pacman -S)
function apt-get() {
    if [[ "$1" == "install" ]]; then
        agentshield guard-scan-cmd -- apt-get "$@" || return 1
    fi
    command apt-get "$@"
}

function apt() {
    if [[ "$1" == "install" ]]; then
        agentshield guard-scan-cmd -- apt "$@" || return 1
    fi
    command apt "$@"
}

function yum() {
    if [[ "$1" == "install" ]]; then
        agentshield guard-scan-cmd -- yum "$@" || return 1
    fi
    command yum "$@"
}

function dnf() {
    if [[ "$1" == "install" ]]; then
        agentshield guard-scan-cmd -- dnf "$@" || return 1
    fi
    command dnf "$@"
}

function brew() {
    if [[ "$1" == "install" ]]; then
        agentshield guard-scan-cmd -- brew "$@" || return 1
    fi
    command brew "$@"
}

function apk() {
    if [[ "$1" == "add" ]]; then
        agentshield guard-scan-cmd -- apk "$@" || return 1
    fi
    command apk "$@"
}

function pacman() {
    agentshield guard-scan-cmd -- pacman "$@" || return 1
    command pacman "$@"
}

function zypper() {
    if [[ "$1" == "install" || "$1" == "in" ]]; then
        agentshield guard-scan-cmd -- zypper "$@" || return 1
    fi
    command zypper "$@"
}

function snap() {
    if [[ "$1" == "install" ]]; then
        agentshield guard-scan-cmd -- snap "$@" || return 1
    fi
    command snap "$@"
}

function flatpak() {
    if [[ "$1" == "install" ]]; then
        agentshield guard-scan-cmd -- flatpak "$@" || return 1
    fi
    command flatpak "$@"
}

export PS1="[guard] $PS1"
echo "[AgentShield Guard] Active — pip, npm, and cargo install commands are protected."
echo "[AgentShield Guard] System package managers (apt-get, brew, etc.) are monitored with CVE scanning."
"""

_ZSH_INIT = """\
# AgentShield Guard — zsh integration

function pip() {
    if [[ "$1" == "install" ]]; then
        agentshield guard-scan-cmd pip "$@" || return 1
    fi
    command pip "$@"
}

function pip3() {
    if [[ "$1" == "install" ]]; then
        agentshield guard-scan-cmd pip3 "$@" || return 1
    fi
    command pip3 "$@"
}

function npm() {
    if [[ "$1" == "install" || "$1" == "i" ]]; then
        agentshield guard-scan-cmd npm "$@" || return 1
    fi
    command npm "$@"
}

function cargo() {
    if [[ "$1" == "add" || "$1" == "install" ]]; then
        agentshield guard-scan-cmd cargo "$@" || return 1
    fi
    command cargo "$@"
}

# System package managers — CVE scan may block if critical vulns found (v0.9.0)
# Note: -- stops typer from interpreting package-manager flags (e.g. pacman -S)
function apt-get() {
    if [[ "$1" == "install" ]]; then
        agentshield guard-scan-cmd -- apt-get "$@" || return 1
    fi
    command apt-get "$@"
}

function apt() {
    if [[ "$1" == "install" ]]; then
        agentshield guard-scan-cmd -- apt "$@" || return 1
    fi
    command apt "$@"
}

function yum() {
    if [[ "$1" == "install" ]]; then
        agentshield guard-scan-cmd -- yum "$@" || return 1
    fi
    command yum "$@"
}

function dnf() {
    if [[ "$1" == "install" ]]; then
        agentshield guard-scan-cmd -- dnf "$@" || return 1
    fi
    command dnf "$@"
}

function brew() {
    if [[ "$1" == "install" ]]; then
        agentshield guard-scan-cmd -- brew "$@" || return 1
    fi
    command brew "$@"
}

function apk() {
    if [[ "$1" == "add" ]]; then
        agentshield guard-scan-cmd -- apk "$@" || return 1
    fi
    command apk "$@"
}

function pacman() {
    agentshield guard-scan-cmd -- pacman "$@" || return 1
    command pacman "$@"
}

function zypper() {
    if [[ "$1" == "install" || "$1" == "in" ]]; then
        agentshield guard-scan-cmd -- zypper "$@" || return 1
    fi
    command zypper "$@"
}

function snap() {
    if [[ "$1" == "install" ]]; then
        agentshield guard-scan-cmd -- snap "$@" || return 1
    fi
    command snap "$@"
}

function flatpak() {
    if [[ "$1" == "install" ]]; then
        agentshield guard-scan-cmd -- flatpak "$@" || return 1
    fi
    command flatpak "$@"
}

export PROMPT="[guard] $PROMPT"
echo "[AgentShield Guard] Active — pip, npm, and cargo install commands are protected."
echo "[AgentShield Guard] System package managers (apt-get, brew, etc.) are monitored with CVE scanning."
"""

_FISH_INIT = """\
# AgentShield Guard — fish integration

function pip
    if test "$argv[1]" = "install"
        agentshield guard-scan-cmd pip $argv; or return 1
    end
    command pip $argv
end

function pip3
    if test "$argv[1]" = "install"
        agentshield guard-scan-cmd pip3 $argv; or return 1
    end
    command pip3 $argv
end

function npm
    if test "$argv[1]" = "install"; or test "$argv[1]" = "i"
        agentshield guard-scan-cmd npm $argv; or return 1
    end
    command npm $argv
end

function cargo
    if test "$argv[1]" = "add"; or test "$argv[1]" = "install"
        agentshield guard-scan-cmd cargo $argv; or return 1
    end
    command cargo $argv
end

# System package managers — CVE scan may block if critical vulns found (v0.9.0)
# Note: -- stops typer from interpreting package-manager flags (e.g. pacman -S)
function apt-get
    if test "$argv[1]" = "install"
        agentshield guard-scan-cmd -- apt-get $argv; or return 1
    end
    command apt-get $argv
end

function apt
    if test "$argv[1]" = "install"
        agentshield guard-scan-cmd -- apt $argv; or return 1
    end
    command apt $argv
end

function yum
    if test "$argv[1]" = "install"
        agentshield guard-scan-cmd -- yum $argv; or return 1
    end
    command yum $argv
end

function dnf
    if test "$argv[1]" = "install"
        agentshield guard-scan-cmd -- dnf $argv; or return 1
    end
    command dnf $argv
end

function brew
    if test "$argv[1]" = "install"
        agentshield guard-scan-cmd -- brew $argv; or return 1
    end
    command brew $argv
end

function apk
    if test "$argv[1]" = "add"
        agentshield guard-scan-cmd -- apk $argv; or return 1
    end
    command apk $argv
end

function pacman
    agentshield guard-scan-cmd -- pacman $argv; or return 1
    command pacman $argv
end

function zypper
    if test "$argv[1]" = "install"; or test "$argv[1]" = "in"
        agentshield guard-scan-cmd -- zypper $argv; or return 1
    end
    command zypper $argv
end

function snap
    if test "$argv[1]" = "install"
        agentshield guard-scan-cmd -- snap $argv; or return 1
    end
    command snap $argv
end

function flatpak
    if test "$argv[1]" = "install"
        agentshield guard-scan-cmd -- flatpak $argv; or return 1
    end
    command flatpak $argv
end

echo "[AgentShield Guard] Active — pip, npm, and cargo install commands are protected."
echo "[AgentShield Guard] System package managers (apt-get, brew, etc.) are monitored with CVE scanning."
"""

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
