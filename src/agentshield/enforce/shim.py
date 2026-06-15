"""PATH shim — the portable, no-privilege enforcement baseline.

Installs a directory of wrapper scripts (one per managed binary, taken from
:func:`agentshield.enforce.registry.shadow_binaries`) and instructs the caller
to prepend that directory to ``PATH``.  Each wrapper scans the invocation with
``agentshield guard-scan-cmd`` (which fails closed) and, only if cleared, locates
and ``exec``s the *real* binary further down ``PATH``.

Because the shim dir sits first on ``PATH``, this covers bare-name invocations
(``pip install …``) and shell ``command pip`` lookups.  It does **not** cover
absolute-path invocations (``/usr/bin/pip``) or processes that reset ``PATH`` —
that gap is closed by the ``execve`` interceptor (:mod:`agentshield.enforce.execve`).

This module only *generates and installs* the shim; it performs no scanning
itself (that is delegated to ``guard-scan-cmd`` at runtime).
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from agentshield.enforce.registry import shadow_binaries

_WRAPPER_TEMPLATE = """\
#!/usr/bin/env bash
# AgentShield PATH shim for `{binary}` — generated; do not edit.
# Scans the invocation (fail-closed) then execs the real binary.
set -uo pipefail
AGENTSHIELD_BIN="${{AGENTSHIELD_BIN:-agentshield}}"

# 1. Scan. A non-zero exit blocks the install.
if ! "$AGENTSHIELD_BIN" guard-scan-cmd {binary} "$@"; then
    exit 1
fi

# 2. Resolve the real `{binary}`, skipping this shim directory.
SELF_DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd -P)"
REAL=""
IFS=':' read -ra _as_paths <<< "$PATH"
for _d in "${{_as_paths[@]}}"; do
    [ -z "$_d" ] && continue
    _rp="$(cd "$_d" 2>/dev/null && pwd -P || true)"
    [ "$_rp" = "$SELF_DIR" ] && continue
    if [ -x "$_d/{binary}" ]; then REAL="$_d/{binary}"; break; fi
done
if [ -z "$REAL" ]; then
    echo "agentshield-shim: real '{binary}' not found on PATH" >&2
    exit 127
fi
exec "$REAL" "$@"
"""

_MARKER = "# AgentShield PATH shim for"


def default_shim_dir() -> Path:
    """Default location for the shim directory."""
    return Path(os.environ.get("AGENTSHIELD_HOME", Path.home() / ".agentshield")) / "shim"


def wrapper_script(binary: str) -> str:
    """Return the wrapper-script text for *binary*."""
    return _WRAPPER_TEMPLATE.format(binary=binary)


def install(shim_dir: Path | None = None) -> tuple[Path, list[str]]:
    """Write a wrapper for every managed binary into *shim_dir*.

    Returns ``(shim_dir, installed_binaries)``.  Existing files are overwritten
    only when they are AgentShield-generated (carry the marker) or absent.
    """
    target = Path(shim_dir) if shim_dir else default_shim_dir()
    target.mkdir(parents=True, exist_ok=True)
    installed: list[str] = []
    for binary in shadow_binaries():
        path = target / binary
        if path.exists() and _MARKER not in path.read_text():
            # Don't clobber a non-AgentShield file that happens to share the name.
            continue
        path.write_text(wrapper_script(binary))
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        installed.append(binary)
    return target, installed


def uninstall(shim_dir: Path | None = None) -> list[str]:
    """Remove AgentShield-generated wrappers from *shim_dir*.

    Returns the list of removed binaries.  Only files carrying the marker are
    removed; foreign files are left untouched.
    """
    target = Path(shim_dir) if shim_dir else default_shim_dir()
    removed: list[str] = []
    if not target.is_dir():
        return removed
    for binary in shadow_binaries():
        path = target / binary
        if path.exists() and _MARKER in path.read_text():
            path.unlink()
            removed.append(binary)
    return removed


def path_export_line(shim_dir: Path) -> str:
    """Shell line the user must add so the shim takes precedence on ``PATH``."""
    return f'export PATH="{shim_dir}:$PATH"'
