"""System package manager detection for shell commands.

Detects invocations of system-level package managers (apt-get, yum, dnf, brew,
apk, pacman, zypper, pkg, emerge, snap, flatpak) in shell command strings.
These are **warning-only** — AgentShield does not block system package installs,
but flags them so operators are aware an AI agent is modifying the host OS.

Rule ID: SP1.1
Severity: INFO
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field


@dataclass(frozen=True)
class SysPkgWarning:
    """A single system-package-manager invocation detected in a shell command."""

    manager: str
    """Canonical name of the package manager (e.g. ``apt-get``, ``brew``)."""

    packages: list[str] = field(default_factory=list)
    """Package names extracted from the command, if parseable."""

    raw_fragment: str = ""
    """The substring of the original command that matched."""

    rule_id: str = "SP1.1"
    severity: str = "INFO"

    @property
    def title(self) -> str:
        if self.packages:
            pkg_str = ", ".join(self.packages)
            return f"System package manager '{self.manager}' installing: {pkg_str}"
        return f"System package manager '{self.manager}' invoked"


# ── install sub-commands per manager ────────────────────────────────────────

# Maps binary name → set of sub-commands that trigger an install.
_INSTALL_SUBCOMMANDS: dict[str, frozenset[str]] = {
    "apt-get": frozenset({"install"}),
    "apt": frozenset({"install"}),
    "yum": frozenset({"install"}),
    "dnf": frozenset({"install"}),
    "brew": frozenset({"install"}),
    "apk": frozenset({"add"}),
    "pacman": frozenset({"-S", "-Sy", "-Syu", "-Syyu"}),
    "zypper": frozenset({"install", "in"}),
    "pkg": frozenset({"install"}),
    "emerge": frozenset(),  # emerge takes packages directly (no install sub-command)
    "snap": frozenset({"install"}),
    "flatpak": frozenset({"install"}),
}

_ALL_MANAGERS = frozenset(_INSTALL_SUBCOMMANDS.keys())

# Flags that consume the next token (package managers share common patterns).
_SKIP_VALUE_FLAGS: frozenset[str] = frozenset(
    {
        # Common across many managers
        "-t",
        "--target-release",
        "-o",
        "--option",
        "--root",
        "--config",
        # brew
        "--appdir",
        "--caskroom",
        # apk
        "--repository",
        "-X",
        # zypper / flatpak
        "--from",
        "--repo",
        # flatpak
        "--installation",
    }
)


def detect_syspkg_commands(cmd: str) -> list[SysPkgWarning]:
    """Parse *cmd* for system package manager invocations.

    Handles compound commands (``&&``, ``||``, ``;``, ``|``) and ``sudo``
    prefixes.  Returns one :class:`SysPkgWarning` per detected invocation.
    """
    warnings: list[SysPkgWarning] = []

    for fragment in _split_compound(cmd):
        fragment = fragment.strip()
        if not fragment:
            continue

        tokens = _safe_split(fragment)
        if not tokens:
            continue

        # Strip leading sudo / env prefixes
        idx = 0
        while idx < len(tokens) and tokens[idx] in ("sudo", "env"):
            idx += 1
            # Skip env VAR=val pairs / sudo flags
            while idx < len(tokens) and ("=" in tokens[idx] or tokens[idx].startswith("-")):
                idx += 1

        if idx >= len(tokens):
            continue

        binary = tokens[idx]
        rest = tokens[idx + 1 :]

        if binary not in _ALL_MANAGERS:
            continue

        install_subs = _INSTALL_SUBCOMMANDS[binary]

        # Special case: emerge has no install sub-command
        if binary == "emerge":
            pkgs = _extract_packages(rest)
            if pkgs or rest:
                warnings.append(
                    SysPkgWarning(
                        manager=binary,
                        packages=pkgs,
                        raw_fragment=fragment,
                    )
                )
            continue

        # Special case: pacman uses -S flags
        if binary == "pacman":
            warning = _detect_pacman(rest, fragment)
            if warning:
                warnings.append(warning)
            continue

        # Generic: first non-flag token must be an install sub-command
        if not rest:
            continue

        subcmd = rest[0]
        if subcmd not in install_subs:
            continue

        pkgs = _extract_packages(rest[1:])
        warnings.append(
            SysPkgWarning(
                manager=binary,
                packages=pkgs,
                raw_fragment=fragment,
            )
        )

    return warnings


# ── internal helpers ─────────────────────────────────────────────────────────

# Regex to split on shell compound operators while preserving them for context.
_COMPOUND_RE = re.compile(r"\s*(?:&&|\|\|?|;)\s*")


def _split_compound(cmd: str) -> list[str]:
    """Split a shell command on ``&&``, ``||``, ``|``, and ``;``."""
    return [frag for frag in _COMPOUND_RE.split(cmd) if frag]


def _safe_split(fragment: str) -> list[str]:
    """Shell-split *fragment*, falling back to whitespace split on error."""
    try:
        return shlex.split(fragment)
    except ValueError:
        return fragment.split()


def _detect_pacman(args: list[str], fragment: str) -> SysPkgWarning | None:
    """Detect pacman install operations (-S, -Sy, -Syu, etc.)."""
    install_flag = False
    for token in args:
        if token.startswith("-") and "S" in token and not token.startswith("--"):
            install_flag = True
            break
    if not install_flag:
        return None
    pkgs = _extract_packages(args)
    return SysPkgWarning(manager="pacman", packages=pkgs, raw_fragment=fragment)


def _extract_packages(tokens: list[str]) -> list[str]:
    """Extract likely package names from a token list, skipping flags."""
    packages: list[str] = []
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token.startswith("-"):
            # Skip value-consuming flags
            if token in _SKIP_VALUE_FLAGS and i + 1 < len(tokens):
                i += 2
            else:
                i += 1
            continue
        # Skip tokens that look like paths, URLs, or env assignments
        if re.match(r"^[/~.]|^https?://|=", token):
            i += 1
            continue
        packages.append(token)
        i += 1
    return packages
