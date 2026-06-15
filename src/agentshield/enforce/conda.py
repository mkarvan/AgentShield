"""Conda channel-aware parsing.

``conda`` is not a flat PyPI-style index: the same package name can be served by
different *channels* (``defaults``, ``conda-forge``, third-party channels), and a
malicious or typosquatted channel can ship a trojaned build under an otherwise
benign name.  Treating every ``conda install`` as a plain PyPI lookup (the old
best-effort behaviour) ignores where the package actually comes from.

This module resolves the channel for each requested package and classifies it:

* **Trusted channel** (``defaults``/``conda-forge``/etc., or no channel → default
  channels) → the package is scanned best-effort against PyPI (names largely
  overlap), since no dedicated conda vulnerability backend exists yet.
* **Untrusted channel** (any channel not in the trusted set, whether given via
  ``-c``/``--channel`` or ``channel::package`` spec) → the source cannot be
  verified, so callers operating fail-closed should block it.

Channel syntax handled:
  * ``conda install -c conda-forge numpy``          (command-level channel)
  * ``conda install --channel bad-chan pkg``         (long form)
  * ``conda install conda-forge::numpy``             (per-package ``channel::pkg``)
  * version specs: ``numpy=1.24``, ``numpy==1.24``, ``numpy>=1.20``
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Channels maintained by Anaconda or widely-trusted community orgs. Conservative
# on purpose; everything else is treated as unverifiable.
TRUSTED_CHANNELS: frozenset[str] = frozenset(
    {
        "defaults",
        "main",
        "r",
        "anaconda",
        "free",
        "pro",
        "msys2",
        "conda-forge",
        "bioconda",
        "pkgs/main",
        "pkgs/r",
        "pkgs/free",
        "pytorch",
        "nvidia",
    }
)

# Flags (used without ``=``) whose following token is a value, not a package.
_VALUE_FLAGS: frozenset[str] = frozenset(
    {"-c", "--channel", "-n", "--name", "-p", "--prefix", "--override-channels"}
)

# Bare package name at the start of a spec (channel/version stripped already).
_NAME_RE = re.compile(r"^([A-Za-z0-9_][A-Za-z0-9._-]*)")


@dataclass(frozen=True)
class CondaPackage:
    """A package requested from a ``conda install`` invocation."""

    name: str
    channel: str | None  # explicit channel (``chan::pkg`` or -c when unambiguous)
    trusted: bool


def is_trusted_channel(channel: str | None) -> bool:
    """A ``None`` channel means the default channels are used → trusted."""
    if channel is None:
        return True
    return channel in TRUSTED_CHANNELS


def parse_conda_install(args: list[str]) -> list[CondaPackage]:
    """Parse the tokens *after* ``conda install`` into classified packages.

    ``args`` is the argument vector following the ``install`` subcommand.
    """
    command_channels: list[str] = []
    package_tokens: list[str] = []

    i = 0
    while i < len(args):
        token = args[i]
        if token.startswith("-"):
            flag, eq, inline = token.partition("=")
            if flag in {"-c", "--channel"}:
                if eq and inline:
                    command_channels.append(inline)
                elif i + 1 < len(args):
                    command_channels.append(args[i + 1])
                    i += 1
            elif flag in _VALUE_FLAGS and not eq:
                i += 1  # consume the flag's value token
            # other flags / inline-value flags: skip the flag only
            i += 1
            continue
        package_tokens.append(token)
        i += 1

    cmd_channels_trusted = all(c in TRUSTED_CHANNELS for c in command_channels)

    packages: list[CondaPackage] = []
    for token in package_tokens:
        explicit_channel: str | None = None
        spec = token
        if "::" in token:
            explicit_channel, _, spec = token.partition("::")
        name_match = _NAME_RE.match(spec)
        if not name_match:
            continue
        name = name_match.group(1)
        if explicit_channel is not None:
            trusted = explicit_channel in TRUSTED_CHANNELS
            channel: str | None = explicit_channel
        else:
            trusted = cmd_channels_trusted
            # Record a representative command-level channel if exactly one untrusted.
            channel = next((c for c in command_channels if c not in TRUSTED_CHANNELS), None)
        packages.append(CondaPackage(name=name, channel=channel, trusted=trusted))

    return packages
