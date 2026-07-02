"""Package-manager registry — the single source of truth for coverage.

Every layer that needs to recognise a package-install invocation reads from
this module so coverage is defined exactly once:

* the Hermes plugin parser (:mod:`agentshield.integrations.hermes.plugin`)
* the ``agentshield guard`` shell shadowing (:mod:`agentshield.guard.shell_wrapper`)
* ``agentshield guard-scan-cmd`` (:mod:`agentshield.cli`)
* the PATH shim, ``execve`` interceptor and index proxy (:mod:`agentshield.enforce`)

Two consumption modes are provided:

``parse_command(command_string)``
    Free-form parsing of a shell command line (used by the Hermes plugin and
    ``guard-scan-cmd``).  Handles chained commands, line continuations, and
    de-duplicates overlapping matches (e.g. ``uv pip install`` is not also
    matched as a bare ``pip install``).

``parse_argv([binary, *args])``
    Exact parsing of an already-split argument vector (used by the shim and the
    ``execve`` interceptor where the binary and its arguments are known
    precisely).

Coverage (manager -> ecosystem):

==================  =========  ===============================================
Manager             Ecosystem  Install trigger(s)
==================  =========  ===============================================
pip / pip3          PyPI       ``install``
python -m pip       PyPI       ``-m pip install``
uv pip              PyPI       ``pip install``
uv add              PyPI       ``add``
pipx                PyPI       ``install``
poetry              PyPI       ``add``
conda               PyPI*      ``install``   (*scanned best-effort as PyPI)
npm                 npm        ``install`` / ``i``
yarn                npm        ``add``
pnpm                npm        ``add`` / ``install``
bun                 npm        ``add`` / ``install``
cargo               crates.io  ``add`` / ``install``
gem                 RubyGems   ``install``   (no scan backend -> unverifiable)
go                  Go         ``install``   (no scan backend -> unverifiable)
==================  =========  ===============================================

Managers whose ``ecosystem`` is ``None`` are *recognised but unverifiable*:
there is no scanning backend for them yet, so callers operating fail-closed
should treat a detected install as "cannot verify" (block) rather than silently
allow it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from agentshield.core.models import Ecosystem

# ── token-level helpers (shared by every layer) ───────────────────────────────

# Flags that consume the following token as their value when written without ``=``.
#
# IMPORTANT: only list flags that genuinely take a value. A *boolean* flag listed
# here makes the tokenizer swallow the following token (the package name!), which
# silently hides the install from scanning — e.g. ``npm install --save-exact lodash``
# would parse to zero packages. Boolean npm/yarn/pnpm/bun flags such as
# ``--save-exact``/``-E``, ``--save-dev``/``-D``, ``--save-optional``/``-O``,
# ``--save-prod``/``-P``, ``--global``/``-g``, ``--save-peer`` and ``--no-save``
# must therefore NOT appear here.
VALUE_FLAGS: frozenset[str] = frozenset(
    {
        # pip / pip3 / uv pip / pipx
        "-t",
        "--target",
        "-d",
        "--download",
        "-i",
        "--index-url",
        "--extra-index-url",
        "-r",
        "--requirement",
        "-c",
        "--constraint",
        "-f",
        "--find-links",
        "--trusted-host",
        "--proxy",
        "--retries",
        "--timeout",
        "--exists-action",
        "--cert",
        "--client-cert",
        "--cache-dir",
        "-e",
        "--editable",
        "--platform",
        "--python-version",
        "--abi",
        "--implementation",
        "--prefix",
        "--src",
        "--root",
        "--python",
        # npm / yarn / pnpm / bun
        "--registry",
        "--tag",
        "--scope",
        "-w",
        "--workspace",
        "--cwd",
        # cargo / poetry
        "--version",
        "-p",
        "--package",
        "--manifest-path",
        "--source",
        # conda
        "-n",
        "--name",
        "--channel",
        # go
        "-mod",
    }
)

# Matches a valid package spec and captures the bare name in group 1.
# Handles: requests, requests==2.28.0, requests[security], requests[security]>=2,
# @scope/pkg (npm), serde@1.0 (cargo).
_PKG_SPEC_RE = re.compile(r"^(@?[A-Za-z0-9][A-Za-z0-9._/-]*)(?:\[[^\]]*\])?(?:[><=!~^@][^\s]*)?$")

# Patterns in install args that cannot be statically resolved.
_EXPANSION_RE = re.compile(r"\$(?:\{[^}]*\}|\([^)]*\)|[A-Za-z_][A-Za-z0-9_]*)")
_GIT_URL_RE = re.compile(r"git\+(?:https?|ssh)://\S+", re.IGNORECASE)

# pip flags that reference a requirements/constraint manifest file.
MANIFEST_FLAGS: frozenset[str] = frozenset({"-r", "--requirement", "-c", "--constraint"})


def tokenize_packages(args_str: str) -> list[str]:
    """Extract bare package names from the argument portion of an install command."""
    return _tokenize(args_str.split())


# Exact version pin following the package name: ``==1.2.3`` (pip) or ``@1.2.3``
# (npm/cargo). Range specifiers (>=, ~, ^…) and dist-tags (@latest) are not
# pins and yield no version.
_EXACT_PIN_RE = re.compile(r"^(?:==|@)(\d[^\s,;]*)$")


def _split_spec(token: str) -> tuple[str, str | None] | None:
    """Split a package-spec token into ``(name, exact_pin_or_None)``.

    Returns ``None`` when the token is not a package spec. ``requests==2.28.0``
    → ``("requests", "2.28.0")``; ``serde@1.0``/``@scope/pkg@2.1`` keep their
    pin; ``requests>=2`` / ``pkg@latest`` → pin ``None``.
    """
    m = _PKG_SPEC_RE.match(token)
    if not m:
        return None
    name = m.group(1)
    rest = token[len(name) :]
    rest = re.sub(r"^\[[^\]]*\]", "", rest)  # strip extras: pkg[extra]==1.0
    pin = _EXACT_PIN_RE.match(rest)
    return name, (pin.group(1) if pin else None)


def _tokenize_specs(tokens: list[str]) -> list[tuple[str, str | None]]:
    """Extract ``(package, exact_pin_or_None)`` pairs from a split token list."""
    specs: list[tuple[str, str | None]] = []
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token.startswith("-"):
            if token in VALUE_FLAGS and "=" not in token:
                i += 2
            else:
                i += 1
            continue
        # Skip filesystem paths, plain URLs, and VCS URLs (git+https:// etc.)
        if re.match(r"^(?:[/~.]|https?://|git\+)", token):
            i += 1
            continue
        spec = _split_spec(token)
        if spec is not None:
            specs.append(spec)
        i += 1
    return specs


def _tokenize(tokens: list[str]) -> list[str]:
    """Extract bare package names from an already-split token list."""
    return [name for name, _pin in _tokenize_specs(tokens)]


# ── manager specification ─────────────────────────────────────────────────────


@dataclass(frozen=True)
class ManagerSpec:
    """One package-manager invocation form.

    ``binaries`` are the executable names a shim/shadow must wrap.  ``prefixes``
    are the token sequences that, immediately following the binary, mean
    "install" (everything after the prefix is treated as package arguments).
    ``ecosystem`` is the scan ecosystem, or ``None`` when the manager is
    recognised but has no scanning backend (treated as unverifiable).
    """

    name: str
    binaries: tuple[str, ...]
    prefixes: tuple[tuple[str, ...], ...]
    ecosystem: Ecosystem | None
    binary_regex: str  # regex alternation matching the (possibly path-qualified) binary

    @property
    def verifiable(self) -> bool:
        return self.ecosystem is not None

    @property
    def trigger_tokens(self) -> frozenset[str]:
        """First token of each prefix — used to cheaply gate shell wrappers."""
        return frozenset(p[0] for p in self.prefixes if p)

    def _compiled(self) -> list[re.Pattern[str]]:
        """One regex per prefix; group 1 captures the package-argument portion."""
        pats: list[re.Pattern[str]] = []
        for prefix in self.prefixes:
            mid = r"\s+".join(re.escape(tok) for tok in prefix)
            pats.append(
                re.compile(
                    rf"{self.binary_regex}\s+{mid}\s+((?:[^\n;&|]|\\\n)+)",
                    re.IGNORECASE,
                )
            )
        return pats

    def match_prefix(self, args: list[str]) -> list[str] | None:
        """If *args* (the tokens after the binary) start with an install prefix,
        return the remaining tokens; otherwise ``None`` (not an install)."""
        for prefix in self.prefixes:
            n = len(prefix)
            if len(args) >= n and tuple(a.lower() for a in args[:n]) == tuple(
                p.lower() for p in prefix
            ):
                return args[n:]
        return None

    def argv_packages(self, args: list[str]) -> list[str] | None:
        """If *args* (the tokens after the binary) start with an install prefix,
        return the package names; otherwise ``None`` (not an install)."""
        tail = self.match_prefix(args)
        return None if tail is None else _tokenize(tail)


# Binary-name regexes.  No left boundary is required so path-qualified
# invocations (``/usr/bin/pip``, ``command pip``) are still caught.  A negative
# lookahead protects against ``pip`` matching inside ``pipx`` etc.
_PIP_BIN = r"pip3?(?![\w-])"
_PYTHON_BIN = r"python3?(?:\.\d+)?(?![\w-])"
_UV_BIN = r"uv(?![\w-])"
_NPM_BIN = r"npm(?![\w-])"
_YARN_BIN = r"yarn(?![\w-])"
_PNPM_BIN = r"pnpm(?![\w-])"
_BUN_BIN = r"bun(?![\w-])"
_CARGO_BIN = r"cargo(?![\w-])"
_POETRY_BIN = r"poetry(?![\w-])"
_PIPX_BIN = r"pipx(?![\w-])"
_CONDA_BIN = r"conda(?![\w-])"
_GEM_BIN = r"gem(?![\w-])"
_GO_BIN = r"go(?![\w-])"


MANAGERS: tuple[ManagerSpec, ...] = (
    # ── PyPI family ───────────────────────────────────────────────────────────
    ManagerSpec(
        "python-m-pip",
        ("python", "python3"),
        (("-m", "pip", "install"),),
        Ecosystem.PYPI,
        _PYTHON_BIN,
    ),
    ManagerSpec("uv-pip", ("uv",), (("pip", "install"),), Ecosystem.PYPI, _UV_BIN),
    ManagerSpec("uv-add", ("uv",), (("add",),), Ecosystem.PYPI, _UV_BIN),
    ManagerSpec("pipx", ("pipx",), (("install",),), Ecosystem.PYPI, _PIPX_BIN),
    ManagerSpec("poetry", ("poetry",), (("add",),), Ecosystem.PYPI, _POETRY_BIN),
    ManagerSpec("conda", ("conda",), (("install",),), Ecosystem.PYPI, _CONDA_BIN),
    ManagerSpec("pip", ("pip", "pip3"), (("install",),), Ecosystem.PYPI, _PIP_BIN),
    # ── npm family ──────────────────────────────────────────────────────────────
    ManagerSpec("npm", ("npm",), (("install",), ("i",)), Ecosystem.NPM, _NPM_BIN),
    ManagerSpec("yarn", ("yarn",), (("add",),), Ecosystem.NPM, _YARN_BIN),
    ManagerSpec("pnpm", ("pnpm",), (("add",), ("install",)), Ecosystem.NPM, _PNPM_BIN),
    ManagerSpec("bun", ("bun",), (("add",), ("install",)), Ecosystem.NPM, _BUN_BIN),
    # ── Cargo ───────────────────────────────────────────────────────────────────
    ManagerSpec("cargo", ("cargo",), (("add",), ("install",)), Ecosystem.CARGO, _CARGO_BIN),
    # ── recognised but unverifiable (no scan backend yet) ───────────────────────
    ManagerSpec("gem", ("gem",), (("install",),), None, _GEM_BIN),
    ManagerSpec("go", ("go",), (("install",),), None, _GO_BIN),
)

# Specs ordered so that more specific / longer prefixes win when spans overlap
# in free-form command parsing (e.g. ``uv pip install`` before bare ``pip``).
_PARSE_ORDER: tuple[ManagerSpec, ...] = tuple(
    sorted(MANAGERS, key=lambda s: -max(len(p) for p in s.prefixes))
)


def shadow_binaries() -> tuple[str, ...]:
    """Unique, sorted list of executable names any shim/shadow must wrap."""
    names: set[str] = set()
    for spec in MANAGERS:
        names.update(spec.binaries)
    return tuple(sorted(names))


# ── parsed-result container ───────────────────────────────────────────────────


@dataclass
class ParsedInstall:
    """A detected install invocation."""

    manager: str
    ecosystem: Ecosystem | None
    packages: list[str] = field(default_factory=list)
    # When ``ecosystem is None`` (unverifiable), an optional human-readable reason
    # (e.g. an untrusted conda channel) used in fail-closed block messages.
    unverifiable_reason: str | None = None
    # Exact version pins by package name (``pkg==1.2.3`` / ``pkg@1.2.3``).
    # Packages without an exact pin are absent from this map.
    versions: dict[str, str] = field(default_factory=dict)

    @property
    def verifiable(self) -> bool:
        return self.ecosystem is not None


# ── conda channel-aware expansion ─────────────────────────────────────────────


def _conda_parsed(arg_tokens: list[str]) -> list[ParsedInstall]:
    """Classify a ``conda install`` argument vector by channel trust.

    Trusted-channel packages are scanned best-effort as PyPI; untrusted-channel
    packages become an unverifiable result (fail-closed for callers).
    """
    from agentshield.enforce import conda  # local import avoids package-init cycle

    pkgs = conda.parse_conda_install(arg_tokens)
    trusted = [p.name for p in pkgs if p.trusted]
    untrusted = [p for p in pkgs if not p.trusted]

    out: list[ParsedInstall] = []
    if trusted:
        out.append(ParsedInstall(manager="conda", ecosystem=Ecosystem.PYPI, packages=trusted))
    if untrusted:
        channels = sorted({p.channel for p in untrusted if p.channel})
        if channels:
            reason = (
                "conda channel(s) "
                + ", ".join(f"'{c}'" for c in channels)
                + (" not in trusted set — cannot verify")
            )
        else:
            reason = "untrusted conda channel — cannot verify"
        out.append(
            ParsedInstall(
                manager="conda",
                ecosystem=None,
                packages=[p.name for p in untrusted],
                unverifiable_reason=reason,
            )
        )
    return out


# ── free-form command parsing ─────────────────────────────────────────────────


def parse_command(command: str) -> list[ParsedInstall]:
    """Parse a shell command string into the install invocations it contains.

    Overlapping matches are de-duplicated by span so that, e.g.,
    ``uv pip install x`` yields a single ``uv-pip`` result, not also a bare
    ``pip`` result.
    """
    normalised = re.sub(r"\\\n", " ", command)
    raw: list[tuple[int, int, ManagerSpec, str]] = []
    for spec in _PARSE_ORDER:
        for pat in spec._compiled():
            for m in pat.finditer(normalised):
                raw.append((m.start(), m.end(), spec, m.group(1)))

    # Greedy span de-dup: accept matches left-to-right, skipping any whose start
    # falls inside an already-accepted match's span.
    raw.sort(key=lambda t: (t[0], -(t[1] - t[0])))
    accepted: list[tuple[int, int, ManagerSpec, str]] = []
    consumed_end = -1
    for start, end, spec, args in raw:
        if start < consumed_end:
            continue
        accepted.append((start, end, spec, args))
        consumed_end = end

    results: list[ParsedInstall] = []
    for _start, _end, spec, args in sorted(accepted, key=lambda t: t[0]):
        if spec.name == "conda":
            results.extend(_conda_parsed(args.split()))
        else:
            pkg_specs = _tokenize_specs(args.split())
            results.append(
                ParsedInstall(
                    manager=spec.name,
                    ecosystem=spec.ecosystem,
                    packages=[name for name, _pin in pkg_specs],
                    versions={name: pin for name, pin in pkg_specs if pin},
                )
            )
    return results


def parse_packages(command: str) -> list[tuple[str, Ecosystem]]:
    """Backward-compatible helper: ``(package, ecosystem)`` pairs for *verifiable*
    managers only.  Unverifiable managers (gem/go) are excluded here — callers
    that care about them should use :func:`parse_command`."""
    pairs: list[tuple[str, Ecosystem]] = []
    for inst in parse_command(command):
        if inst.ecosystem is None:
            continue
        for pkg in inst.packages:
            pairs.append((pkg, inst.ecosystem))
    return pairs


def parse_argv(argv: list[str]) -> ParsedInstall | None:
    """Parse an already-split argument vector ``[binary, *args]``.

    Returns a :class:`ParsedInstall` if *argv* is a recognised install
    invocation, else ``None``.  The binary may be path-qualified
    (``/usr/bin/pip``); only its basename is matched.
    """
    if not argv:
        return None
    import os

    binary = os.path.basename(argv[0])
    args = argv[1:]
    for spec in _PARSE_ORDER:
        if not any(re.fullmatch(b, binary, re.IGNORECASE) for b in _bin_basenames(spec)):
            continue
        tail = spec.match_prefix(args)
        if tail is None:
            continue
        if spec.name == "conda":
            # Summarise a possibly mixed-trust conda install as a single result:
            # verifiable only if every requested package is from a trusted channel.
            parsed = _conda_parsed(tail)
            names = [p for inst in parsed for p in inst.packages]
            untrusted = [inst for inst in parsed if inst.ecosystem is None]
            if untrusted:
                return ParsedInstall(
                    manager="conda",
                    ecosystem=None,
                    packages=names,
                    unverifiable_reason=untrusted[0].unverifiable_reason,
                )
            return ParsedInstall(manager="conda", ecosystem=Ecosystem.PYPI, packages=names)
        pkg_specs = _tokenize_specs(tail)
        return ParsedInstall(
            manager=spec.name,
            ecosystem=spec.ecosystem,
            packages=[name for name, _pin in pkg_specs],
            versions={name: pin for name, pin in pkg_specs if pin},
        )
    return None


def _bin_basenames(spec: ManagerSpec) -> tuple[str, ...]:
    """Regex fragments matching the basenames this spec's binary regex accepts."""
    # The binary_regex already encodes acceptable basenames; reuse it directly.
    return (spec.binary_regex,)


# ── unverifiable / unanalyzable detection ─────────────────────────────────────


def find_suspicions(command: str) -> list[str]:
    """Return descriptions of install-arg patterns that cannot be statically
    analyzed: shell variable/command expansion and VCS URLs in package position.
    """
    normalised = re.sub(r"\\\n", " ", command)
    suspicions: list[str] = []
    for spec in _PARSE_ORDER:
        for pat in spec._compiled():
            for match in pat.finditer(normalised):
                args_str = match.group(1)
                for var_match in _EXPANSION_RE.finditer(args_str):
                    suspicions.append(
                        f"shell variable/command expansion "
                        f"'{var_match.group()}' in package position"
                    )
                for git_match in _GIT_URL_RE.finditer(args_str):
                    suspicions.append(f"unanalyzable VCS URL '{git_match.group()}'")
    return suspicions


def parse_manifests(command: str) -> tuple[list[str], list[str]]:
    """Find pip ``-r``/``-c`` manifest references in *command*.

    Returns ``(local_paths, suspicions)``.  Remote references (``http(s)://``)
    are returned as suspicions because their contents cannot be verified.
    Only PyPI-family managers are considered.
    """
    normalised = re.sub(r"\\\n", " ", command)
    paths: list[str] = []
    suspicions: list[str] = []
    for spec in _PARSE_ORDER:
        if spec.ecosystem is not Ecosystem.PYPI:
            continue
        for pat in spec._compiled():
            for match in pat.finditer(normalised):
                tokens = match.group(1).split()
                i = 0
                while i < len(tokens):
                    flag, _, inline = tokens[i].partition("=")
                    if flag in MANIFEST_FLAGS:
                        if inline:
                            value = inline
                        elif i + 1 < len(tokens):
                            value = tokens[i + 1]
                            i += 1
                        else:
                            value = ""
                        if value and "://" in value:
                            suspicions.append(f"unanalyzable remote requirements file '{value}'")
                        elif value:
                            paths.append(value)
                    i += 1
    # De-dup while preserving order.
    return list(dict.fromkeys(paths)), list(dict.fromkeys(suspicions))
