"""Hermes Agent tool plugin for AgentShield.

Intercepts two categories of tool calls:

1. **Structured install tools** — ``pip_install``, ``npm_install``, ``cargo_add``:
   package name/version come directly from the tool call arguments.

2. **Shell tools** — ``bash``, ``shell``, ``run_command``, ``execute``, ``terminal``:
   the command string is parsed for ``pip install``, ``pip3 install``,
   ``python -m pip install``, ``uv pip install``, ``npm install``, ``npm i``,
   ``yarn add``, ``cargo add``, and ``cargo install`` patterns.  Each detected
   package is scanned before the command is allowed to run.

Usage in ``hermes_config.yaml``::

    plugins:
      - module: agentshield.integrations.hermes
        class: AgentShieldPlugin
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from agentshield.core.config import Config
from agentshield.core.models import DecisionAction, Ecosystem, Finding, ScanRequest
from agentshield.core.scanner import AgentShield

try:
    from hermes.tools import ToolCall, ToolPlugin, ToolResult  # type: ignore[import-not-found]
except ImportError:
    from agentshield.integrations.hermes._types import (
        ToolCall,
        ToolPlugin,
        ToolResult,
    )

# ── structured tool-call mapping ─────────────────────────────────────────────

_TOOL_ECOSYSTEM: dict[str, Ecosystem] = {
    "pip_install": Ecosystem.PYPI,
    "npm_install": Ecosystem.NPM,
    "cargo_add": Ecosystem.CARGO,
}

# ── shell tool names ──────────────────────────────────────────────────────────

_SHELL_TOOLS = frozenset({"bash", "shell", "run_command", "execute", "terminal"})

# ── install-command detection regexes ────────────────────────────────────────

# Each tuple: (pattern that captures the argument portion, ecosystem).
# The argument portion is everything after the install subcommand up to a shell
# statement boundary (newline, ; & | characters).
_INSTALL_PATTERNS: list[tuple[re.Pattern[str], Ecosystem]] = [
    (
        re.compile(
            r"(?:pip3?|python3?(?:\.\d+)?\s+-m\s+pip|uv\s+pip)\s+install"
            r"\s+((?:[^\n;&|]|\\\n)+)",
            re.IGNORECASE,
        ),
        Ecosystem.PYPI,
    ),
    (
        re.compile(
            r"npm\s+(?:install|i)\s+((?:[^\n;&|]|\\\n)+)",
            re.IGNORECASE,
        ),
        Ecosystem.NPM,
    ),
    (
        re.compile(
            r"yarn\s+add\s+((?:[^\n;&|]|\\\n)+)",
            re.IGNORECASE,
        ),
        Ecosystem.NPM,
    ),
    (
        re.compile(
            r"cargo\s+(?:add|install)\s+((?:[^\n;&|]|\\\n)+)",
            re.IGNORECASE,
        ),
        Ecosystem.CARGO,
    ),
]

# Flags that consume the next token when written without = (e.g. -r req.txt vs --requirement=req.txt)
_VALUE_FLAGS = frozenset(
    {
        # pip / pip3 / uv pip
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
        # npm
        "--registry",
        "--tag",
        "--scope",
        "-w",
        "--workspace",
        # cargo
        "--version",
        "-p",
        "--package",
        "--manifest-path",
        # yarn
        "--cwd",
    }
)

# Matches a valid package spec and captures the bare name in group 1.
# Handles: requests, requests==2.28.0, requests[security], requests[security]>=2
_PKG_SPEC_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?(?:[><=!~^@][^\s]*)?$")

# Patterns in install args that we cannot statically resolve
_EXPANSION_RE = re.compile(r"\$(?:\{[^}]*\}|\([^)]*\)|[A-Za-z_][A-Za-z0-9_]*)")
_GIT_URL_RE = re.compile(r"git\+(?:https?|ssh)://\S+", re.IGNORECASE)


# ── helpers (module-level, testable) ─────────────────────────────────────────


def _extract_command(args: dict[str, Any]) -> str | None:
    """Return the shell command string from a tool call's args dict."""
    for key in ("command", "cmd", "code"):
        val = args.get(key)
        if isinstance(val, str):
            return val
    return None


def _parse_shell_packages(command: str) -> list[tuple[str, Ecosystem]]:
    """Scan *command* for package-install invocations.

    Returns a list of ``(bare_package_name, ecosystem)`` pairs, one per
    package found across all install invocations in the command string.
    """
    results: list[tuple[str, Ecosystem]] = []
    for pattern, ecosystem in _INSTALL_PATTERNS:
        for match in pattern.finditer(command):
            for pkg in _tokenize_packages(match.group(1)):
                results.append((pkg, ecosystem))
    return results


def _tokenize_packages(args_str: str) -> list[str]:
    """Extract bare package names from the argument portion of an install command."""
    # Normalize POSIX line continuations (backslash-newline)
    args_str = re.sub(r"\\\n", " ", args_str)
    tokens = args_str.split()
    packages: list[str] = []
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token.startswith("-"):
            # Skip value-taking flags along with their argument
            if token in _VALUE_FLAGS and "=" not in token:
                i += 2
            else:
                i += 1
            continue
        # Skip filesystem paths, plain URLs, and VCS URLs (git+https:// etc.)
        if re.match(r"^(?:[/~.]|https?://|git\+)", token):
            i += 1
            continue
        m = _PKG_SPEC_RE.match(token)
        if m:
            packages.append(m.group(1))
        i += 1
    return packages


def _find_shell_suspicions(command: str) -> list[str]:
    """Return descriptions of install-arg patterns that cannot be statically analyzed.

    Covers: shell variable/command expansion ($VAR, ${VAR}, $(cmd)) and VCS URLs
    (git+https://, git+ssh://) where the real package identity cannot be verified.
    """
    suspicions: list[str] = []
    for pattern, _ in _INSTALL_PATTERNS:
        for match in pattern.finditer(command):
            args_str = match.group(1)
            for var_match in _EXPANSION_RE.finditer(args_str):
                suspicions.append(
                    f"shell variable/command expansion '{var_match.group()}' in package position"
                )
            for git_match in _GIT_URL_RE.finditer(args_str):
                suspicions.append(f"unanalyzable VCS URL '{git_match.group()}'")
    return suspicions


# ── plugin ────────────────────────────────────────────────────────────────────


class AgentShieldPlugin(ToolPlugin):  # type: ignore[misc]
    """Hermes tool plugin — scans packages before install.

    Registered in Hermes as a plugin; ``before_tool_call`` is invoked by the
    Hermes runtime for every tool call whose name is in ``intercepts``.
    """

    name = "agentshield"
    intercepts = [*_TOOL_ECOSYSTEM.keys(), *sorted(_SHELL_TOOLS)]

    def __init__(
        self,
        config_path: Path | None = None,
        config: Config | None = None,
    ) -> None:
        self.shield = AgentShield(config=config, config_path=config_path)

    async def before_tool_call(self, call: ToolCall) -> ToolCall | ToolResult:
        """Scan the requested package; return ToolResult on block/warn, else pass call through."""
        if call.name in _SHELL_TOOLS:
            return await self._handle_shell_call(call)
        if call.name in _TOOL_ECOSYSTEM:
            return await self._handle_tool_call(call)
        return call

    # ── structured tool handlers ──────────────────────────────────────────────

    async def _handle_tool_call(self, call: ToolCall) -> ToolCall | ToolResult:
        request = self._build_scan_request(call)
        result = await self.shield.ascan(request)

        if result.decision.action == DecisionAction.BLOCK:
            return ToolResult.error(f"AgentShield blocked {call.name}: {result.decision.reason}")

        if result.decision.action == DecisionAction.NEEDS_CONFIRMATION:
            return ToolResult.needs_confirmation(
                message=self._format_findings(result.findings),
                on_confirm=call,
            )

        return call

    # ── shell command handler ─────────────────────────────────────────────────

    async def _handle_shell_call(self, call: ToolCall) -> ToolCall | ToolResult:
        command = _extract_command(call.args)
        if not command:
            return call

        # Check for patterns that cannot be statically analyzed (must happen before
        # _parse_shell_packages so that commands like `pip install $PKG` that produce
        # an empty pkg_list are not accidentally passed through)
        suspicions = _find_shell_suspicions(command)
        if suspicions:
            return ToolResult.error(
                "AgentShield blocked shell command — cannot verify package source:\n"
                + "\n".join(f"  • {s}" for s in suspicions)
            )

        pkg_list = _parse_shell_packages(command)
        if not pkg_list:
            return call

        blocked_messages: list[str] = []
        confirmation_findings: list[Finding] = []

        for pkg_name, ecosystem in pkg_list:
            request = ScanRequest(
                package=pkg_name,
                ecosystem=ecosystem,
                source="hermes",
            )
            result = await self.shield.ascan(request)
            if result.decision.action == DecisionAction.BLOCK:
                blocked_messages.append(f"{pkg_name}: {result.decision.reason}")
            elif result.decision.action == DecisionAction.NEEDS_CONFIRMATION:
                confirmation_findings.extend(result.findings)

        if blocked_messages:
            return ToolResult.error(
                "AgentShield blocked shell command — unsafe packages detected:\n"
                + "\n".join(f"  • {m}" for m in blocked_messages)
            )

        if confirmation_findings:
            return ToolResult.needs_confirmation(
                message=self._format_findings(confirmation_findings),
                on_confirm=call,
            )

        return call

    # ── helpers ───────────────────────────────────────────────────────────────

    def _build_scan_request(self, call: ToolCall) -> ScanRequest:
        ecosystem = _TOOL_ECOSYSTEM[call.name]
        package = call.args.get("package") or call.args.get("name") or ""
        version = call.args.get("version")
        context = call.args.get("reason") or call.args.get("context")
        return ScanRequest(
            package=package,
            version=version,
            ecosystem=ecosystem,
            source="hermes",
            context_hint=context,
        )

    def _format_findings(self, findings: list[Finding]) -> str:
        lines = [f"AgentShield found {len(findings)} security issue(s):"]
        for f in findings:
            lines.append(f"  [{f.severity.value}] {f.rule_id}: {f.title}")
        lines.append("\nApprove to proceed with the installation.")
        return "\n".join(lines)
