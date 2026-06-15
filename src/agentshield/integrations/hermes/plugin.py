"""Hermes Agent tool plugin for AgentShield.

Intercepts two categories of tool calls:

1. **Structured install tools** — ``pip_install``, ``npm_install``, ``cargo_add``:
   package name/version come directly from the tool call arguments.

2. **Shell tools** — ``bash``, ``shell``, ``run_command``, ``execute``, ``terminal``:
   the command string is parsed (via :mod:`agentshield.enforce.registry`, the
   single source of truth for manager coverage) for any supported package-install
   invocation — pip/pip3, ``python -m pip``, ``uv pip``/``uv add``, npm/yarn/
   pnpm/bun, cargo, poetry, pipx, conda, and gem/go.  Each detected package is
   scanned before the command is allowed to run.

**Fail-closed:** if a detected install cannot be verified — an unanalyzable
argument (shell expansion / VCS URL), a recognised-but-unsupported manager
(gem/go, which have no scan backend), or a scanner error — the command is
blocked rather than allowed through.

Usage in ``hermes_config.yaml``::

    plugins:
      - module: agentshield.integrations.hermes
        class: AgentShieldPlugin
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from agentshield.core.config import Config
from agentshield.core.models import DecisionAction, Ecosystem, Finding, ScanRequest
from agentshield.core.scanner import AgentShield
from agentshield.enforce import registry

try:
    from hermes.tools import ToolCall, ToolPlugin, ToolResult  # type: ignore[import-not-found]
except ImportError:
    from agentshield.integrations.hermes._types import (
        ToolCall,
        ToolPlugin,
        ToolResult,
    )

logger = logging.getLogger(__name__)

# ── structured tool-call mapping ─────────────────────────────────────────────

_TOOL_ECOSYSTEM: dict[str, Ecosystem] = {
    "pip_install": Ecosystem.PYPI,
    "npm_install": Ecosystem.NPM,
    "cargo_add": Ecosystem.CARGO,
}

# ── shell tool names ──────────────────────────────────────────────────────────

_SHELL_TOOLS = frozenset({"bash", "shell", "run_command", "execute", "terminal"})


# ── backward-compatible module-level helpers (delegate to the registry) ───────
# These names are part of the plugin's existing public surface (imported by the
# CLI and tests); they now forward to the shared registry so coverage is defined
# in exactly one place.

_tokenize_packages = registry.tokenize_packages


def _parse_shell_packages(command: str) -> list[tuple[str, Ecosystem]]:
    """``(bare_package_name, ecosystem)`` pairs for verifiable managers."""
    return registry.parse_packages(command)


def _find_shell_suspicions(command: str) -> list[str]:
    """Descriptions of install-arg patterns that cannot be statically analyzed."""
    return registry.find_suspicions(command)


def _parse_shell_manifests(command: str) -> tuple[list[str], list[str]]:
    """``(local_paths, suspicions)`` for pip ``-r``/``-c`` manifest references."""
    return registry.parse_manifests(command)


# ── helpers (module-level, testable) ─────────────────────────────────────────


def _extract_command(args: dict[str, Any]) -> str | None:
    """Return the shell command string from a tool call's args dict."""
    for key in ("command", "cmd", "code"):
        val = args.get(key)
        if isinstance(val, str):
            return val
    return None


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
        try:
            result = await self.shield.ascan(request)
        except Exception as exc:  # noqa: BLE001 — fail closed on any scanner error
            logger.warning("AgentShield scan error for %s: %s", request.package, exc)
            return ToolResult.error(
                f"AgentShield blocked {call.name}: scan failed for "
                f"'{request.package}' ({exc}); blocking to fail closed."
            )

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

        # Patterns that cannot be statically analyzed (shell expansion, VCS URLs,
        # remote requirements files) — fail closed before scanning anything.
        manifest_paths, manifest_suspicions = registry.parse_manifests(command)
        suspicions = registry.find_suspicions(command) + manifest_suspicions
        if suspicions:
            return ToolResult.error(
                "AgentShield blocked shell command — cannot verify package source:\n"
                + "\n".join(f"  • {s}" for s in suspicions)
            )

        installs = registry.parse_command(command)
        if not installs and not manifest_paths:
            return call

        blocked_messages: list[str] = []
        confirmation_findings: list[Finding] = []

        for inst in installs:
            # Recognised but unverifiable manager (e.g. gem, go) — no scan backend,
            # so we cannot clear it. Fail closed.
            if inst.ecosystem is None:
                for pkg in inst.packages or ["<unspecified>"]:
                    blocked_messages.append(
                        f"{pkg}: '{inst.manager}' has no scan backend — cannot verify "
                        f"(blocking to fail closed)"
                    )
                continue

            for pkg_name in inst.packages:
                request = ScanRequest(
                    package=pkg_name,
                    ecosystem=inst.ecosystem,
                    source="hermes",
                )
                try:
                    result = await self.shield.ascan(request)
                except Exception as exc:  # noqa: BLE001 — fail closed
                    logger.warning("AgentShield scan error for %s: %s", pkg_name, exc)
                    blocked_messages.append(
                        f"{pkg_name}: scan failed ({exc}); blocking to fail closed"
                    )
                    continue
                if result.decision.action == DecisionAction.BLOCK:
                    blocked_messages.append(f"{pkg_name}: {result.decision.reason}")
                elif result.decision.action == DecisionAction.NEEDS_CONFIRMATION:
                    confirmation_findings.extend(result.findings)

        # Scan packages declared in referenced requirements/constraint files.
        for manifest in manifest_paths:
            manifest_path = Path(manifest)
            if not manifest_path.exists():
                continue
            try:
                file_result = await self.shield.ascan_file(manifest_path)
            except Exception as exc:  # noqa: BLE001 — fail closed
                logger.warning("AgentShield scan error for manifest %s: %s", manifest, exc)
                blocked_messages.append(
                    f"{manifest}: scan failed ({exc}); blocking to fail closed"
                )
                continue
            action = file_result.aggregate_decision.action
            if action == DecisionAction.BLOCK:
                blocked_messages.append(f"{manifest}: {file_result.aggregate_decision.reason}")
            elif action == DecisionAction.NEEDS_CONFIRMATION:
                for r in file_result.results:
                    confirmation_findings.extend(r.findings)

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
