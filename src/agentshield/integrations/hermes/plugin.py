"""Hermes Agent tool plugin for AgentShield.

Intercepts ``pip_install``, ``npm_install``, and ``cargo_add`` tool calls
and runs a security scan before allowing them to proceed.

Usage in ``hermes_config.yaml``::

    plugins:
      - module: agentshield.integrations.hermes
        class: AgentShieldPlugin
"""
from __future__ import annotations

from pathlib import Path

from agentshield.core.config import Config
from agentshield.core.models import DecisionAction, Ecosystem, Finding, ScanRequest
from agentshield.core.scanner import AgentShield

try:
    from hermes.tools import ToolCall, ToolPlugin, ToolResult  # type: ignore[import-not-found]
except ImportError:
    from agentshield.integrations.hermes._types import (  # type: ignore[assignment]
        ToolCall,
        ToolPlugin,
        ToolResult,
    )

_TOOL_ECOSYSTEM: dict[str, Ecosystem] = {
    "pip_install": Ecosystem.PYPI,
    "npm_install": Ecosystem.NPM,
    "cargo_add": Ecosystem.CARGO,
}


class AgentShieldPlugin(ToolPlugin):
    """Hermes tool plugin — scans packages before install.

    Registered in Hermes as a plugin; ``before_tool_call`` is invoked by the
    Hermes runtime for every tool call whose name is in ``intercepts``.
    """

    name = "agentshield"
    intercepts = list(_TOOL_ECOSYSTEM.keys())

    def __init__(
        self,
        config_path: Path | None = None,
        config: Config | None = None,
    ) -> None:
        self.shield = AgentShield(config=config, config_path=config_path)

    async def before_tool_call(self, call: ToolCall) -> ToolCall | ToolResult:
        """Scan the requested package; return ToolResult on block/warn, else pass call through."""
        if call.name not in _TOOL_ECOSYSTEM:
            return call

        request = self._build_scan_request(call)
        result = await self.shield.ascan(request)

        if result.decision.action == DecisionAction.BLOCK:
            return ToolResult.error(
                f"AgentShield blocked {call.name}: {result.decision.reason}"
            )

        if result.decision.action == DecisionAction.NEEDS_CONFIRMATION:
            return ToolResult.needs_confirmation(
                message=self._format_findings(result.findings),
                on_confirm=call,
            )

        # ALLOW or LOG_ASYNC: pass the tool call through unmodified
        return call

    # ── helpers ──────────────────────────────────────────────────────────────

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
