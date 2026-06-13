"""Shim types matching the Hermes Agent tool-plugin contract.

When ``hermes-agent`` is not installed these types are used so that
AgentShieldPlugin can be imported and tested without the real framework.
When ``hermes-agent`` *is* installed the plugin imports from it directly
(see plugin.py) and these shims are ignored.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolCall:
    """An intercepted tool call forwarded by the Hermes runtime."""

    name: str
    args: dict[str, Any] = field(default_factory=dict)
    call_id: str = ""


@dataclass
class ToolResult:
    """Result returned to the Hermes runtime after plugin processing."""

    output: str = ""
    error_message: str | None = None
    _needs_confirmation: bool = False
    confirmation_message: str = ""
    on_confirm: ToolCall | None = None

    @classmethod
    def error(cls, message: str) -> ToolResult:
        return cls(error_message=message)

    @classmethod
    def needs_confirmation(cls, *, message: str, on_confirm: ToolCall) -> ToolResult:
        result = cls()
        result._needs_confirmation = True
        result.confirmation_message = message
        result.on_confirm = on_confirm
        return result

    @property
    def is_error(self) -> bool:
        return self.error_message is not None

    @property
    def requires_confirmation(self) -> bool:
        return self._needs_confirmation


class ToolPlugin:
    """Abstract base for Hermes tool plugins."""

    name: str = ""
    intercepts: list[str] = []

    async def before_tool_call(self, call: ToolCall) -> ToolCall | ToolResult:
        return call
