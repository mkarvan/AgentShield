"""Hermes Agent plugin for AgentShield.

Install with: ``pip install agentshield[hermes]``

Register as a real Hermes plugin (``register(ctx)`` + ``pre_tool_call`` hook).
Drop it under ``~/.hermes/plugins/agentshield/`` with a ``plugin.yaml`` (or ship
it as a ``hermes_agent.plugins`` entry-point) and enable it::

    # ~/.hermes/config.yaml
    plugins:
      enabled:
        - agentshield
"""

from agentshield.integrations.hermes.plugin import (
    HermesGuard,
    intercepted_tools,
    register,
    verify_registered,
)

__all__ = ["HermesGuard", "intercepted_tools", "register", "verify_registered"]
