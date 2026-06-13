"""Hermes Agent tool plugin for AgentShield.

Install with: pip install agentshield[hermes]

Register in your Hermes config::

    plugins:
      - module: agentshield.integrations.hermes
        class: AgentShieldPlugin
"""
from agentshield.integrations.hermes.plugin import AgentShieldPlugin

__all__ = ["AgentShieldPlugin"]
