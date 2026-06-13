"""OpenClaw skill integration for AgentShield.

Install with: pip install agentshield[openclaw]

Register in your OpenClaw config::

    skills:
      - module: agentshield.integrations.openclaw
        class: AgentShieldSkill
        triggers:
          - action_type: pip_install
          - action_type: npm_install
          - action_type: cargo_add
"""
from agentshield.integrations.openclaw.skill import AgentShieldSkill

__all__ = ["AgentShieldSkill"]
