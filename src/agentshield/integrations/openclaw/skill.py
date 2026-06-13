"""OpenClaw skill integration for AgentShield.

Registers ``AgentShieldSkill`` as a pre-condition skill that blocks or warns
before any install-type agent action proceeds.

Usage in ``openclaw_config.yaml``::

    skills:
      - module: agentshield.integrations.openclaw
        class: AgentShieldSkill
        triggers:
          - action_type: pip_install
          - action_type: npm_install
          - action_type: cargo_add
"""
from __future__ import annotations

from pathlib import Path

from agentshield.core.config import Config
from agentshield.core.models import DecisionAction, Ecosystem, ScanRequest
from agentshield.core.scanner import AgentShield

try:
    from openclaw.skills import Skill, SkillContext, SkillResult  # type: ignore[import-not-found]
except ImportError:
    from agentshield.integrations.openclaw._types import Skill, SkillContext, SkillResult  # type: ignore[assignment]


class AgentShieldSkill(Skill):
    """OpenClaw pre-condition skill — scans packages before install.

    ``execute()`` is called by the OpenClaw kernel before any triggered
    action proceeds. Returning ``allowed=False`` prevents the action.
    """

    name = "agentshield_check"
    description = (
        "Security check before installing packages — blocks or warns on CVEs, "
        "typosquatting, and prompt injection."
    )

    def __init__(
        self,
        config_path: Path | None = None,
        config: Config | None = None,
    ) -> None:
        self.shield = AgentShield(config=config, config_path=config_path)

    async def execute(self, ctx: SkillContext) -> SkillResult:
        """Run a security scan; return SkillResult indicating allow/block."""
        package = ctx.params.get("package") or ctx.params.get("name") or ""
        if not package:
            return SkillResult(allowed=True, decision="ALLOW", message="No package specified")

        ecosystem_str = ctx.params.get("ecosystem", "pypi")
        try:
            ecosystem = Ecosystem(ecosystem_str.lower())
        except ValueError:
            ecosystem = Ecosystem.PYPI

        version = ctx.params.get("version")
        context = ctx.params.get("reason") or ctx.params.get("context")

        result = await self.shield.ascan(
            ScanRequest(
                package=package,
                version=version,
                ecosystem=ecosystem,
                source="openclaw",
                context_hint=context,
            )
        )

        allowed = result.decision.action in (DecisionAction.ALLOW, DecisionAction.LOG_ASYNC)
        return SkillResult(
            allowed=allowed,
            decision=result.decision.action.value,
            findings=[f.model_dump() for f in result.findings],
            message=result.decision.reason,
        )
