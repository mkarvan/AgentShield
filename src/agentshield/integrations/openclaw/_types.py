"""Shim types matching the OpenClaw skill contract.

When ``openclaw`` is not installed these types are used so that
AgentShieldSkill can be imported and tested without the real framework.
When ``openclaw`` *is* installed the skill imports from it directly
(see skill.py) and these shims are ignored.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SkillContext:
    """Execution context passed to an OpenClaw skill."""

    params: dict[str, Any] = field(default_factory=dict)
    agent_id: str = ""
    session_id: str = ""


@dataclass
class SkillResult:
    """Result returned by an OpenClaw skill to the agent kernel."""

    allowed: bool = True
    decision: str = "ALLOW"
    findings: list[dict[str, Any]] = field(default_factory=list)
    message: str = ""


class Skill:
    """Abstract base class for OpenClaw skills."""

    name: str = ""
    description: str = ""

    async def execute(self, ctx: SkillContext) -> SkillResult:
        raise NotImplementedError
