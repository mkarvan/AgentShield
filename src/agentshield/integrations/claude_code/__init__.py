"""Claude Code (and OpenAI Codex) PreToolUse hook integration for AgentShield.

Both Claude Code and the Codex CLI expose a ``PreToolUse`` hook whose contracts
have converged: each runs a configured command, passes the pending tool call as
a JSON object on **stdin**, and lets the command block the call by emitting

    {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                            "permissionDecision": "deny",
                            "permissionDecisionReason": "..."}}

on **stdout** with exit code 0 (or, equivalently, exiting 2 with the reason on
stderr).  This module implements the shared logic behind the ``agentshield
hook`` CLI subcommand: it reads that payload, extracts the shell command Codex /
Claude Code is about to run, scans every package-install it contains through the
**shared scan core** (:mod:`agentshield.enforce.registry` →
:class:`agentshield.core.scanner.AgentShield`), and renders the correct
allow / block / ask response for the requesting agent.

Coverage and fail-closed semantics are identical to the Hermes plugin and the
``guard-scan-cmd`` shell wrapper — parsing lives in exactly one place
(:mod:`agentshield.enforce.registry`) and is never reimplemented here.

**Fail-closed:** a detected install that cannot be verified — an unanalyzable
argument (shell expansion / VCS URL / remote requirements file), a
recognised-but-unsupported manager (gem/go, untrusted conda channel), or a
scanner error — is blocked rather than allowed through.

**Agent dialects.** ``permissionDecision`` values are honored slightly
differently by each agent, so :func:`run_hook` takes an ``agent`` argument:

* ``claude-code`` (default): BLOCK → ``deny``; NEEDS_CONFIRMATION → ``ask``
  (Claude Code escalates ``ask`` to the user, matching WARN_CONFIRM).
* ``codex``: BLOCK → ``deny``; NEEDS_CONFIRMATION → ``deny``.  Codex parses but
  does **not** honor ``ask`` yet (it fails open), so to stay fail-closed a
  warn-level finding is denied rather than silently allowed.

ALLOW / LOG_ASYNC produce an empty exit-0 response (the call proceeds through
the agent's normal permission flow) for both agents.

Configuration (Claude Code — ``.claude/settings.json``)::

    {
      "hooks": {
        "PreToolUse": [
          {"matcher": "Bash",
           "hooks": [{"type": "command", "command": "agentshield hook"}]}
        ]
      }
    }

Configuration (Codex — ``~/.codex/hooks.json``; requires ``codex_hooks = true``
under ``[features]`` in ``config.toml``)::

    {
      "hooks": {
        "PreToolUse": [
          {"matcher": "Bash",
           "hooks": [{"type": "command", "command": "agentshield hook --agent codex"}]}
        ]
      }
    }
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from pathlib import Path

from agentshield.core.config import Config
from agentshield.core.models import DecisionAction
from agentshield.core.scanner import AgentShield
from agentshield.enforce.command_scan import CommandDecision, evaluate_command

logger = logging.getLogger(__name__)

__all__ = [
    "AGENTS",
    "CLAUDE_CODE",
    "CODEX",
    "CommandDecision",
    "HookDecision",
    "HookResponse",
    "evaluate_command",
    "extract_command",
    "render_response",
    "run_hook",
]

# ── agent dialects ────────────────────────────────────────────────────────────

CLAUDE_CODE = "claude-code"
CODEX = "codex"
AGENTS = frozenset({CLAUDE_CODE, CODEX})

_HOOK_EVENT = "PreToolUse"


# ── payload helpers (module-level, testable) ──────────────────────────────────


def extract_command(payload: dict[str, object]) -> str | None:
    """Return the shell command string from a PreToolUse hook payload.

    Both Claude Code and Codex nest it under ``tool_input.command``; a couple of
    common aliases and a top-level fallback are accepted for robustness.
    """
    tool_input = payload.get("tool_input")
    if isinstance(tool_input, dict):
        for key in ("command", "cmd", "code"):
            val = tool_input.get(key)
            if isinstance(val, str):
                return val
    for key in ("command", "cmd", "code"):
        val = payload.get(key)
        if isinstance(val, str):
            return val
    return None


# ── resolved outcomes ─────────────────────────────────────────────────────────

# ``HookDecision`` is the historical name for the shared command verdict; the
# command-evaluation logic now lives in one place (``enforce.command_scan``) so
# the Hermes plugin and this hook can never drift apart.
HookDecision = CommandDecision


@dataclass
class HookResponse:
    """What the ``agentshield hook`` process writes back to the agent."""

    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0


# ── agent-specific rendering ──────────────────────────────────────────────────


def render_response(decision: HookDecision, agent: str) -> HookResponse:
    """Translate a :class:`HookDecision` into the JSON/exit-code contract."""
    if decision.action in (DecisionAction.ALLOW, DecisionAction.LOG_ASYNC):
        # Exit 0 with no output: no decision to report; the agent proceeds
        # through its normal permission flow.
        return HookResponse()

    reason = "AgentShield blocked this command — " + "; ".join(decision.reasons)

    if decision.action == DecisionAction.BLOCK:
        permission = "deny"
    else:  # NEEDS_CONFIRMATION
        # Claude Code escalates "ask" to the user; Codex parses but does not
        # honor "ask" (fails open), so deny there to stay fail-closed.
        permission = "deny" if agent == CODEX else "ask"
        if permission == "ask":
            reason = "AgentShield flagged this command for review — " + "; ".join(decision.reasons)

    payload = {
        "hookSpecificOutput": {
            "hookEventName": _HOOK_EVENT,
            "permissionDecision": permission,
            "permissionDecisionReason": reason,
        }
    }
    # JSON on stdout is only honored on exit 0 (Claude Code is explicit about
    # this; Codex honors the same shape). Keep stderr empty so the structured
    # decision is the single signal.
    return HookResponse(stdout=json.dumps(payload), stderr="", exit_code=0)


# ── top-level driver (used by the CLI subcommand) ─────────────────────────────


def run_hook(
    stdin_text: str,
    *,
    agent: str = CLAUDE_CODE,
    config: Config | None = None,
    config_path: Path | None = None,
    shield: AgentShield | None = None,
) -> HookResponse:
    """Process one PreToolUse hook invocation end to end.

    *stdin_text* is the raw payload the agent wrote to the hook's stdin.  Returns
    a :class:`HookResponse` the caller writes back (stdout / stderr / exit code).
    """
    if agent not in AGENTS:
        agent = CLAUDE_CODE

    text = stdin_text.strip()
    if not text:
        # No payload at all — nothing to scan. Don't wedge the session.
        return HookResponse()

    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        # Malformed payload: we cannot determine the command. We only fail
        # closed on *detected installs* we can't verify — blocking every tool
        # call on an unparseable payload would be a denial of service on the
        # whole session. Log and let it proceed.
        logger.warning("AgentShield hook: could not parse payload as JSON")
        return HookResponse()

    if not isinstance(payload, dict):
        logger.warning("AgentShield hook: payload was not a JSON object")
        return HookResponse()

    command = extract_command(payload)
    if not command:
        # Non-shell tool, or no command present — nothing to scan.
        return HookResponse()

    active_shield = shield or AgentShield(config=config, config_path=config_path)
    try:
        decision = asyncio.run(evaluate_command(active_shield, command, source=agent))
    except Exception as exc:  # noqa: BLE001 — fail closed on any unexpected error
        logger.warning("AgentShield hook: evaluation failed: %s", exc)
        decision = HookDecision(
            DecisionAction.BLOCK,
            [f"hook evaluation failed ({exc}); blocking to fail closed"],
        )

    return render_response(decision, agent)
