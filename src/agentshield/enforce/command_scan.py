"""Shared command-evaluation core for in-process integrations.

Both the Claude Code / Codex ``PreToolUse`` hook and the Hermes ``pre_tool_call``
plugin hook need to take a shell command string, find every package install it
contains, scan each one, and collapse the results into a single allow / warn /
block decision.  That logic lives here, exactly once, on top of the shared
parsing registry (:mod:`agentshield.enforce.registry`) and the scan core
(:class:`agentshield.core.scanner.AgentShield`).

**Fail-closed:** a detected install that cannot be verified — an unanalyzable
argument (shell expansion / VCS URL / remote requirements file), a
recognised-but-unsupported manager (gem/go, untrusted conda channel), or a
scanner error — is blocked rather than allowed through.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Coroutine
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypeVar

from agentshield.core.models import DecisionAction, ScanRequest
from agentshield.core.scanner import AgentShield
from agentshield.enforce import registry

logger = logging.getLogger(__name__)

_T = TypeVar("_T")


def run_async(make_coro: Callable[[], Coroutine[Any, Any, _T]]) -> _T:
    """Run a coroutine to completion from synchronous code.

    ``asyncio.run`` works when no event loop is running; if one *is* already
    running on this thread, the coroutine is driven to completion on a
    short-lived worker thread instead of raising ``RuntimeError``.  *make_coro*
    is a zero-arg factory so the coroutine is created in the thread that awaits
    it.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(make_coro())
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(lambda: asyncio.run(make_coro())).result()


@dataclass
class CommandDecision:
    """The scan verdict for a command, before integration-specific rendering."""

    action: DecisionAction
    reasons: list[str] = field(default_factory=list)


async def evaluate_command(
    shield: AgentShield, command: str, *, source: str = "agent"
) -> CommandDecision:
    """Scan every package-install detected in *command*.

    Pre-check for unanalyzable args, parse installs via the registry, scan each
    verifiable package, scan referenced requirements files, and fail closed on
    anything that cannot be cleared.
    """
    # Patterns that cannot be statically analyzed (shell expansion, VCS URLs,
    # remote requirements files) — fail closed before scanning anything.
    manifest_paths, manifest_suspicions = registry.parse_manifests(command)
    suspicions = registry.find_suspicions(command) + manifest_suspicions
    if suspicions:
        return CommandDecision(
            DecisionAction.BLOCK,
            [f"cannot verify package source: {s}" for s in suspicions],
        )

    installs = registry.parse_command(command)
    if not installs and not manifest_paths:
        return CommandDecision(DecisionAction.ALLOW, [])

    blocked: list[str] = []
    warned: list[str] = []

    for inst in installs:
        # Recognised but unverifiable manager (gem/go, untrusted conda channel) —
        # no scan backend, so we cannot clear it. Fail closed.
        if inst.ecosystem is None:
            reason = (
                inst.unverifiable_reason or f"'{inst.manager}' has no scan backend — cannot verify"
            )
            for pkg in inst.packages or ["<unspecified>"]:
                blocked.append(f"{pkg}: {reason} (blocking to fail closed)")
            continue

        for pkg_name in inst.packages:
            request = ScanRequest(package=pkg_name, ecosystem=inst.ecosystem, source=source)
            try:
                result = await shield.ascan(request)
            except Exception as exc:  # noqa: BLE001 — fail closed on any scanner error
                logger.warning("AgentShield scan error for %s: %s", pkg_name, exc)
                blocked.append(f"{pkg_name}: scan failed ({exc}); blocking to fail closed")
                continue
            if result.decision.action == DecisionAction.BLOCK:
                blocked.append(f"{pkg_name}: {result.decision.reason}")
            elif result.decision.action == DecisionAction.NEEDS_CONFIRMATION:
                warned.append(f"{pkg_name}: {result.decision.reason}")

    # Scan packages declared in referenced requirements/constraint files.
    for manifest in manifest_paths:
        manifest_path = Path(manifest)
        if not manifest_path.exists():
            continue
        try:
            file_result = await shield.ascan_file(manifest_path)
        except Exception as exc:  # noqa: BLE001 — fail closed
            logger.warning("AgentShield scan error for manifest %s: %s", manifest, exc)
            blocked.append(f"{manifest}: scan failed ({exc}); blocking to fail closed")
            continue
        action = file_result.aggregate_decision.action
        if action == DecisionAction.BLOCK:
            blocked.append(f"{manifest}: {file_result.aggregate_decision.reason}")
        elif action == DecisionAction.NEEDS_CONFIRMATION:
            warned.append(f"{manifest}: {file_result.aggregate_decision.reason}")

    if blocked:
        return CommandDecision(DecisionAction.BLOCK, blocked)
    if warned:
        return CommandDecision(DecisionAction.NEEDS_CONFIRMATION, warned)
    return CommandDecision(DecisionAction.ALLOW, [])


def evaluate_command_sync(
    shield: AgentShield, command: str, *, source: str = "agent"
) -> CommandDecision:
    """Synchronous wrapper around :func:`evaluate_command`.

    Hermes invokes ``pre_tool_call`` callbacks synchronously, but the scan core
    is async; :func:`run_async` bridges the two whether or not a loop is running.
    """
    return run_async(lambda: evaluate_command(shield, command, source=source))
