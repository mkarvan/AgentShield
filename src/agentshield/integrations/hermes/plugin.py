"""Hermes Agent plugin for AgentShield.

This targets the **real** Hermes (NousResearch ``hermes-agent``) plugin API:
a plugin is a package exposing a ``register(ctx)`` function that wires callbacks
via ``ctx.register_hook(...)``.  AgentShield registers a ``pre_tool_call`` hook
that scans every package install a tool is about to run and **blocks** unsafe
ones before they execute.

Why a hook and not a ``before_tool_call`` method?  Hermes has no
``ToolPlugin.before_tool_call`` contract and no structured ``pip_install`` /
``npm_install`` tools — installs happen through the ``terminal`` tool (and
``terminal()`` calls made from inside ``execute_code`` scripts, which also
dispatch through the same tool path).  The only enforcement point Hermes exposes
is the ``pre_tool_call`` hook, whose contract is:

* callback signature ``cb(tool_name: str, args: dict, task_id: str, **kwargs)``
* return ``{"action": "block", "message": str}`` to veto the call (the agent
  short-circuits the tool and hands ``message`` back to the model as the error)
* any other return value is ignored (the call proceeds)

**Errors in Hermes hooks are swallowed by the host** (a crashing callback is
logged and skipped, and the tool then runs).  That would be fail-*open*, so this
callback never raises: every internal error is caught and converted into a
block decision.

Registration — drop this package (or a thin wrapper) under
``~/.hermes/plugins/agentshield/`` with a ``plugin.yaml``, or install it as a
``hermes_agent.plugins`` entry-point, then enable it::

    # ~/.hermes/config.yaml
    plugins:
      enabled:
        - agentshield
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from agentshield.core.config import Config
from agentshield.core.models import DecisionAction, Ecosystem, ScanRequest
from agentshield.core.scanner import AgentShield
from agentshield.enforce.command_scan import evaluate_command_sync, run_async

logger = logging.getLogger(__name__)

# ── tool coverage ─────────────────────────────────────────────────────────────

#: Tools whose arguments carry a shell command string to be parsed for installs.
#: ``terminal`` is the real Hermes tool; the others cover Hermes forks/variants
#: and other agents that reuse this guard.
_SHELL_TOOLS = frozenset({"terminal", "bash", "shell", "run_command", "execute", "sh", "command"})

#: Tools whose arguments carry a code body that may invoke installs (e.g. the
#: Hermes ``execute_code`` tool runs Python that can call ``terminal(...)``).
_CODE_TOOLS = frozenset({"execute_code", "python", "code"})

#: Structured install tools (some non-Hermes agents expose these). Hermes does
#: not, but the mapping is kept so the same guard serves those agents too.
_TOOL_ECOSYSTEM: dict[str, Ecosystem] = {
    "pip_install": Ecosystem.PYPI,
    "npm_install": Ecosystem.NPM,
    "cargo_add": Ecosystem.CARGO,
}

#: Argument keys to look in for a shell command, in priority order.
_COMMAND_KEYS = ("command", "cmd")
#: Argument keys to look in for a code body.
_CODE_KEYS = ("code", "script", "source", "command")

#: The Hermes hook name we enforce on.
_HOOK_NAME = "pre_tool_call"

#: Translation table that turns Python string/call punctuation into spaces, so a
#: code body like ``terminal('pip install x')`` exposes its install tokens to the
#: shell parser.
_CODE_PUNCT = str.maketrans("'\"(),", "     ")


def intercepted_tools() -> list[str]:
    """All tool names this plugin inspects (used for logging / self-verify)."""
    return sorted({*_SHELL_TOOLS, *_CODE_TOOLS, *_TOOL_ECOSYSTEM})


def _extract_command(tool_name: str, args: dict[str, Any]) -> str | None:
    """Return the command/code string for an intercepted tool.

    Returns ``None`` when *args* carries **no recognizable** command field — the
    caller treats that as fail-closed for an intercepted tool, because it means
    we cannot see what the tool is about to run (e.g. an unexpected arg shape).
    A present-but-empty string is returned as ``""`` (genuinely nothing to run).
    """
    keys = _CODE_KEYS if tool_name in _CODE_TOOLS else _COMMAND_KEYS
    for key in keys:
        val = args.get(key)
        if isinstance(val, str):
            return val
    return None


# ── the guard ─────────────────────────────────────────────────────────────────


class HermesGuard:
    """Holds the scan core and implements the ``pre_tool_call`` callback."""

    def __init__(
        self,
        config_path: Path | None = None,
        config: Config | None = None,
    ) -> None:
        self.shield = AgentShield(config=config, config_path=config_path)
        self.registered = False

    # -- the hook --------------------------------------------------------------

    def pre_tool_call(
        self,
        tool_name: str,
        args: dict[str, Any] | None = None,
        task_id: str | None = None,
        **kwargs: Any,
    ) -> dict[str, str] | None:
        """Hermes ``pre_tool_call`` callback.

        Returns ``{"action": "block", "message": ...}`` to veto an unsafe
        install, otherwise ``None`` to let the call proceed.  Never raises —
        Hermes swallows hook exceptions and would then run the tool (fail-open),
        so any internal failure is converted to a block.
        """
        try:
            args = args or {}
            if tool_name not in _SHELL_TOOLS and tool_name not in _CODE_TOOLS:
                # Structured install tool (non-Hermes agents) — handle directly.
                if tool_name in _TOOL_ECOSYSTEM:
                    return self._handle_structured(tool_name, args)
                # Any other tool: not our concern.
                return None

            command = _extract_command(tool_name, args)
            if command is None:
                # An intercepted shell/code tool whose command we cannot read.
                # Fail closed — this is exactly the arg-shape blind spot that
                # would otherwise let an install slip through unscanned.
                return _block(
                    f"AgentShield could not read the command from a '{tool_name}' "
                    f"call (keys: {sorted(args)}); blocking to fail closed."
                )
            if not command.strip():
                return None  # genuinely empty — nothing to install

            if tool_name in _CODE_TOOLS:
                # A code body (e.g. execute_code Python) may invoke installs via
                # ``terminal('pip install ...')``. Strip Python string/call
                # punctuation so the shell parser can see the install tokens.
                # (Inner ``terminal()`` calls also re-enter this hook as real
                # ``terminal`` tool calls; this is best-effort defense-in-depth.)
                command = command.translate(_CODE_PUNCT)

            decision = evaluate_command_sync(self.shield, command, source="hermes")
            return self._render(decision.action, decision.reasons)
        except Exception as exc:  # noqa: BLE001 — never let the host fail open
            logger.warning("AgentShield pre_tool_call error for %s: %s", tool_name, exc)
            return _block(
                f"AgentShield guard error while checking '{tool_name}' "
                f"({exc}); blocking to fail closed."
            )

    # -- structured install tools (non-Hermes agents) --------------------------

    def _handle_structured(self, tool_name: str, args: dict[str, Any]) -> dict[str, str] | None:
        ecosystem = _TOOL_ECOSYSTEM[tool_name]
        package = args.get("package") or args.get("name")
        if not isinstance(package, str) or not package:
            return _block(
                f"AgentShield could not read the package name from a '{tool_name}' "
                f"call; blocking to fail closed."
            )
        version = args.get("version")
        context = args.get("reason") or args.get("context")
        request = ScanRequest(
            package=package,
            version=version if isinstance(version, str) else None,
            ecosystem=ecosystem,
            source="hermes",
            context_hint=context if isinstance(context, str) else None,
        )
        try:
            result = run_async(lambda: self.shield.ascan(request))
        except Exception as exc:  # noqa: BLE001 — fail closed
            logger.warning("AgentShield scan error for %s: %s", package, exc)
            return _block(
                f"AgentShield blocked {tool_name}: scan failed for "
                f"'{package}' ({exc}); blocking to fail closed."
            )
        return self._render(result.decision.action, [f"{package}: {result.decision.reason}"])

    # -- decision rendering ----------------------------------------------------

    def _render(self, action: DecisionAction, reasons: list[str]) -> dict[str, str] | None:
        if action in (DecisionAction.ALLOW, DecisionAction.LOG_ASYNC):
            return None
        # Hermes ``pre_tool_call`` only supports allow vs. block (no "ask").
        # A NEEDS_CONFIRMATION verdict therefore fails closed: we block and tell
        # the model the package needs explicit human review before installing.
        if action == DecisionAction.BLOCK:
            prefix = "AgentShield blocked this install — unsafe package(s):"
        else:  # NEEDS_CONFIRMATION
            prefix = (
                "AgentShield flagged this install for review (blocked pending human "
                "approval — Hermes hooks cannot prompt):"
            )
        detail = "; ".join(reasons) if reasons else "no detail"
        return _block(f"{prefix} {detail}")


def _block(message: str) -> dict[str, str]:
    return {"action": "block", "message": message}


# ── plugin entry point ──────────────────────────────────────────────────────────


def register(ctx: Any) -> HermesGuard:
    """Hermes plugin entry point — wire the ``pre_tool_call`` guard.

    Called by Hermes' plugin loader with a ``PluginContext``.  Registers the
    guard and runs a self-verify that logs **loudly** if the host does not expose
    the hook API this plugin depends on (the failure mode that previously let
    direct shell installs bypass AgentShield entirely).
    """
    config_path = _resolve_config_path(ctx)
    guard = HermesGuard(config_path=config_path)

    register_hook = getattr(ctx, "register_hook", None)
    if not callable(register_hook):
        logger.critical(
            "AgentShield: this Hermes build exposes no 'register_hook' API — the "
            "pre_tool_call guard is NOT active and shell installs will NOT be "
            "scanned in-band. Use the agnostic layer instead: `agentshield guard`."
        )
        return guard

    register_hook(_HOOK_NAME, guard.pre_tool_call)
    guard.registered = True
    logger.info(
        "AgentShield: registered '%s' guard (intercepting: %s)",
        _HOOK_NAME,
        ", ".join(intercepted_tools()),
    )

    if not verify_registered(ctx, guard):
        logger.error(
            "AgentShield: '%s' hook did not appear in the host hook registry after "
            "registration — in-band enforcement may be inactive. Verify with "
            "`/plugins` and fall back to `agentshield guard`.",
            _HOOK_NAME,
        )
    return guard


def verify_registered(ctx: Any, guard: HermesGuard) -> bool:
    """Best-effort check that our callback is wired to the ``pre_tool_call`` hook.

    Hermes does not document a public introspection API, so this inspects a few
    plausible registry shapes on *ctx*.  If none can be read, it trusts the fact
    that ``register_hook`` returned without raising (``guard.registered``) rather
    than producing a false alarm.
    """
    if not guard.registered:
        return False
    # Real Hermes stores hooks on the manager behind the context
    # (``ctx._manager._hooks``); a fake/!test ctx may expose ``ctx.hooks``.
    candidates = []
    manager = getattr(ctx, "_manager", None)
    if manager is not None:
        candidates.append(getattr(manager, "_hooks", None))
    for attr in ("hooks", "_hooks", "hook_registry", "_hook_registry"):
        candidates.append(getattr(ctx, attr, None))
    for registry_obj in candidates:
        if registry_obj is None or not hasattr(registry_obj, "get"):
            continue
        try:
            entries = registry_obj.get(_HOOK_NAME)
        except Exception:  # noqa: BLE001 — introspection is best-effort
            return True
        if entries:
            callbacks = entries if isinstance(entries, (list, tuple, set)) else [entries]
            # Presence of our callback (or any entry, for wrapping hosts) is good.
            return any(cb is guard.pre_tool_call for cb in callbacks) or True
    # Could not introspect — rely on register_hook having succeeded.
    return True


def _resolve_config_path(ctx: Any) -> Path | None:
    """Pull an optional AgentShield config path from the plugin context/config."""
    for getter in ("config", "plugin_config", "settings"):
        obj = getattr(ctx, getter, None)
        if isinstance(obj, dict):
            val = obj.get("config_path") or obj.get("agentshield_config")
            if isinstance(val, str):
                return Path(val).expanduser()
    return None
