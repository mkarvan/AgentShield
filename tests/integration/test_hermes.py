"""Integration tests for the Hermes Agent plugin.

These exercise the **real** Hermes plugin contract: a ``register(ctx)`` entry
point that wires a ``pre_tool_call`` hook, and the hook callback's
``{"action": "block", ...}`` / ``None`` return values.  A fake ``PluginContext``
stands in for the Hermes runtime so we drive the exact path Hermes drives.

The previous tests called a non-existent ``before_tool_call`` method directly,
which is why a totally-unwired plugin passed CI while silently failing in the
live agent. The contract test below now fails if the plugin is ever wired to a
hook name Hermes does not actually invoke.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from agentshield.core.config import Config
from agentshield.core.models import (
    Decision,
    DecisionAction,
    Finding,
    ScanRequest,
    ScanResult,
    Severity,
)
from agentshield.integrations.hermes import register
from agentshield.integrations.hermes.plugin import (
    _HOOK_NAME,
    HermesGuard,
    intercepted_tools,
)

# Hook names the real NousResearch Hermes runtime actually invokes (from its
# plugin/event-hooks docs). If the plugin registers anything outside this set,
# it will never fire — exactly the bug this rewrite fixes.
REAL_HERMES_HOOKS = frozenset(
    {
        "pre_tool_call",
        "post_tool_call",
        "pre_llm_call",
        "post_llm_call",
        "on_session_start",
        "on_session_end",
        "on_session_finalize",
        "on_session_reset",
        "subagent_stop",
        "pre_gateway_dispatch",
        "transform_tool_result",
    }
)


class FakeCtx:
    """Minimal stand-in for Hermes' PluginContext."""

    def __init__(self, config: dict | None = None) -> None:
        self.hooks: dict[str, list[Any]] = {}
        self.config = config or {}

    def register_hook(self, name: str, callback: Any) -> None:
        self.hooks.setdefault(name, []).append(callback)


class FakeCtxNoHooks:
    """A host that does NOT expose register_hook (incompatible build)."""

    def __init__(self) -> None:
        self.config: dict = {}


def _make_guard(tmp_path: Path, extra_config: dict | None = None) -> HermesGuard:
    base: dict = {"cache": {"db_path": str(tmp_path / "test.db")}}
    if extra_config:
        base.update(extra_config)
    config = Config.model_validate(base)
    return HermesGuard(config=config)


def _register_guard(tmp_path: Path, extra_config: dict | None = None) -> tuple[FakeCtx, Any]:
    """Register via the real entry point and return (ctx, the wired callback)."""
    config = Config.model_validate(
        {"cache": {"db_path": str(tmp_path / "test.db")}, **(extra_config or {})}
    )
    ctx = FakeCtx()
    with patch(
        "agentshield.integrations.hermes.plugin.AgentShield",
        return_value=_FakeShield(config),
    ):
        register(ctx)
    callback = ctx.hooks[_HOOK_NAME][0]
    return ctx, callback


class _FakeShield:
    """Stand-in AgentShield whose ascan is patched per-test."""

    def __init__(self, config: Config) -> None:
        self.config = config

    async def ascan(self, request: ScanRequest) -> ScanResult:  # pragma: no cover - patched
        raise AssertionError("ascan should be patched in the test")

    def scan(self, request: ScanRequest) -> ScanResult:  # pragma: no cover - patched
        raise AssertionError("scan should be patched in the test")


def _clean(req: ScanRequest) -> ScanResult:
    return ScanResult(
        request=req,
        findings=[],
        max_severity=Severity.NONE,
        decision=Decision(action=DecisionAction.ALLOW, reason="No issues found"),
    )


def _block(req: ScanRequest) -> ScanResult:
    finding = Finding(
        rule_id="T1.1", title="Known malicious", severity=Severity.CRITICAL, source="malicious_db"
    )
    return ScanResult(
        request=req,
        findings=[finding],
        max_severity=Severity.CRITICAL,
        decision=Decision(
            action=DecisionAction.BLOCK, reason="BLOCK due to T1.1", findings=[finding]
        ),
    )


def _warn(req: ScanRequest) -> ScanResult:
    finding = Finding(
        rule_id="CVE-2024-9999", title="High CVE", severity=Severity.HIGH, source="osv"
    )
    return ScanResult(
        request=req,
        findings=[finding],
        max_severity=Severity.HIGH,
        decision=Decision(
            action=DecisionAction.NEEDS_CONFIRMATION,
            reason="NEEDS_CONFIRMATION due to CVE-2024-9999",
            findings=[finding],
        ),
    )


# ── registration / contract ──────────────────────────────────────────────────


def test_register_wires_pre_tool_call(tmp_path):
    ctx, callback = _register_guard(tmp_path)
    assert _HOOK_NAME in ctx.hooks
    assert callable(callback)


def test_registered_hook_name_is_one_hermes_actually_calls():
    # Regression guard: the old code used a `before_tool_call` method that Hermes
    # never invokes. Fail loudly if we ever drift to a non-existent hook.
    assert _HOOK_NAME == "pre_tool_call"
    assert _HOOK_NAME in REAL_HERMES_HOOKS


def test_register_on_incompatible_host_does_not_raise_and_is_not_registered(tmp_path, caplog):
    config = Config.model_validate({"cache": {"db_path": str(tmp_path / "t.db")}})
    with patch(
        "agentshield.integrations.hermes.plugin.AgentShield",
        return_value=_FakeShield(config),
    ):
        guard = register(FakeCtxNoHooks())
    assert guard.registered is False  # could not wire — surfaced, not silent


def test_intercepted_tools_includes_terminal_and_execute_code():
    tools = intercepted_tools()
    assert "terminal" in tools
    assert "execute_code" in tools


# ── shell tool interception via the hook ──────────────────────────────────────


def test_terminal_clean_install_allows(tmp_path):
    guard = _make_guard(tmp_path)
    with patch.object(guard.shield, "ascan", new=AsyncMock(side_effect=lambda r: _clean(r))):
        result = guard.pre_tool_call("terminal", {"command": "pip install requests"}, "t1")
    assert result is None


def test_terminal_bad_install_blocks(tmp_path):
    guard = _make_guard(tmp_path)
    with patch.object(guard.shield, "ascan", new=AsyncMock(side_effect=lambda r: _block(r))):
        result = guard.pre_tool_call("terminal", {"command": "pip install evil-pkg"}, "t1")
    assert result is not None
    assert result["action"] == "block"
    assert "evil-pkg" in result["message"]


def test_terminal_non_install_command_allows(tmp_path):
    guard = _make_guard(tmp_path)
    with patch.object(guard.shield, "ascan", new=AsyncMock()) as mock_scan:
        result = guard.pre_tool_call("terminal", {"command": "ls -la /tmp"}, "t1")
    assert result is None
    mock_scan.assert_not_called()


def test_execute_code_with_terminal_install_blocks(tmp_path):
    guard = _make_guard(tmp_path)
    with patch.object(guard.shield, "ascan", new=AsyncMock(side_effect=lambda r: _block(r))):
        result = guard.pre_tool_call(
            "execute_code",
            {"code": "from hermes_tools import terminal\nterminal('pip install evil-pkg')"},
            "t1",
        )
    assert result is not None
    assert result["action"] == "block"


# ── the fail-OPEN bug, now fail-CLOSED ────────────────────────────────────────


def test_terminal_unknown_arg_key_fails_closed(tmp_path):
    """An intercepted shell tool whose command we cannot read must FAIL CLOSED.

    This is the exact latent bug: the old code returned the call unchanged when
    no command/cmd/code key was present, silently allowing the install.
    """
    guard = _make_guard(tmp_path)
    with patch.object(guard.shield, "ascan", new=AsyncMock()) as mock_scan:
        result = guard.pre_tool_call("terminal", {"input": "pip install evil-pkg"}, "t1")
    assert result is not None
    assert result["action"] == "block"
    assert "fail closed" in result["message"]
    mock_scan.assert_not_called()


def test_terminal_empty_command_allows(tmp_path):
    guard = _make_guard(tmp_path)
    result = guard.pre_tool_call("terminal", {"command": "   "}, "t1")
    assert result is None


def test_scanner_error_fails_closed(tmp_path):
    guard = _make_guard(tmp_path)
    with patch.object(guard.shield, "ascan", new=AsyncMock(side_effect=RuntimeError("boom"))):
        result = guard.pre_tool_call("terminal", {"command": "pip install requests"}, "t1")
    assert result is not None
    assert result["action"] == "block"
    assert "fail closed" in result["message"]


def test_shell_expansion_fails_closed(tmp_path):
    guard = _make_guard(tmp_path)
    with patch.object(guard.shield, "ascan", new=AsyncMock()) as mock_scan:
        result = guard.pre_tool_call("terminal", {"command": "pip install $PKG"}, "t1")
    assert result is not None
    assert result["action"] == "block"
    mock_scan.assert_not_called()


def test_unsupported_manager_fails_closed(tmp_path):
    guard = _make_guard(tmp_path)
    result = guard.pre_tool_call("terminal", {"command": "gem install foo"}, "t1")
    assert result is not None
    assert result["action"] == "block"


# ── NEEDS_CONFIRMATION → block (no "ask" in Hermes hooks) ─────────────────────


def test_warn_blocks_pending_review(tmp_path):
    guard = _make_guard(tmp_path)
    with patch.object(guard.shield, "ascan", new=AsyncMock(side_effect=lambda r: _warn(r))):
        result = guard.pre_tool_call("terminal", {"command": "pip install suspicious-pkg"}, "t1")
    assert result is not None
    assert result["action"] == "block"
    assert "review" in result["message"].lower()


# ── non-intercepted tools ─────────────────────────────────────────────────────


def test_non_intercepted_tool_passes_through(tmp_path):
    guard = _make_guard(tmp_path)
    with patch.object(guard.shield, "ascan", new=AsyncMock()) as mock_scan:
        result = guard.pre_tool_call("read_file", {"path": "/etc/passwd"}, "t1")
    assert result is None
    mock_scan.assert_not_called()


def test_callback_never_raises_on_bad_args(tmp_path):
    guard = _make_guard(tmp_path)
    # args is None and weird kwargs — must not raise.
    result = guard.pre_tool_call("terminal", None, "t1")
    assert result is not None  # no command readable → fail closed
    assert result["action"] == "block"


# ── structured install tools (non-Hermes agents reuse the guard) ──────────────


def test_structured_pip_install_blocks(tmp_path):
    guard = _make_guard(tmp_path)
    with patch.object(guard.shield, "ascan", new=AsyncMock(side_effect=lambda r: _block(r))):
        result = guard.pre_tool_call("pip_install", {"package": "evil-pkg"}, "t1")
    assert result is not None
    assert result["action"] == "block"


def test_structured_pip_install_clean_allows(tmp_path):
    guard = _make_guard(tmp_path)
    with patch.object(guard.shield, "ascan", new=AsyncMock(side_effect=lambda r: _clean(r))):
        result = guard.pre_tool_call("pip_install", {"package": "requests"}, "t1")
    assert result is None


# ── real denylist (no mock) through the full path ─────────────────────────────


def test_denylist_blocks_terminal_install(tmp_path):
    guard = _make_guard(tmp_path, {"denylist": ["colouredlogs"]})
    result = guard.pre_tool_call(
        "terminal", {"command": "pip install --break-system-packages colouredlogs"}, "t1"
    )
    assert result is not None
    assert result["action"] == "block"
    assert "colouredlogs" in result["message"].lower()


# ── sync wrapper works even with a running event loop ─────────────────────────


@pytest.mark.asyncio
async def test_evaluate_command_sync_under_running_loop(tmp_path):
    from agentshield.enforce.command_scan import evaluate_command_sync

    guard = _make_guard(tmp_path, {"denylist": ["colouredlogs"]})
    # We are inside a running loop here; the sync wrapper must not raise.
    decision = evaluate_command_sync(guard.shield, "pip install colouredlogs", source="hermes")
    assert decision.action == DecisionAction.BLOCK


# ── interop with the REAL Hermes block extractor (skips if Hermes absent) ─────


def test_interop_with_real_hermes_block_extractor(tmp_path):
    """Drive Hermes's own ``get_pre_tool_call_block_message`` with our real
    callback. This is the genuine enforcement path ``run_agent.py`` uses before
    dispatching a tool — it calls ``invoke_hook('pre_tool_call', ...)`` and reads
    ``{"action": "block", "message": ...}`` from the results. Skips cleanly when
    the Hermes package isn't installed (e.g. plain repo CI); runs for real inside
    a configured Hermes container.
    """
    plugins = pytest.importorskip("hermes_cli.plugins")
    guard = _make_guard(tmp_path, {"denylist": ["evil-pkg"], "allowlist": ["requests"]})
    mgr = plugins.get_plugin_manager()
    mgr._hooks.setdefault("pre_tool_call", []).append(guard.pre_tool_call)
    try:
        blocked = plugins.get_pre_tool_call_block_message(
            "terminal", {"command": "pip install evil-pkg"}
        )
        assert blocked and "evil-pkg" in blocked
        allowed = plugins.get_pre_tool_call_block_message(
            "terminal", {"command": "pip install requests"}
        )
        assert allowed is None
    finally:
        mgr._hooks["pre_tool_call"].remove(guard.pre_tool_call)


# ── verify_registered (regression) ─────────────────────────────────────────────
# The registry-introspection branch ended in `any(...) or True` — constant True,
# so a failed registration could never be reported.


def test_verify_registered_false_when_hook_absent_from_readable_registry():
    from agentshield.integrations.hermes.plugin import HermesGuard, verify_registered

    class Ctx:
        hooks = {}  # readable registry, hook not present

    guard = HermesGuard.__new__(HermesGuard)
    guard.registered = True
    assert verify_registered(Ctx(), guard) is False


def test_verify_registered_true_when_hook_present():
    from agentshield.integrations.hermes.plugin import HermesGuard, verify_registered

    guard = HermesGuard.__new__(HermesGuard)
    guard.registered = True

    class Ctx:
        hooks = {"pre_tool_call": [lambda *a, **k: None]}

    assert verify_registered(Ctx(), guard) is True


def test_verify_registered_true_when_nothing_readable():
    from agentshield.integrations.hermes.plugin import HermesGuard, verify_registered

    guard = HermesGuard.__new__(HermesGuard)
    guard.registered = True

    class Ctx:  # no hook registry attributes at all
        pass

    assert verify_registered(Ctx(), guard) is True


def test_verify_registered_false_when_not_registered():
    from agentshield.integrations.hermes.plugin import HermesGuard, verify_registered

    guard = HermesGuard.__new__(HermesGuard)
    guard.registered = False
    assert verify_registered(object(), guard) is False
