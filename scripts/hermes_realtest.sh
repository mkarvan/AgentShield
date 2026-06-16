#!/usr/bin/env bash
# =============================================================================
# AgentShield × Hermes — REAL-INSTANCE interception test
# =============================================================================
# Run this INSIDE the user's real, fully-configured Hermes container/box. It
# proves AgentShield's pre_tool_call hook is wired into Hermes's OWN plugin
# loader and that it actually blocks a bad install through Hermes's OWN
# enforcement function — not a fake ctx and not by calling our methods directly.
#
# It drives the genuine path Hermes uses in production:
#   hermes_cli.plugins.discover_plugins()            ← Hermes's real loader
#   hermes_cli.plugins.get_pre_tool_call_block_message(tool, args)
#                                                    ← the exact function
#       run_agent.py calls before dispatching every tool; returns the block
#       message when a pre_tool_call hook vetoes the call.
#
# No LLM and no real package install are required for the must-have checks
# (get_pre_tool_call_block_message only consults hooks; it does not run pip).
# An optional LLM-driven end-to-end is gated behind HERMES_LLM_E2E=1.
#
# Usage:
#   HERMES_PY=~/.hermes/venv/bin/python ./scripts/hermes_realtest.sh
# Env:
#   HERMES_PY   python interpreter Hermes runs from (default ~/.hermes/venv/bin/python)
#   HERMES_DIR  Hermes source dir, if it must be on sys.path (optional)
#   HERMES_LLM_E2E=1  also run the optional model-driven end-to-end
# =============================================================================
set -uo pipefail

HERMES_PY="${HERMES_PY:-$HOME/.hermes/venv/bin/python}"
BAD="${AGENTSHIELD_E2E_BAD:-agentshield-e2e-blocked-pkg}"
GOOD="${AGENTSHIELD_E2E_GOOD:-agentshield-e2e-allowed-pkg}"
CFG="$HOME/.config/agentshield/config.toml"

pass=0; fail=0
ok()   { echo "  PASS  $*"; pass=$((pass+1)); }
bad()  { echo "  FAIL  $*"; fail=$((fail+1)); }
hr()   { echo "------------------------------------------------------------"; }

echo "AgentShield × Hermes real-instance test"
echo "interpreter: $HERMES_PY"
hr

if [ ! -x "$HERMES_PY" ]; then
  echo "FATAL: '$HERMES_PY' is not executable. Set HERMES_PY to the interpreter Hermes runs from."
  exit 2
fi

# --- Deterministic, offline verdicts: deny BAD, allow GOOD -------------------
mkdir -p "$(dirname "$CFG")"
if [ -f "$CFG" ]; then cp "$CFG" "$CFG.realtest.bak"; echo "backed up existing config -> $CFG.realtest.bak"; fi
cat > "$CFG" <<TOML
# Written by hermes_realtest.sh for a deterministic, offline interception test.
denylist = ["$BAD"]
allowlist = ["$GOOD"]
TOML
echo "wrote deterministic test config -> $CFG"
hr

# --- 1. Import the plugin in Hermes's interpreter ---------------------------
if "$HERMES_PY" -c "from agentshield.integrations.hermes import register" 2>/dev/null; then
  ok "agentshield.integrations.hermes importable in Hermes's interpreter"
else
  bad "cannot import agentshield in $HERMES_PY — install: $HERMES_PY -m pip install 'agentshield[hermes] @ git+https://github.com/mkarvan/AgentShield.git'"
fi

# --- 2-4. Drive Hermes's REAL loader + enforcement function -----------------
EXTRA_PATH=""
[ -n "${HERMES_DIR:-}" ] && EXTRA_PATH="$HERMES_DIR"

AGENTSHIELD_E2E_BAD="$BAD" AGENTSHIELD_E2E_GOOD="$GOOD" HERMES_EXTRA_PATH="$EXTRA_PATH" \
"$HERMES_PY" - <<'PY'
import os, sys
extra = os.environ.get("HERMES_EXTRA_PATH") or ""
if extra:
    sys.path.insert(0, extra)

BAD = os.environ["AGENTSHIELD_E2E_BAD"]
GOOD = os.environ["AGENTSHIELD_E2E_GOOD"]

try:
    from hermes_cli.plugins import (
        discover_plugins,
        get_plugin_manager,
        get_pre_tool_call_block_message,
    )
except Exception as exc:  # noqa: BLE001
    print(f"  FAIL  cannot import hermes_cli.plugins ({exc}). "
          f"Run inside the Hermes box, or set HERMES_DIR to the Hermes source dir.")
    sys.exit(3)

rc = 0

# Use Hermes's own loader (respects ~/.hermes/config.yaml plugins.enabled).
discover_plugins(force=True)
mgr = get_plugin_manager()

plugins = {p["name"]: p for p in mgr.list_plugins()}
ash = plugins.get("agentshield")
if ash is None:
    print("  FAIL  'agentshield' not discovered by Hermes's plugin loader. "
          "Install agentshield[hermes] in this interpreter and/or drop it under ~/.hermes/plugins/.")
    rc = 1
elif not ash.get("enabled"):
    print("  FAIL  'agentshield' discovered but NOT enabled. Add it to plugins.enabled "
          "in ~/.hermes/config.yaml:\n          plugins:\n            enabled:\n              - agentshield")
    rc = 1
elif ash.get("error"):
    print(f"  FAIL  'agentshield' failed to load: {ash['error']}")
    rc = 1
else:
    print(f"  PASS  'agentshield' loaded & enabled via Hermes's real loader "
          f"({ash.get('hooks')} hook(s) registered)")

# Confirm the pre_tool_call hook is actually in Hermes's hook registry.
hooks = getattr(mgr, "_hooks", {}) or {}
if hooks.get("pre_tool_call"):
    print(f"  PASS  Hermes registry has {len(hooks['pre_tool_call'])} pre_tool_call hook(s)")
else:
    print("  FAIL  no pre_tool_call hook registered in Hermes — the guard will NEVER fire")
    rc = 1

# The decisive checks: drive Hermes's OWN pre-dispatch enforcement function.
def block_msg(tool, args):
    return get_pre_tool_call_block_message(tool, args)

# (a) bad install via terminal MUST be blocked — this is the exact gap we fix.
msg_bad = block_msg("terminal", {"command": f"pip install {BAD}"})
if msg_bad:
    print(f"  PASS  terminal 'pip install {BAD}' BLOCKED by the hook: {msg_bad[:80]}")
else:
    print(f"  FAIL  terminal 'pip install {BAD}' was NOT blocked — hook did not fire/return block")
    rc = 1

# (b) good install via terminal must be allowed (None).
msg_good = block_msg("terminal", {"command": f"pip install {GOOD}"})
if msg_good is None:
    print(f"  PASS  terminal 'pip install {GOOD}' allowed (no block)")
else:
    print(f"  FAIL  terminal 'pip install {GOOD}' unexpectedly blocked: {msg_good[:80]}")
    rc = 1

# (c) execute_code that drives a terminal install must also be blocked.
msg_code = block_msg("execute_code", {"code": f"from hermes_tools import terminal\nterminal('pip install {BAD}')"})
if msg_code:
    print(f"  PASS  execute_code body installing {BAD} BLOCKED")
else:
    print(f"  FAIL  execute_code body installing {BAD} was NOT blocked")
    rc = 1

# (d) fail-closed: an intercepted terminal call whose command we cannot read.
msg_argkey = block_msg("terminal", {"input": f"pip install {BAD}"})
if msg_argkey:
    print(f"  PASS  unreadable terminal command FAILS CLOSED (blocked)")
else:
    print(f"  FAIL  unreadable terminal command was allowed (should fail closed)")
    rc = 1

sys.exit(rc)
PY
real_rc=$?
hr
if [ "$real_rc" -eq 0 ]; then ok "real loader + enforcement checks"; else bad "real loader + enforcement checks (exit $real_rc)"; fi

# --- Confirm the startup self-verify line is in the logs (best-effort) -------
if ls "$HOME"/.hermes/logs/*.log >/dev/null 2>&1; then
  if grep -rqi "AgentShield: registered 'pre_tool_call'" "$HOME"/.hermes/logs/*.log; then
    ok "log shows 'AgentShield: registered pre_tool_call guard'"
  else
    echo "  NOTE  no registration line in ~/.hermes/logs yet (restart Hermes to emit it)"
  fi
fi

# --- Optional: model-driven end-to-end (needs creds) ------------------------
if [ "${HERMES_LLM_E2E:-0}" = "1" ]; then
  hr; echo "Optional LLM end-to-end (HERMES_LLM_E2E=1):"
  LOG="$(mktemp)"
  if command -v hermes >/dev/null 2>&1; then
    printf 'Use the terminal to run exactly: pip install %s\n' "$BAD" | timeout 180 hermes chat >"$LOG" 2>&1 || true
    if grep -qi "AgentShield" "$LOG"; then
      ok "LLM-driven install attempt was intercepted by AgentShield"
    else
      bad "LLM-driven attempt: no AgentShield interception seen in output ($LOG)"
    fi
  else
    echo "  NOTE  'hermes' CLI not on PATH; skipping LLM e2e."
  fi
fi

# --- Restore config ---------------------------------------------------------
if [ -f "$CFG.realtest.bak" ]; then mv "$CFG.realtest.bak" "$CFG"; echo "restored original $CFG"; fi

hr
echo "RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ] && [ "$real_rc" -eq 0 ] && { echo "OVERALL: PASS"; exit 0; } || { echo "OVERALL: FAIL"; exit 1; }
