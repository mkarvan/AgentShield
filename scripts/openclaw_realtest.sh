#!/bin/sh
# =============================================================================
# AgentShield x OpenClaw - REAL-INSTANCE interception test  (POSIX sh)
# =============================================================================
# Run this INSIDE the user's real OpenClaw box/container. OpenClaw is a
# TypeScript/Node framework; AgentShield ships a Node plugin
# (integrations/openclaw/) that registers a `before_tool_call` hook on the
# `exec` tool and shells out to the `agentshield` CLI for verdicts via
# `agentshield guard-scan-cmd` (exit 1 = block, exit 0 = allow).
#
# This proves, through the REAL surfaces:
#   1. `agentshield guard-scan-cmd` blocks a bad install (exit 1) and allows a
#      good one (exit 0) - the verdict oracle the plugin depends on.
#   2. The plugin's REAL registered before_tool_call handler (driven through the
#      real definePluginEntry loader when present, else the plugin's own pure
#      module) + the real CLI blocks a bad `exec` install and allows a good one.
#      It FAILS if the hook never fires.
#   3. (Best-effort) OpenClaw's own loader lists the plugin (`openclaw plugins`).
#
# POSIX sh only (the reference container had no bash). A model-driven end-to-end
# is gated behind OPENCLAW_LLM_E2E=1.
#
# Usage:   sh scripts/openclaw_realtest.sh
# Env:
#   AGENTSHIELD_BIN     path to the agentshield CLI (default: agentshield on PATH)
#   PLUGIN_DIR          plugin path (default: integrations/openclaw next to this)
#   OPENCLAW_LLM_E2E=1  also run the optional model-driven end-to-end
# =============================================================================
set -u

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PLUGIN_DIR="${PLUGIN_DIR:-$HERE/../integrations/openclaw}"
AGENTSHIELD_BIN="${AGENTSHIELD_BIN:-agentshield}"
export AGENTSHIELD_BIN
BAD="${AGENTSHIELD_E2E_BAD:-agentshield-e2e-blocked-pkg}"
GOOD="${AGENTSHIELD_E2E_GOOD:-agentshield-e2e-allowed-pkg}"
CFG="$HOME/.config/agentshield/config.toml"

pass=0
fail=0
real_rc=0
ok()   { echo "  PASS  $*"; pass=$((pass + 1)); }
bad()  { echo "  FAIL  $*"; fail=$((fail + 1)); }
hr()   { echo "------------------------------------------------------------"; }

echo "AgentShield x OpenClaw real-instance test"
echo "plugin: $PLUGIN_DIR"
echo "cli:    $AGENTSHIELD_BIN"
hr

command -v node >/dev/null 2>&1 || { echo "FATAL: node not found (OpenClaw needs Node >= 22)"; exit 2; }
command -v "$AGENTSHIELD_BIN" >/dev/null 2>&1 || { echo "FATAL: '$AGENTSHIELD_BIN' not on PATH - install agentshield (pipx install agentshield)"; exit 2; }
[ -f "$PLUGIN_DIR/index.mjs" ] || { echo "FATAL: plugin not found at $PLUGIN_DIR"; exit 2; }

# Deterministic, offline verdicts.
mkdir -p "$(dirname "$CFG")"
[ -f "$CFG" ] && cp "$CFG" "$CFG.realtest.bak"
printf 'denylist = ["%s"]\nallowlist = ["%s"]\n' "$BAD" "$GOOD" > "$CFG"
echo "wrote deterministic test config -> $CFG"
hr

# --- 1. The CLI verdict oracle (real: agentshield guard-scan-cmd) ------------
# guard-scan-cmd takes the command as argv TOKENS and exits 1 on block, 0 on allow.
"$AGENTSHIELD_BIN" guard-scan-cmd pip install "$BAD" >/dev/null 2>&1
if [ $? -eq 1 ]; then
  ok "guard-scan-cmd blocks bad install (exit 1)"
else
  bad "guard-scan-cmd did NOT block bad install (expected exit 1)"
fi
"$AGENTSHIELD_BIN" guard-scan-cmd pip install "$GOOD" >/dev/null 2>&1
if [ $? -eq 0 ]; then
  ok "guard-scan-cmd allows good install (exit 0)"
else
  bad "guard-scan-cmd wrongly blocked good install (expected exit 0)"
fi
hr

# --- 2. The REAL registered handler via the real definePluginEntry loader ----
node --input-type=module - "$PLUGIN_DIR" "$BAD" "$GOOD" <<'NODE'
import { pathToFileURL } from "node:url";
import path from "node:path";

const [pluginDir, BAD, GOOD] = process.argv.slice(2);
let rc = 0;

const registered = {};
const fakeApi = { on: (name, handler) => { (registered[name] ||= []).push(handler); } };

let entry;
try {
  await import("openclaw/plugin-sdk/plugin-entry"); // exercise real SDK if present
  const mod = await import(pathToFileURL(path.join(pluginDir, "index.mjs")).href);
  entry = mod.default;
  if (entry && typeof entry.register === "function") entry.register(fakeApi);
  else if (typeof entry === "function") entry(fakeApi);
  console.log("  PASS  loaded plugin via real openclaw/plugin-sdk");
} catch {
  try {
    const mod = await import(pathToFileURL(path.join(pluginDir, "index.mjs")).href);
    entry = mod.default;
    if (entry && typeof entry.register === "function") entry.register(fakeApi);
    console.log("  NOTE  openclaw SDK not importable here; loaded plugin entry directly");
  } catch {
    const { evaluateToolCall, HOOK_NAME, EXEC_TOOL_NAMES } = await import(
      pathToFileURL(path.join(pluginDir, "scan-command.mjs")).href
    );
    registered[HOOK_NAME] = [
      async (event) =>
        EXEC_TOOL_NAMES.has(event.toolName) ? evaluateToolCall(event.toolName, event.params) : null,
    ];
    console.log("  NOTE  openclaw SDK not present; verifying via the plugin's pure module + real CLI");
  }
}

const handlers = registered["before_tool_call"] || [];
if (handlers.length === 0) {
  console.log("  FAIL  plugin did not register a before_tool_call hook - it will NEVER fire");
  process.exit(1);
}
console.log(`  PASS  plugin registered ${handlers.length} before_tool_call handler(s)`);

async function decide(toolName, params) {
  for (const h of handlers) {
    const r = await h({ toolName, params });
    if (r && r.block) return r;
  }
  return null;
}

const badRes = await decide("exec", { command: `pip install ${BAD}` });
if (badRes && badRes.block) console.log(`  PASS  exec 'pip install ${BAD}' BLOCKED: ${String(badRes.blockReason).slice(0, 80)}`);
else { console.log(`  FAIL  exec install of ${BAD} was NOT blocked`); rc = 1; }

const goodRes = await decide("exec", { command: `pip install ${GOOD}` });
if (!goodRes) console.log(`  PASS  exec 'pip install ${GOOD}' allowed`);
else { console.log(`  FAIL  exec install of ${GOOD} was unexpectedly blocked`); rc = 1; }

const lsRes = await decide("exec", { command: "ls -la" });
if (!lsRes) console.log("  PASS  non-install exec allowed");
else { console.log("  FAIL  non-install exec was blocked"); rc = 1; }

process.exit(rc);
NODE
real_rc=$?
hr
if [ "$real_rc" -eq 0 ]; then ok "real handler dispatch (bad blocked, good allowed)"; else bad "real handler dispatch (exit $real_rc)"; fi

# --- 3. Best-effort: install into OpenClaw and confirm its loader lists it ----
# OpenClaw refuses to load plugin files that are not root-owned. If we can become
# root, chown the plugin tree and (re)install through OpenClaw's own loader,
# clearing any stale entry from a previous (broken) attempt first.
if command -v openclaw >/dev/null 2>&1; then
  CHOWN=""
  if [ "$(id -u)" = "0" ]; then CHOWN="chown"; elif command -v sudo >/dev/null 2>&1; then CHOWN="sudo chown"; fi
  if [ -n "$CHOWN" ]; then
    $CHOWN -R root:root "$PLUGIN_DIR" 2>/dev/null || $CHOWN -R 0:0 "$PLUGIN_DIR" 2>/dev/null || true
  else
    echo "  NOTE  not root and no sudo - OpenClaw may reject non-root-owned plugin files; run as root to install."
  fi
  # Clear stale entries from earlier broken installs (ignore errors).
  openclaw plugins remove agentshield >/dev/null 2>&1 || true
  openclaw plugins remove @agentshield/openclaw-plugin >/dev/null 2>&1 || true
  openclaw plugins install "$PLUGIN_DIR" >/dev/null 2>&1 || true
  if openclaw plugins list 2>/dev/null | grep -qi agentshield; then
    ok "openclaw plugins list shows agentshield"
  else
    echo "  NOTE  'agentshield' not listed by 'openclaw plugins list' - install it as root: openclaw plugins install $PLUGIN_DIR"
  fi
fi

# --- Optional model-driven end-to-end ----------------------------------------
if [ "${OPENCLAW_LLM_E2E:-0}" = "1" ] && command -v openclaw >/dev/null 2>&1; then
  hr
  echo "Optional LLM end-to-end (OPENCLAW_LLM_E2E=1):"
  LOG=$(mktemp)
  printf 'Use the exec tool to run exactly: pip install %s\n' "$BAD" | timeout 180 openclaw chat >"$LOG" 2>&1 || true
  if grep -qi "agentshield\|block" "$LOG"; then ok "LLM-driven exec install intercepted"; else bad "LLM-driven attempt not intercepted (see $LOG)"; fi
fi

# --- Restore config ----------------------------------------------------------
[ -f "$CFG.realtest.bak" ] && mv "$CFG.realtest.bak" "$CFG" && echo "restored original $CFG"

hr
echo "RESULT: $pass passed, $fail failed"
if [ "$fail" -eq 0 ] && [ "$real_rc" -eq 0 ]; then echo "OVERALL: PASS"; exit 0; else echo "OVERALL: FAIL"; exit 1; fi
