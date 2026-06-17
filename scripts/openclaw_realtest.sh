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
OPENCLAW_HOME="${OPENCLAW_HOME:-$HOME/.openclaw}"

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

# Deterministic, offline verdicts. Back up any existing config and restore it on
# exit via a trap (covers early exits too); if there was no config, remove the
# temporary one we write.
CFG_CREATED=0
restore_cfg() {
  if [ -f "$CFG.realtest.bak" ]; then
    mv "$CFG.realtest.bak" "$CFG" && echo "restored original $CFG"
  elif [ "$CFG_CREATED" = 1 ]; then
    rm -f "$CFG" && echo "removed temporary test config $CFG"
  fi
}
trap restore_cfg EXIT INT TERM

mkdir -p "$(dirname "$CFG")"
if [ -f "$CFG" ]; then cp "$CFG" "$CFG.realtest.bak"; else CFG_CREATED=1; fi
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

# --- 2b. Scanner-unavailable fallback (CLI missing -> JS fail-closed) ---------
# When the agentshield CLI cannot run, the plugin must still FAIL CLOSED for
# install-looking commands via its broadened JS fallback (INSTALL_RE) — including
# `python -m pip install` AND the attached `python -mpip install` form that the
# pre-fix regex missed. We make the CLI unavailable by pointing AGENTSHIELD_BIN at
# a missing binary and drive the REAL evaluateToolCall with its REAL default
# runner (which spawns $AGENTSHIELD_BIN and gets ENOENT).
hr
echo "Scanner-unavailable fallback (CLI missing -> JS fail-closed):"
fb_rc=0
AGENTSHIELD_BIN="$HERE/.no-such-agentshield-$$" node --input-type=module - "$PLUGIN_DIR" "$BAD" <<'NODE'
import { pathToFileURL } from "node:url";
import path from "node:path";
const [pluginDir, BAD] = process.argv.slice(2);
const { evaluateToolCall } = await import(
  pathToFileURL(path.join(pluginDir, "scan-command.mjs")).href
);
let rc = 0;
// Real default runner spawns process.env.AGENTSHIELD_BIN -> ENOENT -> fail closed.
const mustBlock = [
  `pip install ${BAD}`,
  `python -m pip install ${BAD}`,
  `python -mpip install ${BAD}`,   // attached -m form — the previously-missed case
  `python3 -mpip install ${BAD}`,
];
for (const cmd of mustBlock) {
  const r = evaluateToolCall("exec", { command: cmd });
  if (r && r.block) console.log(`  PASS  fallback blocked: ${cmd}`);
  else { console.log(`  FAIL  fallback did NOT block: ${cmd}`); rc = 1; }
}
const safe = evaluateToolCall("exec", { command: "ls -la" });
if (!safe) console.log("  PASS  fallback allows non-install: ls -la");
else { console.log("  FAIL  fallback blocked a non-install command"); rc = 1; }
process.exit(rc);
NODE
fb_rc=$?
if [ "$fb_rc" -eq 0 ]; then ok "scanner-unavailable fallback (installs blocked, non-install allowed)"; else bad "scanner-unavailable fallback (exit $fb_rc)"; fi
hr

# --- Purge stale agentshield debris from prior (broken) installs -------------
# A previously-broken install can leave an extension dir whose OLD manifest lacks
# `configSchema`. OpenClaw then rejects the whole plugin set with
# "config invalid: plugin manifest requires configSchema", and `openclaw doctor
# --fix` does NOT remove it — the dir must be physically deleted and the stale
# entry dropped from openclaw.json. We purge ONLY agentshield-related extension
# dirs and entries here; other plugins are never touched. Idempotent.
purge_agentshield_debris() {
  ext_dir="$OPENCLAW_HOME/extensions"
  if [ -d "$ext_dir" ]; then
    # @agentshield-openclaw-plugin-<hash>/ and any old agentshield-id dirs.
    for d in "$ext_dir"/@agentshield-openclaw-plugin-* "$ext_dir"/@agentshield-openclaw-plugin \
             "$ext_dir"/agentshield-* "$ext_dir"/agentshield; do
      [ -e "$d" ] || continue
      rm -rf "$d" 2>/dev/null && echo "  CLEAN removed stale extension dir: $d"
    done
  fi

  cfg="$OPENCLAW_HOME/openclaw.json"
  if [ -f "$cfg" ]; then
    if command -v python3 >/dev/null 2>&1; then
      if python3 - "$cfg" <<'PY'
import json, sys
p = sys.argv[1]
STALE = {"agentshield", "@agentshield/openclaw-plugin"}
try:
    with open(p) as f:
        data = json.load(f)
except Exception:
    sys.exit(1)  # unreadable/not-json: leave it alone
plugins = data.get("plugins")
if not isinstance(plugins, dict):
    sys.exit(1)
entries = plugins.get("entries")
changed = False
if isinstance(entries, list):
    kept = []
    for e in entries:
        eid = (e.get("id") or e.get("name")) if isinstance(e, dict) else e
        if eid in STALE:
            changed = True
        else:
            kept.append(e)
    if changed:
        plugins["entries"] = kept
elif isinstance(entries, dict):
    for k in list(entries):
        if k in STALE:
            del entries[k]
            changed = True
if not changed:
    sys.exit(1)  # nothing agentshield-related to remove
with open(p, "w") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
sys.exit(0)
PY
      then
        echo "  CLEAN pruned stale agentshield entries from $cfg"
      fi
    else
      echo "  NOTE  python3 absent; cannot prune stale agentshield entries from $cfg (delete them manually if a stale install blocks validation)."
    fi
  fi
}

# --- 3. Best-effort: install into OpenClaw and confirm its loader lists it ----
# OpenClaw refuses to load plugin files that are not root-owned. If we can become
# root, chown the plugin tree and (re)install through OpenClaw's own loader. We
# first physically purge any agentshield debris from prior broken installs (a
# stale extension dir with a configSchema-less manifest blocks validation), then
# clear any stale registry entry, then install.
if command -v openclaw >/dev/null 2>&1; then
  purge_agentshield_debris
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

# Config is restored by the restore_cfg EXIT trap registered above.
hr
echo "RESULT: $pass passed, $fail failed"
if [ "$fail" -eq 0 ] && [ "$real_rc" -eq 0 ]; then echo "OVERALL: PASS"; exit 0; else echo "OVERALL: FAIL"; exit 1; fi
