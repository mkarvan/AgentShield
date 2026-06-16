#!/bin/sh
# =============================================================================
# AgentShield container end-to-end test harness
# =============================================================================
# Self-contained, self-grading POSIX-sh (BusyBox/ash safe) test harness meant to
# be run INSIDE the alpine/arm64 container that has AgentShield
# installed, e.g.:
#
#     container exec <container-id> sh < ~/Downloads/AgentShield/scripts/container_e2e_test.sh
#
# It exercises every AgentShield enforcement surface with a known-bad "sentinel"
# package (which must BLOCK) and a known-good package (which must ALLOW), grading
# each case PASS/FAIL by comparing the observed BLOCK/ALLOW against the expected.
#
# The "known-bad sentinel" is implemented using AgentShield's REAL malicious-
# package detection mechanism: a row in the local `malicious_packages` SQLite
# table at the default DB path ($HOME/.agentshield/agentshield.db). MaliciousDB
# .check() reads this table on every scan (offline, instant) and emits a T1.1
# CRITICAL finding -> the response engine maps CRITICAL -> BLOCK. This is the
# only mechanism that works uniformly for pypi/npm AND cargo (the bundled
# curated JSON ships malicious pypi/npm names but an empty cargo list).
#
# Known-good packages are the canonical popular names (requests / lodash /
# serde) that appear verbatim in AgentShield's top_packages.json, so the
# typosquatting analyzer treats them as exact matches and emits no finding.
# Because a *warmed* offline DB can still carry real CVEs for popular packages
# (e.g. requests' CVE-2018-18074 maps to CRITICAL -> BLOCK), the harness also
# backs up and temporarily removes any cve_mirror / malicious_packages rows for
# the GOOD packages (restored on exit) so the GOOD path is deterministic ALLOW.
# Scanning runs with AGENTSHIELD_OFFLINE=1 so verdicts never depend on the
# network, and AGENTSHIELD_SESSION_ID is unset so the per-session scan rate
# limiter (default 20/hour, BLOCKs once tripped) can't accumulate across calls.
#
# Safety: the sentinel rows are tagged source='agentshield-e2e' and are deleted
# on every entry AND on exit (via trap), so a real urllib3 (used only for the
# transitive-dependency test) is never left flagged in the user's DB.
#
# Standing rules honoured: no branches (main only), nothing here touches
# docs/real-fix-plan.md. Committing THIS script to main is fine.
# =============================================================================

set -u

# ----------------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------------
BAD="agentshield-e2e-sentinel-bad"   # sentinel package name (all ecosystems)
GOOD_PYPI="requests"
GOOD_NPM="lodash"
GOOD_CARGO="serde"
TRANS_PARENT="requests"              # real pypi pkg with a real dep we poison
TRANS_DEP="urllib3"                  # real transitive dep of requests
E2E_TAG="agentshield-e2e"            # source tag for cleanup
MARKER="REAL_PM_RAN"                 # printed by the fake downstream binary

export AGENTSHIELD_OFFLINE=1

# AgentShield has a per-SESSION package rate limiter (core/rate_limiter.py,
# default 20 scans/hour) that returns a hard BLOCK once tripped. A "session" is
# keyed by $AGENTSHIELD_SESSION_ID, falling back to a fresh UUID per process. If
# the container exports a shared AGENTSHIELD_SESSION_ID, our many scans would
# accumulate into one session and start blocking otherwise-clean packages. Unset
# it so every agentshield invocation gets its own fresh session (counter = 0).
unset AGENTSHIELD_SESSION_ID 2>/dev/null || true

# ----------------------------------------------------------------------------
# Colours (disabled when not a TTY or NO_COLOR set)
# ----------------------------------------------------------------------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    RED=$(printf '\033[31m'); GRN=$(printf '\033[32m'); YEL=$(printf '\033[33m')
    CYN=$(printf '\033[36m'); BLD=$(printf '\033[1m');  RST=$(printf '\033[0m')
else
    RED=''; GRN=''; YEL=''; CYN=''; BLD=''; RST=''
fi

# ----------------------------------------------------------------------------
# Scratch + counters
# ----------------------------------------------------------------------------
TMP=$(mktemp -d 2>/dev/null || echo /tmp/as-e2e.$$)
mkdir -p "$TMP"
RESULTS="$TMP/results.tsv"
: > "$RESULTS"
FAKEBIN="$TMP/fakebin"
SHIMDIR="$TMP/shim"
LIB="$TMP/libagentshield_exec.so"
OFFLINE_BACKUP="$TMP/offline_good_backup.json"
PROXY_PIDS=""

P_PASS=0; P_FAIL=0; P_SKIP=0

say()  { printf '%s\n' "$*"; }
hr()   { printf '%s\n' "------------------------------------------------------------------------"; }
head2(){ printf '\n%s== %s ==%s\n' "$BLD" "$*" "$RST"; }

# ----------------------------------------------------------------------------
# Cleanup
# ----------------------------------------------------------------------------
cleanup() {
    for pid in $PROXY_PIDS; do kill "$pid" 2>/dev/null; done
    # uninstall any shims we created (only removes AgentShield-generated files)
    [ -d "$SHIMDIR" ] && agentshield shim uninstall --dir "$SHIMDIR" >/dev/null 2>&1
    # delete sentinel rows so nothing stays flagged in the user's DB
    delete_sentinels 2>/dev/null
    # restore any offline CVE/malicious rows we temporarily removed for GOOD pkgs
    restore_good_offline 2>/dev/null
    rm -rf "$TMP" 2>/dev/null
}
trap cleanup EXIT INT TERM

# ----------------------------------------------------------------------------
# Grading helpers  (must NOT run in a subshell, or counters won't persist)
# ----------------------------------------------------------------------------
record() {  # status feature expected observed command
    _st=$1; _ft=$2; _ex=$3; _ob=$4; _cmd=$5
    printf '%s\t%s\t%s\t%s\t%s\n' "$_st" "$_ft" "$_ex" "$_ob" "$_cmd" >> "$RESULTS"
    case $_st in
        PASS) P_PASS=$((P_PASS+1)); _c=$GRN ;;
        FAIL) P_FAIL=$((P_FAIL+1)); _c=$RED ;;
        SKIP) P_SKIP=$((P_SKIP+1)); _c=$YEL ;;
        *)    _c=$RST ;;
    esac
    printf '  %s%-4s%s %-40s exp=%-14s obs=%-14s\n' "$_c" "$_st" "$RST" "$_ft" "$_ex" "$_ob"
}
grade() {   # feature expected observed command
    if [ "$2" = "$3" ]; then record PASS "$1" "$2" "$3" "$4"
    else record FAIL "$1" "$2" "$3" "$4"; fi
}
skip()  { record SKIP "$1" "$2" "n/a" "$3"; }

# ----------------------------------------------------------------------------
# Sentinel management (uses the installed agentshield package directly)
# ----------------------------------------------------------------------------
insert_sentinels() {  # extra ecosystems handled; always pypi/npm/cargo for BAD
    python3 - "$@" <<PYEOF
import asyncio, sys
from agentshield.core.config import CacheConfig, DEFAULT_DB_PATH
from agentshield.core.cache import ScanCache
bad = "$BAD"; tag = "$E2E_TAG"
rows = [(bad, "pypi", "e2e sentinel", tag),
        (bad, "npm",  "e2e sentinel", tag),
        (bad, "cargo","e2e sentinel", tag)]
for extra in sys.argv[1:]:
    name, eco = extra.split("@@")
    rows.append((name, eco, "e2e transitive sentinel", tag))
c = ScanCache(CacheConfig(db_path=DEFAULT_DB_PATH))
asyncio.run(c.add_malicious_packages_bulk(rows))
PYEOF
}
delete_sentinels() {
    python3 - <<PYEOF
import sqlite3
from agentshield.core.config import DEFAULT_DB_PATH
try:
    con = sqlite3.connect(str(DEFAULT_DB_PATH))
    con.execute("DELETE FROM malicious_packages WHERE source=?", ("$E2E_TAG",))
    con.commit(); con.close()
except Exception:
    pass
PYEOF
}

# ----------------------------------------------------------------------------
# Offline-DB neutralization for the known-GOOD packages.
#
# The container's DB may be warmed (`agentshield cache warm`) so the offline
# cve_mirror contains real CVEs. A "popular" package like `requests` has
# historically CRITICAL-rated advisories (e.g. CVE-2018-18074, CVSS 9.8); in
# offline mode the scanner reads cve_mirror, _SEV_MAP maps the row to CRITICAL,
# and the response engine maps CRITICAL -> BLOCK. That makes such a package a
# legitimately-blocked, INVALID "known-good" fixture.
#
# To make the GOOD path deterministic *without* destroying user data, we back up
# and DELETE any cve_mirror / malicious_packages rows for the GOOD packages at
# setup, then RESTORE them on exit. After purge the GOOD packages produce zero
# findings -> ALLOW, exercising the genuine clean-scan allow path (not a config
# shortcut). The transitive parent stays non-allowlisted so its deps still
# resolve.  `urllib3` is intentionally NOT purged here (it is the poisoned dep).
purge_good_offline() {  # backs up to $OFFLINE_BACKUP then deletes
    python3 - "$OFFLINE_BACKUP" <<PYEOF
import json, sqlite3, sys
from agentshield.core.config import DEFAULT_DB_PATH
goods = [("$GOOD_PYPI","pypi"), ("$GOOD_NPM","npm"), ("$GOOD_CARGO","cargo"),
         ("$TRANS_PARENT","pypi")]
dump = {}
try:
    con = sqlite3.connect(str(DEFAULT_DB_PATH)); con.row_factory = sqlite3.Row
    for table in ("cve_mirror", "malicious_packages"):
        rows = []
        try:
            for pkg, eco in goods:
                cur = con.execute(
                    "SELECT * FROM %s WHERE lower(package)=? AND lower(ecosystem)=?" % table,
                    (pkg.lower(), eco.lower()))
                rows += [dict(r) for r in cur.fetchall()]
            for pkg, eco in goods:
                con.execute(
                    "DELETE FROM %s WHERE lower(package)=? AND lower(ecosystem)=?" % table,
                    (pkg.lower(), eco.lower()))
        except sqlite3.Error:
            pass
        dump[table] = rows
    con.commit(); con.close()
    open(sys.argv[1], "w").write(json.dumps(dump))
    print(sum(len(v) for v in dump.values()))
except Exception:
    print(0)
PYEOF
}
restore_good_offline() {
    [ -f "$OFFLINE_BACKUP" ] || return 0
    python3 - "$OFFLINE_BACKUP" <<PYEOF
import json, sqlite3, sys, os
from agentshield.core.config import DEFAULT_DB_PATH
try:
    dump = json.load(open(sys.argv[1]))
    con = sqlite3.connect(str(DEFAULT_DB_PATH))
    for table, rows in dump.items():
        for r in rows:
            cols = ",".join(r.keys()); qs = ",".join("?" for _ in r)
            try:
                con.execute("INSERT OR REPLACE INTO %s (%s) VALUES (%s)" % (table, cols, qs),
                            list(r.values()))
            except sqlite3.Error:
                pass
    con.commit(); con.close()
except Exception:
    pass
PYEOF
}

# ----------------------------------------------------------------------------
# Low-level observers
# ----------------------------------------------------------------------------
# guard-scan-cmd: exit 0 => ALLOW, non-zero => BLOCK.
# The leading `--` stops typer from eating command flags like -c/-r/-t with its
# own --config/-c option, so the real command is parsed faithfully.
guard_obs() {
    if agentshield guard-scan-cmd -- "$@" >"$TMP/guard.out" 2>&1; then
        echo ALLOW
    else
        echo BLOCK
    fi
}

classify_marker() {  # ALLOW if the fake downstream binary actually ran
    if printf '%s' "$1" | grep -q "$MARKER"; then echo ALLOW; else echo BLOCK; fi
}

# agentshield hook (Claude Code / Codex PreToolUse): reads a PreToolUse payload
# on stdin and emits permissionDecision JSON on stdout. BLOCK -> "deny"; the
# Claude Code warn path -> "ask"; ALLOW -> empty stdout (exit 0). We classify by
# the rendered decision. First arg may be "--agent codex" (passed straight on);
# the remaining args are the command the agent is "about to run".
hook_obs() {
    agent_opt=""
    case "$1" in
        --agent) agent_opt="--agent $2"; shift 2 ;;
    esac
    cmd="$*"
    payload=$(printf '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"%s"}}' "$cmd")
    # shellcheck disable=SC2086
    out=$(printf '%s' "$payload" | agentshield hook $agent_opt 2>/dev/null)
    if printf '%s' "$out" | grep -q '"permissionDecision": "deny"'; then
        echo BLOCK
    elif printf '%s' "$out" | grep -q '"permissionDecision": "ask"'; then
        echo WARN
    else
        echo ALLOW
    fi
}

# ----------------------------------------------------------------------------
# 0. Preconditions
# ----------------------------------------------------------------------------
head2 "0. Preconditions"
if ! command -v agentshield >/dev/null 2>&1; then
    say "${RED}FATAL: 'agentshield' is not on PATH inside this container.${RST}"
    say "Install it (pip install agentshield) and re-run."
    exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
    say "${RED}FATAL: python3 not found; cannot drive plugin/DB tests.${RST}"
    exit 2
fi
AGENTSHIELD_BIN=$(command -v agentshield); export AGENTSHIELD_BIN
DBPATH=$(python3 -c 'from agentshield.core.config import DEFAULT_DB_PATH; print(DEFAULT_DB_PATH)' 2>/dev/null)
say "agentshield binary : $AGENTSHIELD_BIN"
say "malicious DB path  : ${DBPATH:-<unknown>}"
say "offline mode       : AGENTSHIELD_OFFLINE=$AGENTSHIELD_OFFLINE"
HAVE_CC=no; for c in cc gcc clang; do command -v "$c" >/dev/null 2>&1 && HAVE_CC=yes && break; done
HAVE_BASH=no; command -v bash >/dev/null 2>&1 && HAVE_BASH=yes
say "C compiler present : $HAVE_CC      bash present: $HAVE_BASH"

# ----------------------------------------------------------------------------
# 1. Version / commit + optional reinstall-from-repo
# ----------------------------------------------------------------------------
head2 "1. Installed version / commit"
say "Reported version:"; agentshield --version 2>&1 | sed 's/^/    /'
PKG_VER=$(python3 -c 'from importlib.metadata import version; print(version("agentshield"))' 2>/dev/null || echo "unknown")
say "importlib.metadata version: $PKG_VER"

REPO=""
for p in "${AGENTSHIELD_REPO:-}" /work/AgentShield /AgentShield /root/AgentShield /src/AgentShield /app/AgentShield "$PWD" "$PWD/AgentShield"; do
    [ -n "$p" ] || continue
    if [ -f "$p/pyproject.toml" ] && grep -q 'name = "agentshield"' "$p/pyproject.toml" 2>/dev/null; then
        REPO=$p; break
    fi
done
if [ -n "$REPO" ]; then
    say "${CYN}Repo detected at: $REPO${RST}"
    if command -v git >/dev/null 2>&1 && [ -d "$REPO/.git" ]; then
        say "Repo commit: $(git -C "$REPO" rev-parse --short HEAD 2>/dev/null) on $(git -C "$REPO" rev-parse --abbrev-ref HEAD 2>/dev/null)"
    fi
    say "Attempting reinstall from repo (best-effort)…"
    if pip install -e "$REPO" >"$TMP/pipinstall.log" 2>&1 || pip install "$REPO" >>"$TMP/pipinstall.log" 2>&1; then
        say "${GRN}Reinstalled from repo.${RST} New version: $(agentshield --version 2>&1 | head -1)"
    else
        say "${YEL}Reinstall failed (see below); continuing with the currently-installed build.${RST}"
        tail -3 "$TMP/pipinstall.log" 2>/dev/null | sed 's/^/    /'
    fi
else
    say "${YEL}NOTE: AgentShield repo is not mounted/reachable in this container.${RST}"
    say "${YEL}      Skipping upgrade; testing the currently-installed build above.${RST}"
fi

# ----------------------------------------------------------------------------
# 2. Fresh, deterministic state
# ----------------------------------------------------------------------------
head2 "2. Setting up deterministic state"
agentshield cache clear >/dev/null 2>&1 && say "Cleared scan cache."
delete_sentinels; insert_sentinels && say "Inserted known-bad sentinel rows (pypi/npm/cargo)."
n_purged=$(purge_good_offline)
say "Neutralized offline CVE/malicious rows for GOOD pkgs (${n_purged:-0} backed up + removed; restored on exit)."
# Fake downstream package-manager binary used by the shim + execve tests.
mkdir -p "$FAKEBIN"
printf '#!/bin/sh\necho "%s $0 $*"\n' "$MARKER" > "$FAKEBIN/pip"
chmod +x "$FAKEBIN/pip"

# ============================================================================
# 3. Hermes plugin interception
# ============================================================================
head2 "3. Hermes plugin interception"
python3 - <<PYEOF > "$TMP/plugins.out" 2>&1
import asyncio
BAD="$BAD"; GOOD="$GOOD_PYPI"

# ---- Hermes plugin (real register(ctx) + pre_tool_call hook) ----
from agentshield.integrations.hermes import register
from agentshield.integrations.hermes.plugin import _HOOK_NAME, _SHELL_TOOLS, _TOOL_ECOSYSTEM

# Fake PluginContext mirroring the Hermes plugin loader.
class FakeCtx:
    def __init__(self): self.hooks = {}
    def register_hook(self, name, cb): self.hooks.setdefault(name, []).append(cb)

ctx = FakeCtx()
guard = register(ctx)
# Self-verify: the plugin must register the hook Hermes actually invokes.
registered = guard.registered and _HOOK_NAME == "pre_tool_call" and bool(ctx.hooks.get("pre_tool_call"))
print("HERMES_REGISTERED", "OK" if registered else "MISSING")
cb = ctx.hooks["pre_tool_call"][0]

def classify(res):
    # pre_tool_call returns {"action":"block",...} to veto, else None to allow.
    if isinstance(res, dict) and res.get("action") == "block":
        return "WARN" if "review" in res.get("message", "").lower() else "BLOCK"
    return "ALLOW"

async def shell(tool, cmd):
    return classify(cb(tool, {"command": cmd}, "task"))
async def structured(tool, pkg):
    return classify(cb(tool, {"package": pkg}, "task"))

async def hermes():
    # every shell tool name, including ones that previously bypassed interception
    for t in sorted(_SHELL_TOOLS):
        print("HERMES_SHELL_BAD", t, await shell(t, "pip install "+BAD))
        print("HERMES_SHELL_GOOD", t, await shell(t, "pip install "+GOOD))
    print("HERMES_STRUCT_BAD pip_install", await structured("pip_install", BAD))
    print("HERMES_STRUCT_GOOD pip_install", await structured("pip_install", GOOD))
    print("HERMES_STRUCT_BAD npm_install", await structured("npm_install", BAD))
    print("HERMES_STRUCT_BAD cargo_add",   await structured("cargo_add", BAD))
    # execute_code that drives a terminal install must also be caught
    print("HERMES_CODE_BAD", classify(cb("execute_code", {"code": "terminal('pip install "+BAD+"')"}, "task")))
    # arg-shape blind spot must FAIL CLOSED (the latent bug)
    print("HERMES_FAILCLOSED argkey", classify(cb("terminal", {"input": "pip install "+BAD+"'"}, "task")))
    # fail-closed inside the guard
    print("HERMES_FAILCLOSED gem",       await shell("terminal", "gem install foo"))
    print("HERMES_FAILCLOSED expansion", await shell("terminal", "pip install \$PKG"))

asyncio.run(hermes())
PYEOF

# Grade plugin results from the captured output
preg=$(grep -m1 '^HERMES_REGISTERED ' "$TMP/plugins.out" | awk '{print $2}')
grade "hermes self-verify registered" OK "${preg:-MISSING}" "register(ctx) wires pre_tool_call hook"
for t in bash execute run_command shell terminal; do
    grade "hermes shell BAD ($t)"  BLOCK "$(grep -m1 "^HERMES_SHELL_BAD $t " "$TMP/plugins.out" | awk '{print $NF}')" "pre_tool_call($t: pip install \$BAD)"
    grade "hermes shell GOOD ($t)" ALLOW "$(grep -m1 "^HERMES_SHELL_GOOD $t " "$TMP/plugins.out" | awk '{print $NF}')" "pre_tool_call($t: pip install $GOOD_PYPI)"
done
grade "hermes execute_code BAD"      BLOCK "$(grep -m1 '^HERMES_CODE_BAD ' "$TMP/plugins.out" | awk '{print $NF}')" "pre_tool_call(execute_code: terminal pip install \$BAD)"
grade "hermes fail-closed arg-key"   BLOCK "$(grep -m1 '^HERMES_FAILCLOSED argkey ' "$TMP/plugins.out" | awk '{print $NF}')" "terminal call with unreadable command key"
grade "hermes structured pip BAD"  BLOCK "$(grep -m1 '^HERMES_STRUCT_BAD pip_install ' "$TMP/plugins.out" | awk '{print $NF}')" "pip_install package=\$BAD"
grade "hermes structured pip GOOD" ALLOW "$(grep -m1 '^HERMES_STRUCT_GOOD pip_install ' "$TMP/plugins.out" | awk '{print $NF}')" "pip_install package=$GOOD_PYPI"
grade "hermes structured npm BAD"  BLOCK "$(grep -m1 '^HERMES_STRUCT_BAD npm_install ' "$TMP/plugins.out" | awk '{print $NF}')" "npm_install package=\$BAD"
grade "hermes structured cargo BAD" BLOCK "$(grep -m1 '^HERMES_STRUCT_BAD cargo_add ' "$TMP/plugins.out" | awk '{print $NF}')" "cargo_add package=\$BAD"
grade "hermes fail-closed gem"       BLOCK "$(grep -m1 '^HERMES_FAILCLOSED gem ' "$TMP/plugins.out" | awk '{print $NF}')" "bash: gem install foo"
grade "hermes fail-closed expansion" BLOCK "$(grep -m1 '^HERMES_FAILCLOSED expansion ' "$TMP/plugins.out" | awk '{print $NF}')" "bash: pip install \$PKG"
# OpenClaw is a TypeScript/Node plugin — see integrations/openclaw (node --test)
# and scripts/openclaw_realtest.sh; not exercised from this Python harness.

# ============================================================================
# 4. guard-scan-cmd across all 15 managers + absolute-path + `command`
# ============================================================================
head2 "4. guard-scan-cmd across all package managers"
# verifiable managers: BAD must BLOCK, GOOD must ALLOW
grade "guard pip BAD"             BLOCK "$(guard_obs pip install $BAD)"            "pip install \$BAD"
grade "guard pip GOOD"            ALLOW "$(guard_obs pip install $GOOD_PYPI)"      "pip install $GOOD_PYPI"
grade "guard pip3 BAD"            BLOCK "$(guard_obs pip3 install $BAD)"           "pip3 install \$BAD"
grade "guard python -m pip BAD"   BLOCK "$(guard_obs python -m pip install $BAD)"  "python -m pip install \$BAD"
grade "guard python -m pip GOOD"  ALLOW "$(guard_obs python3 -m pip install $GOOD_PYPI)" "python3 -m pip install $GOOD_PYPI"
grade "guard uv pip BAD"          BLOCK "$(guard_obs uv pip install $BAD)"         "uv pip install \$BAD"
grade "guard uv pip GOOD"         ALLOW "$(guard_obs uv pip install $GOOD_PYPI)"   "uv pip install $GOOD_PYPI"
grade "guard uv add BAD"          BLOCK "$(guard_obs uv add $BAD)"                 "uv add \$BAD"
grade "guard pipx BAD"            BLOCK "$(guard_obs pipx install $BAD)"           "pipx install \$BAD"
grade "guard poetry BAD"          BLOCK "$(guard_obs poetry add $BAD)"             "poetry add \$BAD"
grade "guard poetry GOOD"         ALLOW "$(guard_obs poetry add $GOOD_PYPI)"       "poetry add $GOOD_PYPI"
grade "guard npm BAD"             BLOCK "$(guard_obs npm install $BAD)"            "npm install \$BAD"
grade "guard npm GOOD"            ALLOW "$(guard_obs npm i $GOOD_NPM)"             "npm i $GOOD_NPM"
grade "guard yarn BAD"            BLOCK "$(guard_obs yarn add $BAD)"               "yarn add \$BAD"
grade "guard pnpm BAD"            BLOCK "$(guard_obs pnpm add $BAD)"               "pnpm add \$BAD"
grade "guard pnpm GOOD"           ALLOW "$(guard_obs pnpm add $GOOD_NPM)"          "pnpm add $GOOD_NPM"
grade "guard bun BAD"             BLOCK "$(guard_obs bun add $BAD)"                "bun add \$BAD"
grade "guard cargo BAD"           BLOCK "$(guard_obs cargo add $BAD)"              "cargo add \$BAD"
grade "guard cargo GOOD"          ALLOW "$(guard_obs cargo install $GOOD_CARGO)"   "cargo install $GOOD_CARGO"
# unverifiable managers (no scan backend) MUST fail closed -> BLOCK
grade "guard gem (unverifiable)"  BLOCK "$(guard_obs gem install foo)"             "gem install foo"
grade "guard go (unverifiable)"   BLOCK "$(guard_obs go install example.com/x@latest)" "go install example.com/x"
# path-qualified + `command` wrappers
grade "guard absolute-path pip BAD" BLOCK "$(guard_obs /usr/bin/pip install $BAD)" "/usr/bin/pip install \$BAD"
grade "guard 'command pip' BAD"     BLOCK "$(guard_obs command pip install $BAD)"  "command pip install \$BAD"

# ============================================================================
# 5. conda trusted vs untrusted channel
# ============================================================================
head2 "5. conda channel trust"
grade "conda default-channel GOOD"   ALLOW "$(guard_obs conda install $GOOD_PYPI)"                  "conda install $GOOD_PYPI"
grade "conda trusted-channel GOOD"   ALLOW "$(guard_obs conda install -c conda-forge $GOOD_PYPI)"   "conda install -c conda-forge $GOOD_PYPI"
grade "conda trusted-channel BAD"    BLOCK "$(guard_obs conda install -c conda-forge $BAD)"         "conda install -c conda-forge \$BAD"
grade "conda untrusted -c channel"   BLOCK "$(guard_obs conda install -c sketchy-chan somepkg)"     "conda install -c sketchy-chan somepkg"
grade "conda untrusted chan::pkg"    BLOCK "$(guard_obs conda install evilchan::somepkg)"           "conda install evilchan::somepkg"

# ============================================================================
# 6. general fail-closed (unverifiable + unanalyzable args)
# ============================================================================
head2 "6. general fail-closed"
grade "fail-closed shell-expansion"  BLOCK "$(guard_obs pip install \$PKG)"                  "pip install \$PKG"
grade "fail-closed VCS url"          BLOCK "$(guard_obs pip install git+https://x/y.git)"    "pip install git+https://x/y.git"
grade "fail-closed remote -r file"   BLOCK "$(guard_obs pip install -r https://x/req.txt)"   "pip install -r https://x/req.txt"

# ============================================================================
# 6b. Claude Code / Codex PreToolUse hook (agentshield hook)
# ============================================================================
head2 "6b. Claude Code / Codex PreToolUse hook"
# Claude Code dialect (default): BAD -> deny(BLOCK), GOOD -> empty(ALLOW)
grade "hook pip BAD"            BLOCK "$(hook_obs pip install $BAD)"          "hook: pip install \$BAD"
grade "hook pip GOOD"          ALLOW "$(hook_obs pip install $GOOD_PYPI)"    "hook: pip install $GOOD_PYPI"
grade "hook npm BAD"           BLOCK "$(hook_obs npm install $BAD)"          "hook: npm install \$BAD"
grade "hook cargo GOOD"        ALLOW "$(hook_obs cargo install $GOOD_CARGO)" "hook: cargo install $GOOD_CARGO"
grade "hook no-install"        ALLOW "$(hook_obs ls -la /tmp)"              "hook: ls -la /tmp"
# fail-closed: unverifiable manager + unanalyzable arg must deny(BLOCK)
grade "hook gem (unverifiable)" BLOCK "$(hook_obs gem install foo)"          "hook: gem install foo"
grade "hook shell-expansion"   BLOCK "$(hook_obs pip install \$PKG)"         "hook: pip install \$PKG"
# Codex dialect: same deny on BAD (codex_hooks accepts the same shape)
grade "hook codex pip BAD"     BLOCK "$(hook_obs --agent codex pip install $BAD)" "hook --agent codex: pip install \$BAD"
grade "hook codex GOOD"        ALLOW "$(hook_obs --agent codex pip install $GOOD_PYPI)" "hook --agent codex: pip install $GOOD_PYPI"
# malformed payload must NOT block (fail-closed applies to detected installs only)
mal=$(printf 'not valid json' | agentshield hook 2>/dev/null)
if printf '%s' "$mal" | grep -q 'permissionDecision'; then
    grade "hook malformed payload" ALLOW BLOCK "hook: <malformed stdin>"
else
    grade "hook malformed payload" ALLOW ALLOW "hook: <malformed stdin>"
fi

# ============================================================================
# 7. PATH shim baseline
# ============================================================================
head2 "7. PATH shim baseline"
rm -rf "$SHIMDIR"
if agentshield shim install --dir "$SHIMDIR" >"$TMP/shim.out" 2>&1; then
    # registration check: wrappers exist for the managed binaries and call the scanner
    if [ -f "$SHIMDIR/pip" ] && grep -q 'guard-scan-cmd' "$SHIMDIR/pip"; then
        grade "shim wrappers installed" OK OK "shim install --dir $SHIMDIR"
    else
        grade "shim wrappers installed" OK MISSING "shim install --dir $SHIMDIR"
    fi
    if [ "$HAVE_BASH" = yes ]; then
        # functional: shim dir first, fake downstream pip after it
        out=$(PATH="$SHIMDIR:$FAKEBIN:$PATH" AGENTSHIELD_BIN="$AGENTSHIELD_BIN" pip install "$BAD" 2>&1)
        grade "shim blocks BAD"  BLOCK "$(classify_marker "$out")" "PATH=shim pip install \$BAD"
        out=$(PATH="$SHIMDIR:$FAKEBIN:$PATH" AGENTSHIELD_BIN="$AGENTSHIELD_BIN" pip install "$GOOD_PYPI" 2>&1)
        grade "shim allows GOOD" ALLOW "$(classify_marker "$out")" "PATH=shim pip install $GOOD_PYPI"
    else
        skip "shim blocks BAD"  BLOCK "bash absent (wrappers are #!/usr/bin/env bash)"
        skip "shim allows GOOD" ALLOW "bash absent"
    fi
    agentshield shim uninstall --dir "$SHIMDIR" >/dev/null 2>&1
else
    skip "shim wrappers installed" OK "shim install failed"
    skip "shim blocks BAD"  BLOCK "shim install failed"
    skip "shim allows GOOD" ALLOW "shim install failed"
fi

# ============================================================================
# 8. execve interceptor (LD_PRELOAD): absolute-path / `command` / subprocess
# ============================================================================
head2 "8. execve LD_PRELOAD interceptor"
EXEC_READY=no
if [ "$HAVE_CC" = yes ]; then
    if agentshield enforce-build -o "$LIB" >"$TMP/build.out" 2>&1 && [ -f "$LIB" ]; then
        EXEC_READY=yes
    else
        say "${YEL}enforce-build failed:${RST}"; tail -3 "$TMP/build.out" | sed 's/^/    /'
    fi
fi
if [ "$EXEC_READY" = yes ]; then
    # the interceptor must live in the CALLING process, so drive each case via sh -c
    run_preload() {  # $1 = shell command that execs a managed binary
        out=$(LD_PRELOAD="$LIB" AGENTSHIELD_BIN="$AGENTSHIELD_BIN" \
              PATH="$FAKEBIN:$PATH" sh -c "$1" 2>&1)
        classify_marker "$out"
    }
    grade "execve absolute-path BAD"  BLOCK "$(run_preload "$FAKEBIN/pip install $BAD")"      "LD_PRELOAD sh -c '$FAKEBIN/pip install \$BAD'"
    grade "execve absolute-path GOOD" ALLOW "$(run_preload "$FAKEBIN/pip install $GOOD_PYPI")" "LD_PRELOAD sh -c '$FAKEBIN/pip install $GOOD_PYPI'"
    grade "execve 'command pip' BAD"  BLOCK "$(run_preload "command pip install $BAD")"        "LD_PRELOAD sh -c 'command pip install \$BAD'"
    grade "execve bare-PATH BAD"      BLOCK "$(run_preload "pip install $BAD")"                "LD_PRELOAD sh -c 'pip install \$BAD'"
    # subprocess via python (avoid quoting hell by using a temp script)
    printf 'import subprocess,sys\nsys.exit(subprocess.call(["pip","install","%s"]))\n' "$BAD" > "$TMP/sub_bad.py"
    printf 'import subprocess,sys\nsys.exit(subprocess.call(["pip","install","%s"]))\n' "$GOOD_PYPI" > "$TMP/sub_good.py"
    grade "execve subprocess BAD"     BLOCK "$(run_preload "python3 $TMP/sub_bad.py")"   "LD_PRELOAD python3 subprocess pip install \$BAD"
    grade "execve subprocess GOOD"    ALLOW "$(run_preload "python3 $TMP/sub_good.py")"  "LD_PRELOAD python3 subprocess pip install $GOOD_PYPI"
else
    for t in "execve absolute-path BAD:BLOCK" "execve absolute-path GOOD:ALLOW" \
             "execve 'command pip' BAD:BLOCK" "execve bare-PATH BAD:BLOCK" \
             "execve subprocess BAD:BLOCK" "execve subprocess GOOD:ALLOW"; do
        skip "${t%:*}" "${t#*:}" "no C compiler / build failed"
    done
fi

# ============================================================================
# 9. index proxy: env injection + block/allow + transitive-dependency block
# ============================================================================
head2 "9. index proxy"
# 9a. env injection
penv=$(agentshield proxy --print-env 2>/dev/null)
if printf '%s' "$penv" | grep -q 'PIP_INDEX_URL' && \
   printf '%s' "$penv" | grep -q 'UV_INDEX_URL' && \
   printf '%s' "$penv" | grep -q 'npm_config_registry'; then
    grade "proxy env injection" OK OK "agentshield proxy --print-env"
else
    grade "proxy env injection" OK MISSING "agentshield proxy --print-env"
fi

# helper: classify a proxy response (no redirect-follow)
proxy_class() {
    python3 - "$1" <<'PYEOF'
import sys, urllib.request, urllib.error
class NR(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None
op = urllib.request.build_opener(NR)
try:
    r = op.open(urllib.request.Request(sys.argv[1]), timeout=25)
    print("ALLOW" if r.status in (301,302,303,307,308) else "HTTP%d" % r.status)
except urllib.error.HTTPError as e:
    # Some Python versions raise (rather than return) when redirects aren't
    # followed. A 3xx from the proxy is the ALLOW signal (redirect to upstream).
    if e.code in (301,302,303,307,308):
        print("ALLOW")
    elif e.code == 403:
        try: body = e.read().decode("utf-8","replace")
        except Exception: body = ""
        print("BLOCK-TRANSITIVE" if "transitive dependency" in body else "BLOCK")
    else:
        print("HTTP%d" % e.code)
except Exception:
    print("ERR")
PYEOF
}
wait_port() {  # host port -> 0 when accepting connections
    i=0
    while [ "$i" -lt 40 ]; do
        if python3 - "$1" "$2" <<'PYEOF' 2>/dev/null
import socket, sys
s = socket.socket(); s.settimeout(0.5)
try:
    s.connect((sys.argv[1], int(sys.argv[2]))); s.close()
except Exception:
    sys.exit(1)
PYEOF
        then
            return 0
        fi
        i=$((i+1)); sleep 0.25
    done
    return 1
}

# 9b. direct block/allow (run with --no-transitive so no network resolution)
P1=8799
agentshield proxy --host 127.0.0.1 --port "$P1" --no-transitive >"$TMP/proxy1.log" 2>&1 &
PROXY_PIDS="$PROXY_PIDS $!"
if wait_port 127.0.0.1 "$P1"; then
    grade "proxy pypi BAD"  BLOCK "$(proxy_class "http://127.0.0.1:$P1/simple/$BAD/")"      "GET /simple/\$BAD/"
    grade "proxy pypi GOOD" ALLOW "$(proxy_class "http://127.0.0.1:$P1/simple/$GOOD_PYPI/")" "GET /simple/$GOOD_PYPI/"
    grade "proxy npm BAD"   BLOCK "$(proxy_class "http://127.0.0.1:$P1/npm/$BAD")"           "GET /npm/\$BAD"
    grade "proxy npm GOOD"  ALLOW "$(proxy_class "http://127.0.0.1:$P1/npm/$GOOD_NPM")"      "GET /npm/$GOOD_NPM"
else
    say "${YEL}proxy (direct) did not come up:${RST}"; tail -3 "$TMP/proxy1.log" | sed 's/^/    /'
    for t in "proxy pypi BAD:BLOCK" "proxy pypi GOOD:ALLOW" "proxy npm BAD:BLOCK" "proxy npm GOOD:ALLOW"; do
        skip "${t%:*}" "${t#*:}" "proxy did not start"
    done
fi

# 9c. transitive-dependency block (needs network for dependency resolution)
NET_OK=no
python3 -c "import urllib.request as u; u.urlopen('https://pypi.org/pypi/$TRANS_PARENT/json',timeout=8)" >/dev/null 2>&1 && NET_OK=yes
if [ "$NET_OK" = yes ]; then
    insert_sentinels "$TRANS_DEP@@pypi"          # poison a REAL dep of requests
    agentshield cache clear >/dev/null 2>&1
    P2=8800
    agentshield proxy --host 127.0.0.1 --port "$P2" >"$TMP/proxy2.log" 2>&1 &
    PROXY_PIDS="$PROXY_PIDS $!"
    if wait_port 127.0.0.1 "$P2"; then
        # requesting the clean parent must be blocked because a resolved dep is bad
        grade "proxy transitive-dep block" BLOCK-TRANSITIVE \
              "$(proxy_class "http://127.0.0.1:$P2/simple/$TRANS_PARENT/")" \
              "GET /simple/$TRANS_PARENT/ (dep $TRANS_DEP poisoned)"
    else
        skip "proxy transitive-dep block" BLOCK-TRANSITIVE "proxy did not start"
    fi
    delete_sentinels; insert_sentinels   # drop urllib3 poison, keep base sentinels
else
    skip "proxy transitive-dep block" BLOCK-TRANSITIVE "pypi.org unreachable (dependency resolution needs network)"
fi

# ============================================================================
# 10. posture scan
# ============================================================================
head2 "10. posture scan"
if agentshield posture --skip-packages --tools bash,pip_install,read_file >"$TMP/posture.out" 2>&1; then
    if grep -qi 'posture' "$TMP/posture.out"; then
        grade "posture report" OK OK "posture --skip-packages --tools bash,pip_install,read_file"
    else
        grade "posture report" OK NO_OUTPUT "posture --skip-packages --tools ..."
    fi
else
    grade "posture report" OK FAILED "posture --skip-packages --tools ..."
fi

# ============================================================================
# Final report
# ============================================================================
head2 "RESULT TABLE"
printf '%s%-6s %-40s %-15s %-15s%s\n' "$BLD" "STATUS" "FEATURE" "EXPECTED" "OBSERVED" "$RST"
hr
while IFS="$(printf '\t')" read -r st ft ex ob cmd; do
    case $st in PASS) c=$GRN;; FAIL) c=$RED;; SKIP) c=$YEL;; *) c=$RST;; esac
    printf '%s%-6s%s %-40s %-15s %-15s\n' "$c" "$st" "$RST" "$ft" "$ex" "$ob"
done < "$RESULTS"
hr

if [ "$P_FAIL" -gt 0 ]; then
    say ""
    say "${RED}${BLD}!!! FAILURES (${P_FAIL}) !!!${RST}"
    while IFS="$(printf '\t')" read -r st ft ex ob cmd; do
        [ "$st" = FAIL ] || continue
        printf '  %sFAIL%s %-40s expected=%-12s got=%-12s\n        cmd: %s\n' "$RED" "$RST" "$ft" "$ex" "$ob" "$cmd"
    done < "$RESULTS"
fi

TOTAL=$((P_PASS + P_FAIL))
say ""
if [ "$P_FAIL" -eq 0 ]; then
    say "${GRN}${BLD}SUMMARY: $P_PASS/$TOTAL passed, $P_SKIP skipped — ALL GRADED CHECKS PASSED.${RST}"
else
    say "${RED}${BLD}SUMMARY: $P_PASS/$TOTAL passed, $P_FAIL FAILED, $P_SKIP skipped.${RST}"
fi
say "(skips are environment-gated: missing C compiler, missing bash, or no network)"

# exit non-zero if anything failed, so callers/CI can detect it
[ "$P_FAIL" -eq 0 ]
