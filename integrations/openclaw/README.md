# AgentShield — OpenClaw plugin

OpenClaw is a **TypeScript/Node** agent framework. This is its AgentShield
integration: a real OpenClaw plugin that registers a `before_tool_call` hook on
the `exec` tool and blocks unsafe package installs before they run.

It is intentionally **not** a Python module — OpenClaw cannot load Python
classes, which is why the previous `module:`/`class:` "skill" registration never
fired. Scanning is delegated to the `agentshield` CLI (the single source of
truth shared with the Hermes and Claude Code / Codex integrations).

## How it works

1. OpenClaw loads this plugin via its **required** `openclaw.plugin.json`
   manifest (which includes a `configSchema` — OpenClaw refuses a manifest
   without one) and the entry point declared in `package.json`'s
   `openclaw.extensions`, then calls `register(api)` in `index.mjs`.
2. `register` wires `api.on("before_tool_call", handler, { priority: 100 })`.
3. On each `exec` tool call, the handler reads `event.params.command`, tokenizes
   it, and runs `agentshield guard-scan-cmd <tokens>` (exit 1 = block, exit 0 =
   allow; a "flagged for review" warn also blocks). On a block it returns
   OpenClaw's `{ block: true, blockReason }` (terminal; `exec` never runs).
   `NEEDS_CONFIRMATION` fails closed to a block (OpenClaw hooks have no "ask").
4. The handler **never throws** (a thrown hook would let the tool run). A
   missing/erroring scanner fails closed for install-looking commands and lets
   innocuous commands (e.g. `ls`) through.

> The command is passed to `guard-scan-cmd` as argv **tokens**, not as one
> string — `guard-scan-cmd` re-joins and parses tokens, so a single-string
> argument would hide the install from the parser.

The decision logic lives in `scan-command.mjs` with **no** OpenClaw SDK
dependency, so it is unit-testable offline.

## Install

```bash
# AgentShield CLI must be on PATH in the OpenClaw box (or set AGENTSHIELD_BIN):
pipx install agentshield

# Then install the plugin into OpenClaw — as ROOT (OpenClaw rejects
# non-root-owned plugin files):
openclaw plugins install @agentshield/openclaw-plugin
# or from a checkout (chown to root first):
sudo chown -R root:root ./integrations/openclaw
openclaw plugins install ./integrations/openclaw
# clear a prior broken install if needed:
#   openclaw plugins remove agentshield
```

## Test

```bash
# Unit tests (pure logic, offline, Node >= 22):
node --test

# Real-instance test (drives the registered hook + the real CLI):
../../scripts/openclaw_realtest.sh
```

## Config

Override the CLI path if `agentshield` is not on PATH:

```bash
export AGENTSHIELD_BIN=/absolute/path/to/agentshield
```

AgentShield's own policy (denylist/allowlist, severities) lives in
`~/.config/agentshield/config.toml` as usual.
