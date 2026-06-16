# AgentShield — OpenClaw plugin

OpenClaw is a **TypeScript/Node** agent framework. This is its AgentShield
integration: a real OpenClaw plugin that registers a `before_tool_call` hook on
the `exec` tool and blocks unsafe package installs before they run.

It is intentionally **not** a Python module — OpenClaw cannot load Python
classes, which is why the previous `module:`/`class:` "skill" registration never
fired. Scanning is delegated to the `agentshield` CLI (the single source of
truth shared with the Hermes and Claude Code / Codex integrations).

## How it works

1. OpenClaw loads this plugin (manifest `openclaw.plugin.json`) and calls
   `register(api)` in `index.mjs`.
2. `register` wires `api.on("before_tool_call", handler, { priority: 100 })`.
3. On each `exec` tool call, the handler reads `event.params.command`, runs
   `agentshield hook --agent openclaw` with a PreToolUse payload, and returns
   OpenClaw's `{ block: true, blockReason }` when AgentShield blocks (terminal;
   `exec` never runs). `NEEDS_CONFIRMATION` fails closed to a block (OpenClaw
   hooks have no "ask" path).
4. The handler **never throws** (a thrown hook would let the tool run). A
   missing/erroring scanner fails closed for install-looking commands and lets
   innocuous commands (e.g. `ls`) through.

The decision logic lives in `scan-command.mjs` with **no** OpenClaw SDK
dependency, so it is unit-testable offline.

## Install

```bash
# AgentShield CLI must be on PATH in the OpenClaw box (or set AGENTSHIELD_BIN):
pipx install agentshield

# Then install the plugin into OpenClaw:
openclaw plugins install @agentshield/openclaw-plugin
# or from a checkout:
openclaw plugins install ./integrations/openclaw
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
