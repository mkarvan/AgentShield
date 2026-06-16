// AgentShield — OpenClaw plugin entry.
//
// Registers a `before_tool_call` hook that scans package installs the agent is
// about to run through the `exec` tool, and blocks unsafe ones. Verdicts come
// from the AgentShield CLI (see scan-command.mjs) — the single scanning source
// of truth shared with the Hermes plugin and the Claude Code / Codex hook.
//
// Install (into the OpenClaw box):
//   openclaw plugins install @agentshield/openclaw-plugin
//   # or, in-repo: place/symlink this dir under OpenClaw's extensions/
// AgentShield's CLI must be on PATH (pipx install agentshield, or set
// AGENTSHIELD_BIN to its absolute path).

import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";

import { EXEC_TOOL_NAMES, HOOK_NAME, evaluateToolCall } from "./scan-command.mjs";

export default definePluginEntry({
  id: "agentshield",
  name: "AgentShield",
  description:
    "Scans package installs (pip/npm/cargo/...) before the exec tool runs them; blocks unsafe ones. Fail-closed.",
  register(api) {
    if (typeof api?.on !== "function") {
      // Self-verify: surface loudly if wired into a host without the hook API,
      // rather than silently no-op'ing (the failure mode we set out to fix).
      // eslint-disable-next-line no-console
      console.error(
        "[AgentShield] host has no api.on(); the before_tool_call guard is NOT active.",
      );
      return;
    }

    api.on(
      HOOK_NAME,
      async (event) => {
        const toolName = event?.toolName;
        if (!EXEC_TOOL_NAMES.has(toolName)) return;
        const decision = evaluateToolCall(toolName, event?.params ?? {});
        if (decision) return decision; // { block: true, blockReason }
        return; // allow
      },
      { priority: 100 },
    );

    // eslint-disable-next-line no-console
    console.info(
      `[AgentShield] registered '${HOOK_NAME}' guard for tools: ${[...EXEC_TOOL_NAMES].join(", ")}`,
    );
  },
});
