// AgentShield × OpenClaw — pure decision logic (SDK-agnostic, unit-testable).
//
// This module has NO dependency on the OpenClaw SDK so it can be unit-tested
// with `node --test` offline. The plugin entry (index.mjs) imports it and wires
// it to the real `before_tool_call` hook.
//
// Verdicts come from the AgentShield CLI — the single source of truth for
// scanning — via `agentshield hook --agent openclaw`, which prints OpenClaw's
// exact block shape `{ "block": true, "blockReason": "..." }` on stdout (and
// nothing for allow). We never reimplement scanning here.

import { spawnSync } from "node:child_process";

/** The OpenClaw hook this plugin enforces on (must be one OpenClaw dispatches). */
export const HOOK_NAME = "before_tool_call";

/** OpenClaw tool names that carry a shell command we should scan. `exec` is the
 *  real OpenClaw shell tool (param `command`); the rest cover aliases/variants. */
export const EXEC_TOOL_NAMES = new Set(["exec", "shell", "bash", "terminal", "run_command"]);

/** Argument keys an exec-style tool may carry the command under. */
const COMMAND_KEYS = ["command", "cmd", "script"];

/** Cheap pre-check: does this command plausibly install a package? Used only to
 *  decide whether a missing/erroring CLI should fail closed. The authoritative
 *  parse happens in the AgentShield CLI. */
const INSTALL_RE =
  /\b(pip3?|pipx|uv|poetry|conda|npm|yarn|pnpm|bun|cargo|gem|go|apt|apt-get|brew)\b[^\n;|&]*\b(install|add|i)\b/i;

/** Extract the command string from an exec tool's params, or null. */
export function extractCommand(params) {
  if (!params || typeof params !== "object") return null;
  for (const key of COMMAND_KEYS) {
    const v = params[key];
    if (typeof v === "string") return v;
  }
  return null;
}

/**
 * Decide whether an OpenClaw tool call should be blocked.
 *
 * @param {string} toolName
 * @param {Record<string, unknown>} params
 * @param {(command: string) => {status: number|null, stdout: string, stderr: string, error?: Error}} runner
 *        Invokes the AgentShield CLI for a command; defaults to the real CLI.
 * @returns {{block: true, blockReason: string} | null}  null = allow.
 */
export function evaluateToolCall(toolName, params, runner = runAgentShield) {
  // Not an exec-style tool → not our concern.
  if (!EXEC_TOOL_NAMES.has(toolName)) return null;

  const command = extractCommand(params);
  if (command === null || command.trim() === "") {
    // Nothing runnable to scan (exec with no command is a no-op/error).
    return null;
  }

  let res;
  try {
    res = runner(command);
  } catch (err) {
    // Runner blew up. Fail closed only if the command looks like an install we
    // could not verify; otherwise don't wedge every shell command.
    return INSTALL_RE.test(command)
      ? block(`AgentShield could not run its scanner (${String(err)}); blocking unverified install to fail closed.`)
      : null;
  }

  if (res && res.error) {
    return INSTALL_RE.test(command)
      ? block(`AgentShield CLI unavailable (${String(res.error)}); blocking unverified install to fail closed.`)
      : null;
  }

  const out = ((res && res.stdout) || "").trim();
  if (out) {
    // The CLI emitted a decision. It uses OpenClaw's shape: `{block:true,...}`
    // for a block, empty for allow.
    try {
      const parsed = JSON.parse(out);
      if (parsed && parsed.block === true) {
        return block(
          typeof parsed.blockReason === "string" && parsed.blockReason
            ? parsed.blockReason
            : "AgentShield blocked this command.",
        );
      }
      // Explicit non-block JSON → allow.
      return null;
    } catch {
      // Non-JSON stdout: fall through to the exit-status handling below.
    }
  }

  // `agentshield hook` ALWAYS exits 0 with the decision in stdout (empty=allow,
  // JSON=block). A NON-zero exit therefore means the CLI itself failed — not a
  // block verdict. Fail closed only for commands that look like installs, so a
  // scanner crash never wedges innocuous commands like `ls`.
  if (res && typeof res.status === "number" && res.status !== 0) {
    if (INSTALL_RE.test(command)) {
      const detail = out || (res.stderr || "").trim();
      return block(
        `AgentShield scanner failed (exit ${res.status}${detail ? `: ${detail.slice(0, 120)}` : ""}); blocking unverified install to fail closed.`,
      );
    }
    return null;
  }

  // Exit 0 and no block payload → allow.
  return null;
}

function block(blockReason) {
  return { block: true, blockReason };
}

/** Default runner: invoke `agentshield hook --agent openclaw` with a PreToolUse
 *  payload on stdin. Override in tests. */
export function runAgentShield(command) {
  const bin = process.env.AGENTSHIELD_BIN || "agentshield";
  const payload = JSON.stringify({ tool_input: { command } });
  const res = spawnSync(bin, ["hook", "--agent", "openclaw"], {
    input: payload,
    encoding: "utf8",
    timeout: 60_000,
  });
  return {
    status: res.status,
    stdout: res.stdout || "",
    stderr: res.stderr || "",
    error: res.error,
  };
}
