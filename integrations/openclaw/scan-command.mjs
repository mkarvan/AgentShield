// AgentShield × OpenClaw — pure decision logic (SDK-agnostic, unit-testable).
//
// This module has NO dependency on the OpenClaw SDK so it can be unit-tested
// with `node --test` offline. The plugin entry (index.mjs) imports it and wires
// it to the real `before_tool_call` hook.
//
// Verdicts come from the AgentShield CLI — the single source of truth for
// scanning — via `agentshield guard-scan-cmd <command tokens>`:
//   * exit 0, no "flagged for review" text  -> ALLOW
//   * exit 1                                -> BLOCK (reason printed on stdout)
//   * exit 0 with "flagged for review"      -> warn -> BLOCK (fail closed)
//   * any other exit / spawn error          -> CLI failure -> fail closed for
//                                              install-looking commands only
// `guard-scan-cmd` is the same backend the `agentshield guard` shell uses; it is
// present in shipped 0.9.0 builds and takes the command as argv TOKENS (it
// re-joins and parses them), so we must tokenize — passing the whole command as
// one argument hides the install from the parser (fail-open). We never
// reimplement scanning here.

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
 * Tokenize a shell command into argv for `guard-scan-cmd`.
 *
 * A minimal POSIX-ish splitter: whitespace-separated, honoring single and
 * double quotes (quotes stripped). Operators written with surrounding spaces
 * (`&&`, `;`, `|`) naturally become their own tokens, which `guard-scan-cmd`
 * understands. This covers the commands an agent actually emits; the agnostic
 * `agentshield guard` / shim layers remain the backstop for pathological input.
 *
 * @param {string} command
 * @returns {string[]}
 */
export function tokenize(command) {
  const tokens = [];
  let cur = "";
  let quote = null;
  let has = false;
  for (let i = 0; i < command.length; i++) {
    const c = command[i];
    if (quote) {
      if (c === quote) quote = null;
      else cur += c;
    } else if (c === '"' || c === "'") {
      quote = c;
      has = true;
    } else if (c === " " || c === "\t" || c === "\n") {
      if (has) {
        tokens.push(cur);
        cur = "";
        has = false;
      }
    } else {
      cur += c;
      has = true;
    }
  }
  if (has) tokens.push(cur);
  return tokens;
}

/**
 * Decide whether an OpenClaw tool call should be blocked.
 *
 * @param {string} toolName
 * @param {Record<string, unknown>} params
 * @param {(tokens: string[]) => {status: number|null, stdout: string, stderr: string, error?: Error}} runner
 *        Invokes the AgentShield CLI for command tokens; defaults to the real CLI.
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

  const tokens = tokenize(command);
  if (tokens.length === 0) return null;

  let res;
  try {
    res = runner(tokens);
  } catch (err) {
    return failClosedIfInstall(command, `AgentShield could not run its scanner (${String(err)})`);
  }

  if (res && res.error) {
    return failClosedIfInstall(command, `AgentShield CLI unavailable (${String(res.error)})`);
  }

  const stdout = ((res && res.stdout) || "").trim();
  const stderr = ((res && res.stderr) || "").trim();
  const status = res ? res.status : null;

  // BLOCK: guard-scan-cmd exits 1 and prints the blocked item(s) on stdout.
  if (status === 1) {
    return block(cleanReason(stdout) || "AgentShield blocked this command.");
  }

  // WARN → fail closed: guard-scan-cmd exits 0 but prints "flagged for review".
  if (status === 0 && /flagged for review/i.test(stdout)) {
    return block(
      cleanReason(stdout) || "AgentShield flagged this command for review; blocking to fail closed.",
    );
  }

  // Clean allow.
  if (status === 0) return null;

  // Any other exit code (e.g. 2 = CLI usage error / wrong build) means the CLI
  // could not give a verdict. Fail closed only for install-looking commands so a
  // CLI problem never wedges innocuous commands like `ls`.
  return failClosedIfInstall(
    command,
    `AgentShield scanner returned exit ${status}${stderr ? `: ${stderr.slice(0, 120)}` : ""}`,
  );
}

function failClosedIfInstall(command, why) {
  return INSTALL_RE.test(command)
    ? block(`${why}; blocking unverified install to fail closed.`)
    : null;
}

/** Strip guard-scan-cmd's heading and bullet markup into a compact reason. */
function cleanReason(stdout) {
  return stdout
    .split("\n")
    .map((l) => l.replace(/^\s*[•*-]\s*/, "").trim())
    .filter((l) => l && !/^AgentShield (BLOCKED|WARNING|: )/i.test(l) && !/^AgentShield:/i.test(l))
    .join("; ")
    .trim();
}

function block(blockReason) {
  return { block: true, blockReason };
}

/** Default runner: invoke `agentshield guard-scan-cmd <tokens>`. Override in tests. */
export function runAgentShield(tokens) {
  const bin = process.env.AGENTSHIELD_BIN || "agentshield";
  const res = spawnSync(bin, ["guard-scan-cmd", ...tokens], {
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
