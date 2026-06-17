// Unit tests for the AgentShield OpenClaw plugin decision logic.
// Run: node --test  (Node >= 22). No network, no OpenClaw runtime needed —
// the AgentShield CLI is replaced by a fake runner that mimics
// `agentshield guard-scan-cmd` (exit 1 = BLOCK, exit 0 = allow / warn-only
// LOG_ASYNC, exit 0 + "flagged for review" = residual warn, exit 2 =
// NEEDS_CONFIRMATION fail-closed or CLI usage error).

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  EXEC_TOOL_NAMES,
  HOOK_NAME,
  evaluateToolCall,
  extractCommand,
  tokenize,
} from "./scan-command.mjs";

// Fake runners standing in for `agentshield guard-scan-cmd <tokens>`.
const blockRunner =
  (item = "evilpkg", reason = "Package 'evilpkg' is on the denylist") =>
  () => ({ status: 1, stdout: `AgentShield BLOCKED 1 item(s):\n  • ${item}: ${reason}`, stderr: "" });
const allowRunner = () => ({ status: 0, stdout: "", stderr: "" });
const warnRunner = () => ({
  status: 0,
  stdout: "AgentShield: 1 item(s) flagged for review\n  • sus: HIGH CVE",
  stderr: "",
});
const usageErrorRunner = () => ({
  status: 2,
  stdout: "",
  stderr: "Usage: agentshield [OPTIONS] COMMAND [ARGS]...",
});
const throwingRunner = () => {
  throw new Error("ENOENT: agentshield not found");
};
const spawnErrorRunner = () => ({ status: null, stdout: "", stderr: "", error: new Error("spawn failed") });

// ── contract guard: fail if wired to something OpenClaw never calls ──────────

test("hook name is one OpenClaw actually dispatches", () => {
  const REAL_OPENCLAW_HOOKS = new Set([
    "before_model_resolve",
    "before_prompt_build",
    "before_agent_start",
    "before_agent_reply",
    "before_agent_finalize",
    "agent_end",
    "before_tool_call",
    "after_tool_call",
    "tool_result_persist",
    "before_message_write",
    "before_install",
  ]);
  assert.equal(HOOK_NAME, "before_tool_call");
  assert.ok(REAL_OPENCLAW_HOOKS.has(HOOK_NAME));
});

test("exec is the real OpenClaw shell tool we intercept", () => {
  assert.ok(EXEC_TOOL_NAMES.has("exec"));
});

// ── extraction + tokenization ────────────────────────────────────────────────

test("extractCommand reads command / cmd / script keys", () => {
  assert.equal(extractCommand({ command: "pip install x" }), "pip install x");
  assert.equal(extractCommand({ cmd: "npm i y" }), "npm i y");
  assert.equal(extractCommand({ script: "cargo add z" }), "cargo add z");
  assert.equal(extractCommand({ other: "nope" }), null);
});

test("tokenize splits whitespace and honors quotes; operators stay separate", () => {
  assert.deepEqual(tokenize("pip install requests"), ["pip", "install", "requests"]);
  assert.deepEqual(tokenize("ls -la && pip install evilpkg"), [
    "ls",
    "-la",
    "&&",
    "pip",
    "install",
    "evilpkg",
  ]);
  assert.deepEqual(tokenize('pip install "name with space"'), [
    "pip",
    "install",
    "name with space",
  ]);
});

test("the runner is given TOKENS, not the whole command string", () => {
  let received = null;
  evaluateToolCall("exec", { command: "pip install evilpkg" }, (tokens) => {
    received = tokens;
    return { status: 0, stdout: "", stderr: "" };
  });
  assert.deepEqual(received, ["pip", "install", "evilpkg"]);
});

// ── decisions ────────────────────────────────────────────────────────────────

test("bad install (exit 1) is blocked with a cleaned reason", () => {
  const d = evaluateToolCall("exec", { command: "pip install evilpkg" }, blockRunner());
  assert.ok(d);
  assert.equal(d.block, true);
  assert.match(d.blockReason, /evilpkg/);
  assert.doesNotMatch(d.blockReason, /BLOCKED 1 item/); // heading stripped
});

test("clean install (exit 0) is allowed (null)", () => {
  assert.equal(evaluateToolCall("exec", { command: "pip install requests" }, allowRunner), null);
});

test("warn (exit 0 + flagged for review) fails closed to block", () => {
  const d = evaluateToolCall("exec", { command: "pip install sus" }, warnRunner);
  assert.ok(d);
  assert.equal(d.block, true);
});

test("non-install command is allowed", () => {
  assert.equal(evaluateToolCall("exec", { command: "ls -la" }, allowRunner), null);
});

test("non-exec tool is ignored", () => {
  assert.equal(evaluateToolCall("web_search", { query: "pip install evil" }, blockRunner()), null);
});

test("exec with no command is allowed (nothing to run)", () => {
  assert.equal(evaluateToolCall("exec", {}, blockRunner()), null);
  assert.equal(evaluateToolCall("exec", { command: "   " }, blockRunner()), null);
});

// ── fail-closed semantics ────────────────────────────────────────────────────

test("CLI usage error (exit 2) on an install command FAILS CLOSED", () => {
  const d = evaluateToolCall("exec", { command: "pip install evilpkg" }, usageErrorRunner);
  assert.ok(d);
  assert.equal(d.block, true);
  assert.match(d.blockReason, /fail closed/i);
});

test("CLI usage error (exit 2) on a NON-install command does NOT wedge the shell", () => {
  assert.equal(evaluateToolCall("exec", { command: "ls -la" }, usageErrorRunner), null);
});

test("CLI throwing on an install command FAILS CLOSED", () => {
  const d = evaluateToolCall("exec", { command: "pip install evilpkg" }, throwingRunner);
  assert.ok(d);
  assert.equal(d.block, true);
});

test("spawn error on an install command FAILS CLOSED", () => {
  const d = evaluateToolCall("exec", { command: "npm install evil" }, spawnErrorRunner);
  assert.ok(d);
  assert.equal(d.block, true);
});

test("CLI throwing on a NON-install command does not wedge the shell", () => {
  assert.equal(evaluateToolCall("exec", { command: "ls -la" }, throwingRunner), null);
});

// ── scanner-unavailable fallback must cover the registry's install forms ──────
// Regression for the audit finding: the fail-closed fallback previously missed
// install forms the Python registry recognises (notably `python -m pip` and the
// attached `python -mpip`), letting them proceed when the CLI could not run.

const MISSED_INSTALL_FORMS = [
  "python -m pip install evil",
  "python3 -m pip install evil",
  "python3.11 -m pip install evil",
  "python -mpip install evil", // attached module name — valid Python
  "python3 -mpip install evil",
  "/usr/bin/python -m pip install evil",
  "uv pip install evil",
  "uv add evil",
  "pipx install evil",
  "poetry add evil",
  "conda install evil",
];

for (const cmd of MISSED_INSTALL_FORMS) {
  test(`fallback fails closed for install form: ${cmd}`, () => {
    const d = evaluateToolCall("exec", { command: cmd }, throwingRunner);
    assert.ok(d, `${cmd} slipped past the fail-closed fallback`);
    assert.equal(d.block, true);
  });
  test(`fallback fails closed on spawn error for: ${cmd}`, () => {
    const d = evaluateToolCall("exec", { command: cmd }, spawnErrorRunner);
    assert.ok(d, `${cmd} slipped past the fail-closed fallback`);
    assert.equal(d.block, true);
  });
}

// Non-install commands that merely *contain* manager-ish substrings must NOT be
// wedged when the scanner is down (no over-broad fail-closed).
const NON_INSTALL_SAFE = [
  "django manage.py migrate",
  "go run main.go",
  "cargo build",
  "git add .",
  "echo install instructions",
  "npm run build",
];

for (const cmd of NON_INSTALL_SAFE) {
  test(`fallback does not wedge non-install command: ${cmd}`, () => {
    assert.equal(evaluateToolCall("exec", { command: cmd }, throwingRunner), null);
  });
}

// NEEDS_CONFIRMATION now surfaces as exit 2 (fail-closed when non-interactive);
// it must block an install but not a bystander command.
const needsConfirmRunner = () => ({
  status: 2,
  stdout: "AgentShield: 1 item(s) require confirmation before install:\n  • sus: WARN_CONFIRM",
  stderr: "",
});

test("NEEDS_CONFIRMATION (exit 2) on an install fails closed", () => {
  const d = evaluateToolCall("exec", { command: "pip install sus" }, needsConfirmRunner);
  assert.ok(d);
  assert.equal(d.block, true);
});

// LOG_ASYNC is warn-only: exit 0 with no "flagged for review" text → proceed.
const logAsyncRunner = () => ({
  status: 0,
  stdout: "AgentShield: 1 item(s) logged for async review — proceeding\n  • pkg: low-risk",
  stderr: "",
});

test("LOG_ASYNC (exit 0, async review) is allowed to proceed", () => {
  assert.equal(evaluateToolCall("exec", { command: "pip install pkg" }, logAsyncRunner), null);
});
