// Unit tests for the AgentShield OpenClaw plugin decision logic.
// Run: node --test  (Node >= 22). No network, no OpenClaw runtime needed —
// the AgentShield CLI is replaced by a fake runner.

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  EXEC_TOOL_NAMES,
  HOOK_NAME,
  evaluateToolCall,
  extractCommand,
} from "./scan-command.mjs";

// Fake runners standing in for `agentshield hook --agent openclaw`.
const blockRunner = (reason = "evil-pkg: known malicious") => () => ({
  status: 0,
  stdout: JSON.stringify({ block: true, blockReason: reason }),
  stderr: "",
});
const allowRunner = () => ({ status: 0, stdout: "", stderr: "" });
const throwingRunner = () => {
  throw new Error("ENOENT: agentshield not found");
};
const errorRunner = () => ({ status: null, stdout: "", stderr: "", error: new Error("spawn failed") });

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

// ── extraction ───────────────────────────────────────────────────────────────

test("extractCommand reads command / cmd / script keys", () => {
  assert.equal(extractCommand({ command: "pip install x" }), "pip install x");
  assert.equal(extractCommand({ cmd: "npm i y" }), "npm i y");
  assert.equal(extractCommand({ script: "cargo add z" }), "cargo add z");
  assert.equal(extractCommand({ other: "nope" }), null);
});

// ── decisions ────────────────────────────────────────────────────────────────

test("bad install is blocked with the CLI's reason", () => {
  const d = evaluateToolCall("exec", { command: "pip install evil-pkg" }, blockRunner());
  assert.ok(d);
  assert.equal(d.block, true);
  assert.match(d.blockReason, /evil-pkg/);
});

test("clean install is allowed (null)", () => {
  const d = evaluateToolCall("exec", { command: "pip install requests" }, allowRunner);
  assert.equal(d, null);
});

test("non-install command is allowed", () => {
  const d = evaluateToolCall("exec", { command: "ls -la" }, allowRunner);
  assert.equal(d, null);
});

test("non-exec tool is ignored", () => {
  const d = evaluateToolCall("web_search", { query: "pip install evil" }, blockRunner());
  assert.equal(d, null);
});

test("exec with no command is allowed (nothing to run)", () => {
  assert.equal(evaluateToolCall("exec", {}, blockRunner()), null);
  assert.equal(evaluateToolCall("exec", { command: "   " }, blockRunner()), null);
});

// ── fail-closed semantics ────────────────────────────────────────────────────

test("CLI throwing on an install command FAILS CLOSED", () => {
  const d = evaluateToolCall("exec", { command: "pip install evil-pkg" }, throwingRunner);
  assert.ok(d);
  assert.equal(d.block, true);
  assert.match(d.blockReason, /fail closed/i);
});

test("CLI error on an install command FAILS CLOSED", () => {
  const d = evaluateToolCall("exec", { command: "npm install evil" }, errorRunner);
  assert.ok(d);
  assert.equal(d.block, true);
});

test("CLI throwing on a NON-install command does not wedge the shell", () => {
  const d = evaluateToolCall("exec", { command: "ls -la" }, throwingRunner);
  assert.equal(d, null);
});

test("non-zero exit with non-JSON stdout is treated as block", () => {
  const d = evaluateToolCall(
    "exec",
    { command: "pip install evil-pkg" },
    () => ({ status: 1, stdout: "AgentShield BLOCKED 1 item(s)", stderr: "" }),
  );
  assert.ok(d);
  assert.equal(d.block, true);
});
