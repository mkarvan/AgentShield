# AgentShield — Project Plan

> **Status:** Pre-development  
> **Last updated:** 2026-06-12 (rev 2)

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Goals & Non-Goals](#2-goals--non-goals)
3. [Threat Model & Vulnerability Taxonomy](#3-threat-model--vulnerability-taxonomy)
4. [Architecture Design](#4-architecture-design)
5. [Component Breakdown](#5-component-breakdown)
6. [Tech Stack](#6-tech-stack)
7. [API & Interface Design](#7-api--interface-design)
8. [Response Mode System](#8-response-mode-system)
9. [Database & Caching Strategy](#9-database--caching-strategy)
10. [Framework Integration Layers](#10-framework-integration-layers)
11. [Posture Check Reports](#11-posture-check-reports)
12. [Testing Strategy](#12-testing-strategy)
13. [Phased Roadmap](#13-phased-roadmap)
14. [Future Expansion](#14-future-expansion)
15. [Open Questions](#15-open-questions)

---

## 1. Project Overview

AgentShield is a **local-first, framework-agnostic security layer** for AI agent frameworks. It intercepts package installation calls made by agents, evaluates them against vulnerability databases and static analysis tools, and enforces configurable response policies before any package is installed or used.

### Why this exists

AI agents are increasingly capable of installing and invoking arbitrary packages on behalf of users. This creates a novel attack surface:

- An agent can be prompted (directly or via prompt injection) to install a malicious package
- Agents may suggest packages by name, creating typosquatting risk
- Agents don't inherently check CVEs or audit dependency trees
- Compromised packages can exfiltrate context windows, API keys, tool credentials, or local files

AgentShield sits between the agent's intent ("install X") and the system executing that intent, providing a security checkpoint the agent cannot bypass.

### Target frameworks (v1)

| Framework | Integration style |
|-----------|------------------|
| Hermes Agent | Tool plugin |
| OpenClaw | Skill |
| Any MCP-compatible agent | MCP tool server |
| Claude Code | Hooks (post-v1) |

---

## 2. Goals & Non-Goals

### Goals

- Intercept `pip install`, `npm install`, `cargo add` invocations originating from agent actions
- Check packages against NVD, OSV, and GitHub Advisory databases
- Run lightweight static analysis (semgrep rules, bandit, npm audit)
- Detect typosquatting and known-malicious packages
- Apply per-rule or global response policies (block / warn+confirm / ignore / async-report)
- Cache results for known packages to keep latency negligible
- Generate human-readable security posture reports
- Remain local-first: no telemetry, no cloud dependency for core operation

### Non-Goals (v1)

- Runtime sandboxing of installed packages (out of scope; consider gVisor/nsjail separately)
- Network egress filtering for running agents
- Binary/compiled artifact scanning
- CI/CD pipeline integration (planned for v2)
- Multi-user or SaaS deployment

---

## 3. Threat Model & Vulnerability Taxonomy

This taxonomy is informed by the paper *"A Systematic Taxonomy of Security Vulnerabilities in the OpenClaw AI Agent Framework"* (arXiv 2603.27517) and adapted for supply-chain/package-installation attack vectors.

### T1 — Supply Chain Attacks

| ID | Name | Description |
|----|------|-------------|
| T1.1 | Malicious package | Package exists solely to exfiltrate or execute malicious code |
| T1.2 | Typosquatting | Package name is a near-miss of a legitimate package (e.g. `reqests` vs `requests`) |
| T1.3 | Dependency confusion | Internal package name shadowed by a public registry package |
| T1.4 | Compromised legitimate package | Known-good package with a malicious version introduced post-publish |

### T2 — Known Vulnerabilities (CVEs)

| ID | Name | Description |
|----|------|-------------|
| T2.1 | Critical CVE | CVSS ≥ 9.0 in requested package version |
| T2.2 | High CVE | CVSS 7.0–8.9 in requested package version |
| T2.3 | Transitive CVE | Vulnerability in a dependency of the requested package |
| T2.4 | Outdated package | Package has a newer version with security fixes |

### T3 — Code-Level Red Flags (Static Analysis)

| ID | Name | Description |
|----|------|-------------|
| T3.1 | Shell execution | Package uses `subprocess`, `exec`, `eval`, `os.system` at install time (setup.py) |
| T3.2 | Network at install time | Package makes outbound connections during `pip install` (setup.py network calls) |
| T3.3 | Filesystem write outside package dir | Writes to `~/.ssh`, `~/.aws`, `/etc`, etc. |
| T3.4 | Obfuscated code | Base64-encoded payloads, heavily obfuscated strings |
| T3.5 | Credential harvesting patterns | Reads env vars matching `*_KEY`, `*_TOKEN`, `*_SECRET` |

### T4 — Agent-Specific Risks

| ID | Name | Description | v1 coverage |
|----|------|-------------|-------------|
| T4.1 | Prompt-injected install | Agent was instructed to install a package via injected prompt in retrieved content | Heuristic in Phase 3; full detection in v1.0 |
| T4.2 | Excessive permissions | Package requests capabilities beyond what the task requires | Posture report only |
| T4.3 | Context exfiltration | Package or tool could read the agent's context window / memory | Posture report only |

**T4.1 heuristic (Phase 3):** When a `ScanRequest` is received, check whether `context_hint` (the snippet the integration layer passes explaining why the agent wants the package) contains the package name verbatim in a pattern consistent with retrieved/tool-returned content rather than the agent's own reasoning. Specifically: flag if the package name appears inside a quoted string, code block, or markdown link that the agent appears to have copy-pasted rather than generated. Severity: MEDIUM with `warn_confirm` default — enough to surface suspicion without blocking every install. The full v1.0 version uses a small classifier trained on injected vs. benign install intents.

### Severity scoring

AgentShield assigns each finding a severity: **CRITICAL / HIGH / MEDIUM / LOW / INFO**. The default response mode per severity level can be configured globally and overridden per rule.

---

## 4. Architecture Design

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Agent Framework                             │
│  ┌─────────────┐    ┌──────────────┐    ┌─────────────────────┐    │
│  │   Hermes    │    │   OpenClaw   │    │    Claude Code      │    │
│  │ tool plugin │    │    skill     │    │      hooks          │    │
│  └──────┬──────┘    └──────┬───────┘    └──────────┬──────────┘    │
└─────────┼─────────────────┼──────────────────────────┼─────────────┘
          │ ScanRequest      │                           │
          └──────────────────┴───────────────────────────┘
                             │
                    ┌────────▼────────┐
                    │  AgentShield    │
                    │   Core Engine   │
                    │   (CLI + lib)   │
                    └────────┬────────┘
                             │
          ┌──────────────────┼──────────────────┐
          │                  │                  │
   ┌──────▼──────┐  ┌────────▼────────┐  ┌─────▼──────┐
   │  Enrichment │  │  Static Analysis│  │  Response  │
   │   Layer     │  │     Layer       │  │   Engine   │
   │             │  │                 │  │            │
   │ • NVD API   │  │ • semgrep       │  │ • block    │
   │ • OSV API   │  │ • bandit        │  │ • warn+ask │
   │ • GH Adv.   │  │ • npm audit     │  │ • ignore   │
   │ • Typosquat │  │ • custom rules  │  │ • report   │
   └──────┬──────┘  └────────┬────────┘  └─────┬──────┘
          │                  │                  │
          └──────────────────┴──────────────────┘
                             │
                    ┌────────▼────────┐
                    │  Local Cache &  │
                    │  CVE Database   │
                    │  (SQLite)       │
                    └─────────────────┘
```

### Data flow for a single scan

```
Agent requests: pip install numpy==1.24.0
       │
       ▼
[Integration layer] → ScanRequest(package="numpy", version="1.24.0", ecosystem="pypi")
       │
       ▼
[Core Engine] checks local cache
  ├── Cache HIT (< TTL) → return cached ScanResult
  └── Cache MISS →
         │
         ├── [Enrichment] NVD, OSV, GH Advisory queries (async, parallel)
         ├── [Typosquat] Levenshtein + known-package list check
         └── [--deep only] download wheel → semgrep + bandit + custom rules
                │
                ▼
         [ScanResult] aggregated findings + severity
                │
                ▼
         [Response Engine] evaluates against rules config
                │
         ┌──────┴──────┐
         │             │
      ALLOW          BLOCK / WARN / REPORT
         │
         ▼
   [Cache write] store result with TTL
         │
         ▼
   [Integration] return decision to framework
```

---

## 5. Component Breakdown

### 5.1 Core Engine (`agentshield.core`)

| Module | Responsibility |
|--------|---------------|
| `scanner.py` | Orchestrates a scan: coordinates enrichment + typosquatting checks by default; runs static analysis only when `deep=True` is passed (i.e. `--deep` CLI flag or `ScanRequest(deep=True)`) |
| `response_engine.py` | Evaluates a `ScanResult` against the loaded `Config`, produces a `Decision` |
| `config.py` | Loads/validates TOML config; holds global defaults + per-rule overrides |
| `models.py` | Pydantic models: `ScanRequest`, `ScanResult`, `Finding`, `Decision`, `ResponseMode` |
| `cache.py` | SQLite-backed result cache with TTL management |

### 5.2 Enrichment Layer (`agentshield.databases`)

| Module | Data source | Notes |
|--------|-------------|-------|
| `nvd.py` | NIST NVD REST API v2 | Queries by CPE or package name; rate-limited to 5 req/30s without API key |
| `osv.py` | OSV.dev REST API | Best for PyPI/npm/crates.io; returns structured vuln objects |
| `github_advisory.py` | GitHub Advisory Database (GraphQL) | Requires GH token; good for JS ecosystem |
| `typosquatting.py` | Local list + Levenshtein distance | Compares against top-N most downloaded packages per ecosystem |
| `malicious_db.py` | Local curated list + OSV `malicious` type filter | Known-malicious packages (socket.dev feed, etc.) |

### 5.3 Static Analysis Layer (`agentshield.analyzers`)

| Module | Tool | Target |
|--------|------|--------|
| `semgrep_runner.py` | semgrep | Python, JS, Rust source in downloaded packages |
| `bandit_runner.py` | bandit | Python-specific: subprocess, eval, network in setup.py/pyproject |
| `npm_audit_runner.py` | npm audit --json | JS packages |
| `cargo_audit_runner.py` | cargo audit | Rust crates |
| `setup_py_inspector.py` | AST analysis | Detect network calls / filesystem writes in setup.py at install time |

### 5.4 Response Engine (`agentshield.core.response_engine`)

Evaluates findings against the config tree. Returns a `Decision` with:
- `action`: `ALLOW | BLOCK | NEEDS_CONFIRMATION | LOG_ASYNC`
- `reason`: human-readable explanation
- `findings`: list of `Finding` objects that triggered the decision
- `override_token`: short-lived token the user can present to allow a blocked package once

### 5.5 Integration Layers (`agentshield.integrations`)

Each integration is a thin adapter (~100–200 lines) that:
1. Registers with the framework (tool/skill/hook/MCP)
2. Intercepts install intents
3. Calls `agentshield.core.scanner.scan(request)` 
4. Handles the returned `Decision` according to framework conventions

The MCP server (`agentshield serve --mcp`) is the highest-leverage integration: any MCP-compatible agent framework gets AgentShield for free without a custom adapter.

### 5.6 CLI (`agentshield.cli`)

```
agentshield scan <package> [--ecosystem pypi|npm|cargo] [--version X.Y.Z] [--deep]
agentshield posture [--output report.html]
agentshield cache clear | stats | warm <packages-file>
agentshield rules list | test <package> [--deep]
agentshield config validate
agentshield serve  # starts a local Unix socket server for IPC
```

`--deep` opts in to static analysis (semgrep, bandit, setup.py AST inspection). Without it, only CVE database lookups and typosquatting checks run. CVE databases handle the vast majority of known-bad packages; static analysis is the long tail and adds several seconds of latency plus a transient disk write for wheel extraction. Framework integrations should not pass `deep=True` by default; reserve it for high-trust interactive use or explicit user configuration.

### 5.7 Posture Report (`agentshield.reports`)

Generates a snapshot of the agent environment's security posture (see §11).

---

## 6. Tech Stack

### Language: Python 3.11+

**Rationale:** Both Hermes Agent and OpenClaw are Python-first frameworks. Writing AgentShield in Python means:
- Zero FFI friction for integration layers
- Direct reuse of bandit, semgrep's Python SDK
- pip ecosystem is the primary target — eating our own dog food
- Pydantic for validated models, typer for CLI, rich for terminal output

For performance-critical paths (Levenshtein at scale, SQLite cache), we use compiled extensions (`python-Levenshtein`, `apsw`).

### Key dependencies

| Package | Purpose |
|---------|---------|
| `pydantic >= 2.0` | Data models and config validation |
| `typer` | CLI framework |
| `rich` | Terminal output (findings, posture reports) |
| `httpx[asyncio]` | Async HTTP for CVE API calls |
| `semgrep` | Static analysis (Python SDK) |
| `bandit` | Python-specific static analysis |
| `python-Levenshtein` | Fast edit-distance for typosquatting |
| `aiosqlite` | Async SQLite for cache |
| `toml` | Config file parsing |
| `jinja2` | HTML report templating |

### Dev dependencies

| Package | Purpose |
|---------|---------|
| `pytest` + `pytest-asyncio` | Test runner |
| `pytest-cov` | Coverage |
| `respx` | Mock httpx calls in tests |
| `ruff` | Linting + formatting |
| `mypy` | Type checking |
| `pre-commit` | Git hooks |

---

## 7. API & Interface Design

### 7.1 Python library API

```python
from agentshield import AgentShield, ScanRequest, Ecosystem

# Instantiate (loads config from ~/.config/agentshield/config.toml by default)
shield = AgentShield()

# Synchronous scan
result = shield.scan(ScanRequest(
    package="requests",
    version="2.28.0",
    ecosystem=Ecosystem.PYPI,
))

print(result.decision.action)   # Decision.ALLOW | BLOCK | NEEDS_CONFIRMATION | LOG_ASYNC
print(result.findings)          # list[Finding]

# Async scan (preferred for integration layers)
result = await shield.ascan(request)

# Posture check
report = await shield.posture_check(
    installed_packages=shield.detect_installed_packages(),
    agent_tools=["read_file", "bash", "web_search"],
)
```

### 7.2 ScanRequest model

```python
class ScanRequest(BaseModel):
    package: str                         # package name
    version: str | None = None           # None = latest
    ecosystem: Ecosystem                 # PYPI | NPM | CARGO
    source: str | None = None           # "hermes" | "openclaw" | "manual"
    context_hint: str | None = None     # brief snippet of why agent wants this package
```

### 7.3 ScanResult model

```python
class ScanResult(BaseModel):
    request: ScanRequest
    findings: list[Finding]
    max_severity: Severity              # CRITICAL | HIGH | MEDIUM | LOW | INFO | NONE
    decision: Decision
    scan_duration_ms: int
    cache_hit: bool
    scanned_at: datetime
```

### 7.4 Finding model

```python
class Finding(BaseModel):
    rule_id: str                        # e.g. "T1.2", "CVE-2023-12345"
    title: str
    description: str
    severity: Severity
    source: str                         # "nvd" | "osv" | "github_advisory" | "semgrep" | "bandit" | "typosquatting"
    references: list[str]               # URLs
    cvss_score: float | None = None
    remediation: str | None = None
```

### 7.5 IPC socket protocol (for hooks/shell integration)

When `agentshield serve` is running, it exposes a Unix domain socket at `~/.agentshield/agentshield.sock`. Clients send newline-delimited JSON:

```json
// Request
{"jsonrpc": "2.0", "method": "scan", "params": {"package": "numpy", "version": "1.24.0", "ecosystem": "pypi"}, "id": 1}

// Response
{"jsonrpc": "2.0", "result": {"decision": "ALLOW", "findings": [], "cache_hit": true}, "id": 1}
```

This allows shell scripts, Claude Code hooks, and non-Python integrations to call AgentShield without importing the Python library.

---

## 8. Response Mode System

### Modes

| Mode | Identifier | Behavior |
|------|-----------|---------|
| **Block** | `block` | Refuse install, return error to agent. Agent cannot proceed. |
| **Warn and Confirm** | `warn_confirm` | Present findings to user, wait for explicit approval. Agent proceeds only if approved. |
| **Ignore** | `ignore` | Skip this check entirely. No scan, no delay. |
| **Async Report** | `async_report` | Allow install unconditionally, but record findings for the next posture report. |

### Configuration structure (`config.toml`)

```toml
[defaults]
# Global fallback for all severities
critical = "block"
high     = "warn_confirm"
medium   = "async_report"
low      = "ignore"
info     = "ignore"

[ecosystems.pypi]
# Override defaults for pip installs
critical = "block"
high     = "block"        # stricter than default

[ecosystems.npm]
critical = "block"
high     = "warn_confirm"

[rules]
# Per-rule-ID overrides (highest priority)

  [rules."T1.2"]          # typosquatting always blocks
  mode = "block"

  [rules."T1.1"]          # malicious packages always block
  mode = "block"

  [rules."T2.3"]          # transitive CVEs only get reported
  mode = "async_report"

  [rules."T3.1"]          # subprocess at install time: warn+confirm
  mode = "warn_confirm"

[allowlist]
# Packages that bypass all checks (use sparingly)
packages = ["numpy", "requests", "pytest"]

[denylist]
# Packages that are always blocked regardless of findings
packages = ["malicious-pkg-example"]

[cache]
ttl_hours = 24
max_entries = 50000
db_path = "~/.agentshield/cache.db"

[reporting]
report_dir = "~/.agentshield/reports/"
auto_report_on_exit = true
```

### Priority resolution

When determining the response mode for a finding:

```
rule-level override
  ↓ (if not set)
ecosystem-level override
  ↓ (if not set)
global severity default
  ↓ (if in allowlist)
always ALLOW
  ↑ (if in denylist)
always BLOCK (trumps all)
```

### Confirmation UX (warn_confirm mode)

When running inside a framework integration, the confirmation is surfaced through the framework's native user-interaction mechanism:
- **Hermes:** tool returns a structured message asking the user to confirm; agent pauses
- **OpenClaw:** skill emits a `UserConfirmationRequest` object that the framework surfaces
- **CLI:** interactive `rich` prompt with full finding details

A confirmed package issues a short-lived `override_token` (UUID + expiry timestamp) stored in the session. Subsequent installs of the same package+version within the session use the cached token without re-prompting.

---

## 9. Database & Caching Strategy

### 9.1 SQLite schema

All local state lives in `~/.agentshield/agentshield.db`.

```sql
-- Cached scan results
CREATE TABLE scan_cache (
    id            TEXT PRIMARY KEY,          -- sha256(ecosystem:package:version)
    package       TEXT NOT NULL,
    version       TEXT NOT NULL,
    ecosystem     TEXT NOT NULL,
    result_json   TEXT NOT NULL,             -- serialized ScanResult
    scanned_at    INTEGER NOT NULL,          -- unix timestamp
    expires_at    INTEGER NOT NULL           -- unix timestamp
);

-- CVE snapshots (mirror of OSV/NVD for offline use)
CREATE TABLE cve_mirror (
    id            TEXT PRIMARY KEY,          -- CVE-XXXX-XXXXX
    package       TEXT NOT NULL,
    ecosystem     TEXT NOT NULL,
    affected_versions TEXT NOT NULL,         -- JSON range spec
    severity      TEXT NOT NULL,
    cvss_score    REAL,
    description   TEXT,
    last_fetched  INTEGER NOT NULL
);

-- Known-malicious packages
CREATE TABLE malicious_packages (
    id            INTEGER PRIMARY KEY,
    package       TEXT NOT NULL,
    ecosystem     TEXT NOT NULL,
    reason        TEXT,
    source        TEXT,                      -- "osv_malicious" | "socket_dev" | "manual"
    added_at      INTEGER NOT NULL
);

-- Posture report history
CREATE TABLE posture_reports (
    id            TEXT PRIMARY KEY,          -- uuid
    generated_at  INTEGER NOT NULL,
    report_json   TEXT NOT NULL
);
```

### 9.2 Cache warm-up

On first run (or via `agentshield cache warm`), AgentShield:

1. Downloads the full OSV advisory database for PyPI, npm, and crates.io (available as bulk JSON export)
2. Fetches the top-5000 packages per ecosystem by download count and caches their typosquat neighbors
3. Downloads the socket.dev malicious package feed

Subsequent runs refresh incrementally via delta feeds where available (OSV supports this).

### 9.3 Cache TTL strategy

| Data type | Default TTL |
|-----------|-------------|
| Clean scan (no findings) | 24 hours |
| Scan with LOW/INFO findings | 12 hours |
| Scan with MEDIUM+ findings | 6 hours |
| Malicious package record | 7 days |
| CVE mirror entry | 24 hours |

Known-safe packages (e.g., top-100 PyPI packages on allowlist) get a 7-day TTL to minimize latency.

### 9.4 Latency targets

| Scenario | Target P95 latency |
|----------|--------------------|
| Cache hit | < 5 ms |
| Cache miss, default scan (CVE + typosquat only) | < 3 seconds |
| Cache miss, `--deep` scan (+ static analysis) | < 15 seconds |
| Offline mode (no API access) | < 50 ms (local DB only) |

The `--deep` budget is wider because wheel download + extraction + semgrep traversal are inherently I/O-bound. A progress indicator should be shown for any scan exceeding 2 seconds.

---

## 10. Framework Integration Layers

### 10.1 Hermes Agent — Tool Plugin

Hermes exposes a tool plugin API. AgentShield registers as a tool the Hermes runtime calls before executing any `pip_install`, `npm_install`, or `cargo_add` tool calls.

```python
# agentshield/integrations/hermes/plugin.py

from hermes.tools import ToolPlugin, ToolCall, ToolResult

class AgentShieldPlugin(ToolPlugin):
    name = "agentshield"
    intercepts = ["pip_install", "npm_install", "cargo_add"]

    async def before_tool_call(self, call: ToolCall) -> ToolCall | ToolResult:
        request = self._build_scan_request(call)
        result = await self.shield.ascan(request)

        if result.decision.action == "BLOCK":
            return ToolResult.error(f"AgentShield blocked: {result.decision.reason}")

        if result.decision.action == "NEEDS_CONFIRMATION":
            # Return a special result that Hermes surfaces to the user
            return ToolResult.needs_confirmation(
                message=self._format_findings(result.findings),
                on_confirm=call,
            )

        # ALLOW or LOG_ASYNC: proceed
        return call  # pass through unmodified
```

**Config location:** `~/.hermes/plugins/agentshield.toml` or inline in the Hermes agent config.

### 10.2 OpenClaw — Skill

OpenClaw skills are async Python callables registered with the agent kernel. AgentShield provides a `SecurityCheckSkill` that wraps any install-related skill calls.

```python
# agentshield/integrations/openclaw/skill.py

from openclaw.skills import Skill, SkillContext, SkillResult

class AgentShieldSkill(Skill):
    name = "agentshield_check"
    description = "Security check before installing packages"

    async def execute(self, ctx: SkillContext) -> SkillResult:
        package = ctx.params["package"]
        ecosystem = ctx.params.get("ecosystem", "pypi")
        result = await self.shield.ascan(ScanRequest(
            package=package, ecosystem=ecosystem, source="openclaw"
        ))
        return SkillResult(
            allowed=result.decision.action in ("ALLOW", "LOG_ASYNC"),
            decision=result.decision.action,
            findings=[f.model_dump() for f in result.findings],
        )
```

**Wiring:** registered in `openclaw_config.yaml` as a pre-condition skill for install-type actions.

### 10.3 MCP Tool Server

Running `agentshield serve --mcp` starts an MCP-compliant tool server on a local Unix socket (or TCP port). Any agent framework that speaks MCP can connect and call AgentShield tools without a custom integration layer — this is the fastest adoption path for frameworks other than Hermes and OpenClaw.

**Exposed tools:**

```json
{
  "tools": [
    {
      "name": "agentshield_scan",
      "description": "Check a package for security vulnerabilities before installing. Returns a decision (ALLOW/BLOCK/NEEDS_CONFIRMATION/LOG_ASYNC) and a list of findings.",
      "inputSchema": {
        "type": "object",
        "properties": {
          "package":    { "type": "string" },
          "version":    { "type": "string" },
          "ecosystem":  { "type": "string", "enum": ["pypi", "npm", "cargo"] },
          "deep":       { "type": "boolean", "default": false },
          "context_hint": { "type": "string" }
        },
        "required": ["package", "ecosystem"]
      }
    },
    {
      "name": "agentshield_posture",
      "description": "Generate a security posture report for the current environment. Returns a structured JSON report.",
      "inputSchema": { "type": "object", "properties": {} }
    }
  ]
}
```

**Transport:** Stdio (default, works with any MCP client) and Unix socket (`--socket`). The same `agentshield serve` daemon that handles the IPC protocol (§7.5) can serve both MCP and JSON-RPC clients simultaneously.

**Config location:** MCP client configuration points to `agentshield serve --mcp --stdio` as the server command. No additional per-framework wiring is required.

### 10.4 Claude Code — Hooks (post-v1)

Claude Code's hook system can fire shell commands on `PreToolUse` events. AgentShield exposes a CLI entry point:

```bash
# In .claude/settings.json hooks:
# "PreToolUse": "agentshield hook --tool $TOOL_NAME --input '$TOOL_INPUT'"

agentshield hook --tool Bash --input '{"command": "pip install numpy"}'
# exit 0 = allow, exit 1 = block (with reason on stderr)
```

The hook parses the Bash command, extracts any `pip install` / `npm install` / `cargo add` invocations, and runs a scan. This works with the `agentshield serve` daemon for low latency (avoids Python startup on every hook call). Note that Claude Code can also use AgentShield via the MCP tool server (§10.3) — hooks are only needed for intercepting raw Bash commands that bypass MCP.

---

## 11. Posture Check Reports

The posture check generates a point-in-time security assessment of an agent environment.

### 11.1 Report sections

```
AgentShield Posture Report
Generated: 2026-06-12 14:32:00
Agent: hermes-v2.1.0

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Risk score:         HIGH (73/100)
Packages scanned:   147
Critical findings:  2
High findings:      7
Medium findings:    14
Low findings:       31

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CRITICAL FINDINGS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[CRITICAL] CVE-2024-12345 in Pillow 9.5.0
  CVSS: 9.8 | Arbitrary code execution via crafted TIFF
  Fix: upgrade to Pillow >= 10.0.1

[CRITICAL] T1.1 — malicious-helper 0.1.2 (installed via agent session #3)
  Source: OSV malicious package database
  Action: UNINSTALL IMMEDIATELY

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ATTACK SURFACE SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Registered tools:     12
  High-risk tools:    bash, write_file, execute_python
  Medium-risk tools:  web_search, read_file
  Low-risk tools:     (7 others)

Tool permissions:     filesystem:read, filesystem:write,
                      network:outbound, subprocess:exec
Sensitive env vars:   OPENAI_API_KEY ✓ detected (redacted)
                      ANTHROPIC_API_KEY ✓ detected (redacted)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ASYNC REPORT LOG (last 24h)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
14 packages installed without real-time check (async_report mode)
  3 have MEDIUM findings — review recommended
```

### 11.2 Output formats

| Format | Use case |
|--------|---------|
| Terminal (rich) | `agentshield posture` |
| JSON | `agentshield posture --format json` |
| HTML | `agentshield posture --format html --output report.html` |
| Markdown | `agentshield posture --format markdown` |

### 11.3 Risk scoring

Risk score (0–100) uses a **tanh-based saturation formula** so that each severity band contributes diminishing returns as the count grows. A single critical finding lands near the LOW/MEDIUM boundary rather than immediately pushing the score into MEDIUM; it takes a cluster of findings across severities to reach HIGH or CRITICAL.

```python
from math import tanh

def risk_score(
    critical_count: int,
    high_count: int,
    medium_count: int,
    low_count: int,
    high_risk_tool_count: int,
) -> int:
    score = (
        40 * tanh(critical_count        / 1.5) +  # saturates near 40 around 3–4 criticals
        25 * tanh(high_count            / 2.0) +  # saturates near 25 around 4–5 highs
        20 * tanh(medium_count          / 4.0) +  # saturates near 20 around 8–10 mediums
        10 * tanh(low_count             / 8.0) +  # saturates near 10 around 16+ lows
         5 * tanh(high_risk_tool_count  / 3.0)    # up to +5 for dangerous tool config
    )
    return min(100, round(score))
```

**Why tanh?** Each band has a maximum contribution (40 / 25 / 20 / 10 / 5 = 100 total), and the `tanh(n / k)` shape gives fast initial growth then a plateau — intuitively, the 5th critical finding adds much less marginal risk than the 1st. The `k` parameter (denominator) sets how many findings it takes to reach ~76% of the band's max.

**Reference values:**

| Scenario | Score | Label |
|----------|-------|-------|
| 1 critical finding | ~23 | LOW |
| 2 critical findings | ~35 | MEDIUM |
| 3–4 critical findings | ~41 | MEDIUM |
| 1 critical + 3 high | ~46 | MEDIUM |
| 3 critical + 5 high | ~64 | HIGH |
| 3 critical + 5 high + 10 medium | ~73 | HIGH |
| 3 critical + 5 high + 10 med + dangerous tools | ~76 | CRITICAL |

**Thresholds:** 0–24 LOW, 25–49 MEDIUM, 50–74 HIGH, 75–100 CRITICAL.

---

## 12. Testing Strategy

### 12.1 Unit tests

- `test_config.py` — config parsing, priority resolution, allowlist/denylist
- `test_models.py` — Pydantic model validation edge cases
- `test_response_engine.py` — decision logic for all mode combinations
- `test_cache.py` — TTL expiry, cache hit/miss, eviction
- `test_typosquatting.py` — Levenshtein thresholds, known attack vectors
- `test_risk_score.py` — posture report scoring math

### 12.2 Integration tests

- `test_nvd_integration.py` — real NVD API calls (skipped in CI without key, mocked otherwise)
- `test_osv_integration.py` — real OSV API call against known-vulnerable package versions
- `test_static_analysis.py` — semgrep/bandit on synthetic malicious package fixtures

### 12.3 Fixture packages

`tests/fixtures/packages/` contains synthetic packages designed to trigger each rule:

| Fixture | Triggers |
|---------|---------|
| `typosquat_requests/` | T1.2 (misspelling of `requests`) |
| `network_at_install/` | T3.2 (HTTP call in setup.py) |
| `obfuscated_payload/` | T3.4 (base64-encoded payload) |
| `cred_harvester/` | T3.5 (reads `*_TOKEN` env vars) |

### 12.4 End-to-end tests

`tests/e2e/` tests the full scan pipeline including the IPC socket server:

```python
async def test_block_known_malicious():
    async with AgentShieldServer() as server:
        result = await server.scan(ScanRequest(
            package="colouredlogs",  # known malicious package
            ecosystem=Ecosystem.PYPI,
        ))
        assert result.decision.action == "BLOCK"
        assert any(f.rule_id == "T1.1" for f in result.findings)
```

### 12.5 Coverage target

- Core engine: **≥ 95%** line coverage
- Integration layers: **≥ 80%** (harder to mock framework internals)
- CLI: **≥ 70%** (UI paths are exercised via e2e)

---

## 13. Phased Roadmap

### Phase 0 — Foundation (Weeks 1–3)

- [ ] Repository setup, CI/CD (GitHub Actions), pre-commit hooks
- [ ] Core models (Pydantic): `ScanRequest`, `ScanResult`, `Finding`, `Decision`
- [ ] Config loading and validation (TOML)
- [ ] SQLite cache layer (aiosqlite)
- [ ] OSV.dev client (highest coverage, best structured data)
- [ ] Basic typosquatting detection (Levenshtein)
- [ ] Response engine (block/warn/ignore/report logic)
- [ ] CLI: `agentshield scan` command
- [ ] Unit tests for all of the above

**Exit criteria:** `agentshield scan requests==2.28.0 --ecosystem pypi` returns a `ScanResult` in < 2 seconds with correct OSV data.

### Phase 1 — Full Enrichment (Weeks 4–6)

- [ ] NVD API v2 client (with rate limiting and API key support)
- [ ] GitHub Advisory Database client (GraphQL)
- [ ] Malicious package DB (OSV `malicious` type + local curated list)
- [ ] Cache warm-up command (`agentshield cache warm`)
- [ ] Offline mode (local DB only, no API calls)
- [ ] Unit + integration tests for all enrichment sources

**Exit criteria:** Cache warm-up completes in < 5 minutes; offline scan of top-1000 packages works with no network.

### Phase 2 — Static Analysis (`--deep`) (Weeks 7–9)

Static analysis is gated behind `--deep` (opt-in). Default scans stop at CVE databases + typosquatting; `--deep` additionally downloads the wheel, extracts it, and runs the full analyzer suite.

- [ ] semgrep runner (download wheel → extract → scan with AgentShield custom ruleset)
- [ ] bandit runner (Python-specific rules)
- [ ] `setup.py` AST inspector (network calls, filesystem writes)
- [ ] npm audit runner
- [ ] Custom semgrep rules for T3.1–T3.5
- [ ] `--deep` flag wired into CLI and `ScanRequest` model
- [ ] Progress indicator for scans > 2 seconds
- [ ] Fixture packages for each rule (test harness)

**Exit criteria:** All T3.x rules fire correctly on their fixture packages when `--deep` is passed; no false positives on numpy, requests, boto3 with or without `--deep`; default scan (no `--deep`) of numpy completes in < 3 seconds.

### Phase 3 — Framework Integrations + MCP (Weeks 10–12)

- [ ] Hermes Agent tool plugin (`agentshield.integrations.hermes`)
- [ ] OpenClaw skill (`agentshield.integrations.openclaw`)
- [ ] `agentshield serve` daemon (Unix socket IPC + MCP stdio transport)
- [ ] MCP tool server exposing `agentshield_scan` and `agentshield_posture` tools
- [ ] T4.1 heuristic: flag installs where `context_hint` suggests the package name came from retrieved/external content rather than agent reasoning (see §3 for heuristic spec)
- [ ] Integration tests for Hermes, OpenClaw, and MCP
- [ ] End-to-end test: Hermes agent tries to install a blocked package
- [ ] End-to-end test: MCP client (generic) calls `agentshield_scan` and receives a BLOCK decision

**Exit criteria:** Hermes and OpenClaw integrations pass e2e tests; MCP server responds correctly to a scan request from a vanilla MCP client; T4.1 heuristic fires on a synthetic prompt-injection fixture.

### Phase 4 — Posture Reports & Polish (Weeks 13–15)

- [ ] Posture check scanner (enumerates installed packages, tool permissions)
- [ ] Risk scoring algorithm
- [ ] HTML/JSON/Markdown report output
- [ ] Async report log aggregation
- [ ] `agentshield posture` CLI command
- [ ] Documentation: README, integration guides, config reference
- [ ] Public v0.1.0 release

**Exit criteria:** Posture report generates correctly for a Hermes environment with known findings; HTML output is human-readable.

---

## 14. Future Expansion

### v0.2 — Claude Code Hooks

- `PreToolUse` hook integration (shell-based, uses IPC socket)
- Claude Code-specific posture check (reads `.claude/settings.json` for tool permissions)
- `agentshield hook` CLI subcommand

### v0.3 — Tool Call & Script Scanning

Extend beyond package installation to scan:
- Shell commands (`bash`, `subprocess`) for injection patterns
- Python scripts before execution (via agent `run_code` tools)
- Web URLs before fetch (malicious domain check)

### v0.4 — CI/CD Integration

- GitHub Action: `agentshield/scan-action`
- Pre-commit hook for `requirements.txt` / `package.json` changes
- SBOM (Software Bill of Materials) generation

### v1.0 — Multi-Agent & Agentic Pipeline Security

- Cross-agent trust policies (agent A cannot install packages on behalf of agent B unless explicitly allowed)
- T4.1 full detection: replace the Phase 3 heuristic with a small classifier trained on injected vs. benign install intents, handling multi-turn and indirect injection patterns
- Agent session audit log with tamper-evident storage

---

## 15. Open Questions

1. ~~**Semgrep on downloaded packages**~~ — **Resolved:** static analysis is gated behind `--deep` (opt-in). Default scans run CVE lookups + typosquatting only. See §5.6 and §9.4.

2. **False positive rate** — semgrep rules for T3.1 (shell execution) will fire on many legitimate packages (e.g., any package with a C extension). We need a curated allowlist or severity dampener for this rule.

3. **Hermes/OpenClaw API stability** — both frameworks are under active development. We should pin integration tests to specific framework versions and watch for breaking changes in tool/skill plugin APIs.

4. **NVD API key requirement** — without an API key, NVD rate-limits to 5 req/30s. For production use, users need to supply their own key. We should make this a prominent setup step and support the OSV bulk download as a fallback.

5. **Cargo audit** — `cargo audit` requires the `cargo` toolchain to be installed. We should gracefully degrade (skip the check, log a warning) when it's not present rather than failing the entire scan.

6. **Windows support** — Unix domain sockets are used for the IPC daemon. Windows named pipes would be needed for Windows support. Defer unless there's demand.
