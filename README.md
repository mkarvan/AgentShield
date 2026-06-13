# AgentShield

**Security layer for AI agent frameworks.** AgentShield intercepts package installation requests made by AI agents, checks them against CVE databases and static analysis tools, enforces configurable response policies, and generates security posture reports — all locally, with no telemetry.

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](#installation)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![v0.1.0](https://img.shields.io/badge/version-0.1.0-brightgreen)](#)

---

## Why this exists

AI agents can now install arbitrary packages on behalf of users. This creates a novel attack surface that existing security tooling doesn't address:

- An agent can be **prompt-injected** — a malicious web page or tool result instructs the agent to install a backdoored package
- Agents may **typosquat** — suggest `requets` instead of `requests`, or `panda` instead of `pandas`
- Agents don't inherently **check CVEs** or audit dependency trees before installing
- Compromised packages can **exfiltrate context windows**, API keys, tool credentials, or local files before the user notices anything

AgentShield sits between the agent's intent ("install X") and the system executing that intent, providing a security checkpoint the agent cannot bypass. It works with any framework through native plugins (Hermes, OpenClaw) or the MCP protocol.

---

## Table of Contents

- [Architecture](#architecture)
- [Threat model](#threat-model)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [CLI reference](#cli-reference)
- [Framework integrations](#framework-integrations)
- [Posture reports](#posture-reports)
- [Python API](#python-api)
- [Static analysis (--deep)](#static-analysis---deep)
- [Offline mode](#offline-mode)
- [Caching](#caching)
- [Contributing](#contributing)
- [License](#license)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Agent Framework                             │
│  ┌─────────────┐    ┌──────────────┐    ┌─────────────────────┐    │
│  │   Hermes    │    │   OpenClaw   │    │   Any MCP Client    │    │
│  │ tool plugin │    │    skill     │    │  (Claude, etc.)     │    │
│  └──────┬──────┘    └──────┬───────┘    └──────────┬──────────┘    │
└─────────┼─────────────────┼──────────────────────────┼─────────────┘
          │  ScanRequest     │                           │
          └──────────────────┴───────────────────────────┘
                             │
                    ┌────────▼────────┐
                    │  AgentShield    │
                    │   Core Engine   │
                    └────────┬────────┘
                             │
          ┌──────────────────┼──────────────────┐
          │                  │                  │
   ┌──────▼──────┐  ┌────────▼────────┐  ┌─────▼──────┐
   │  Enrichment │  │  Static Analysis│  │  Response  │
   │   Layer     │  │  (--deep only)  │  │   Engine   │
   │             │  │                 │  │            │
   │ • NVD API   │  │ • semgrep       │  │ • block    │
   │ • OSV API   │  │ • bandit        │  │ • warn+ask │
   │ • GH Adv.   │  │ • npm audit     │  │ • ignore   │
   │ • Typosquat │  │ • AST inspector │  │ • report   │
   └──────┬──────┘  └────────┬────────┘  └─────┬──────┘
          │                  │                  │
          └──────────────────┴──────────────────┘
                             │
                    ┌────────▼────────┐
                    │  Local SQLite   │
                    │  (cache + CVE   │
                    │  mirror + log)  │
                    └─────────────────┘
```

### Data flow

```
Agent: "pip install numpy==1.24.0"
  │
  ▼
[Integration layer]
  └─→ ScanRequest(package="numpy", version="1.24.0", ecosystem="pypi")
        │
        ▼
  [Core Engine]
  ├── cache HIT  → return cached ScanResult immediately (< 5 ms)
  └── cache MISS →
        ├── [Enrichment]  OSV + NVD + GitHub Advisory in parallel
        ├── [Typosquat]   Levenshtein vs. top-N package list
        ├── [Malicious]   local curated DB + OSV malicious feed
        ├── [T4.1]        prompt-injection heuristic on context_hint
        └── [--deep only] download wheel → semgrep + bandit + AST
              │
              ▼
        [Response Engine]  evaluate against config
              │
        ┌─────┴──────┐
        │            │
     ALLOW        BLOCK / WARN / LOG_ASYNC
        │
        ▼
  [Cache write] → store with TTL
        │
        ▼
  [Integration] → return decision to framework
```

### Design principles

- **Local-first.** The SQLite cache, CVE mirror, and malicious-package list are all on disk. Core scans work without network after `cache warm`. No telemetry, no cloud dependency.
- **Fail-open with logging.** When an enrichment source times out or errors, it's skipped and logged at WARNING — the scan continues with remaining sources rather than failing entirely.
- **Static analysis is opt-in.** `--deep` downloads the wheel and runs semgrep/bandit. Default scans (CVE + typosquat) run in < 3 seconds without downloading anything.
- **Policy over hard-coding.** Every response (block/warn/ignore/log) is driven by the config. You can tune per-severity, per-ecosystem, or per-rule-ID.

---

## Threat model

Informed by *"A Systematic Taxonomy of Security Vulnerabilities in the OpenClaw AI Agent Framework"* (arXiv 2603.27517), adapted for supply-chain attack vectors.

### T1 — Supply Chain Attacks

| ID | Threat | Description |
|----|--------|-------------|
| T1.1 | Malicious package | Package exists solely to exfiltrate data or execute malicious code |
| T1.2 | Typosquatting | Name is a near-miss of a legitimate package (`reqests` vs `requests`) |
| T1.3 | Dependency confusion | Internal package name shadowed by a public registry package |
| T1.4 | Compromised package | Legitimate package with a malicious version injected post-publish |

### T2 — Known Vulnerabilities (CVEs)

| ID | Threat | Description |
|----|--------|-------------|
| T2.1 | Critical CVE | CVSS ≥ 9.0 in the requested version |
| T2.2 | High CVE | CVSS 7.0–8.9 in the requested version |
| T2.3 | Transitive CVE | Vulnerability in a dependency of the requested package |
| T2.4 | Outdated package | Newer version available with security fixes |

### T3 — Install-time Code Red Flags (`--deep`)

| ID | Threat | Detected by |
|----|--------|-------------|
| T3.1 | Shell execution | `subprocess`, `exec`, `eval`, `os.system` in `setup.py` |
| T3.2 | Network at install time | `urllib.request`, `requests`, socket calls in `setup.py` |
| T3.3 | Filesystem write outside package dir | Writes to `~/.ssh`, `~/.aws`, `/etc` at install |
| T3.4 | Obfuscated code | `exec(base64.b64decode(...))`, marshal/zlib chains |
| T3.5 | Credential harvesting | Reads `*_KEY`, `*_TOKEN`, `*_SECRET` env vars at install |

### T4 — Agent-Specific Risks

| ID | Threat | v0.1.0 coverage |
|----|--------|-----------------|
| T4.1 | Prompt-injected install | Heuristic: flags package names in quoted/code-block patterns in `context_hint` |
| T4.2 | Excessive tool permissions | Posture report: tool risk classification |
| T4.3 | Context exfiltration risk | Posture report: sensitive env var detection |

### Severity and response defaults

| Severity | CVSS range | Default response |
|----------|-----------|-----------------|
| CRITICAL | ≥ 9.0 | `block` |
| HIGH | 7.0–8.9 | `warn_confirm` |
| MEDIUM | 4.0–6.9 | `async_report` |
| LOW | 0.1–3.9 | `ignore` |
| INFO | 0.0 | `ignore` |

All defaults are overridable per severity, ecosystem, or rule ID in `config.toml`.

---

## Installation

```bash
pip install agentshield
```

**Python 3.11+ required.**

### Optional extras

```bash
# Static analysis (semgrep + bandit) — needed for --deep flag
pip install agentshield[static-analysis]

# Hermes Agent integration
pip install agentshield[hermes]

# OpenClaw integration
pip install agentshield[openclaw]

# Everything
pip install agentshield[all]
```

---

## Quick start

```bash
# 1. Scan a package (online — hits OSV + NVD + GitHub Advisory)
agentshield scan requests==2.28.0 --ecosystem pypi

# 2. Deep scan — download wheel and run static analysis
agentshield scan some-new-package --ecosystem pypi --deep

# 3. Populate local database for offline use (~2–5 min first run)
agentshield cache warm

# 4. Generate a security posture report
agentshield posture

# 5. Start the MCP server (any MCP-compatible agent connects to this)
agentshield serve --mcp
```

**Exit codes for `agentshield scan`:** `0` = ALLOW/WARN/LOG_ASYNC, `1` = BLOCK.

---

## Configuration

AgentShield looks for config at `~/.config/agentshield/config.toml`. Create it to override defaults.

### Full config reference

```toml
# ── Response defaults (by severity) ──────────────────────────────────────────
[defaults]
critical = "block"        # ALLOW | BLOCK | WARN_CONFIRM | ASYNC_REPORT
high     = "warn_confirm"
medium   = "async_report"
low      = "ignore"
info     = "ignore"

# ── Per-ecosystem overrides ───────────────────────────────────────────────────
[ecosystems.pypi]
high = "block"            # Stricter than default for pip installs

[ecosystems.npm]
high     = "warn_confirm"
critical = "block"

[ecosystems.cargo]
critical = "block"
high     = "warn_confirm"

# ── Per-rule-ID overrides (highest priority) ──────────────────────────────────
[rules]
  [rules."T1.1"]    # Known-malicious: always block, regardless of severity
  mode = "block"

  [rules."T1.2"]    # Typosquatting: always block
  mode = "block"

  [rules."T2.3"]    # Transitive CVEs: only log, don't block
  mode = "async_report"

  [rules."T3.1"]    # Shell execution at install time
  mode = "warn_confirm"

  [rules."T3.5"]    # Credential harvesting: block
  mode = "block"

  [rules."T4.1"]    # Prompt injection heuristic: confirm before allowing
  mode = "warn_confirm"

# ── Allowlist / denylist ─────────────────────────────────────────────────────
[allowlist]
# Packages that bypass all checks (trusted internal packages, etc.)
packages = ["numpy", "requests", "pytest", "boto3"]

[denylist]
# Packages that are always blocked regardless of findings
packages = ["malicious-pkg-example", "colouredlogs"]

# ── API keys ─────────────────────────────────────────────────────────────────
[api]
# Also accepted via environment variables NVD_API_KEY and GITHUB_TOKEN
nvd_api_key  = ""    # Increases NVD rate limit from 5→50 req/30s
github_token = ""    # Required for GitHub Advisory Database (GraphQL)

# ── Cache settings ────────────────────────────────────────────────────────────
[cache]
db_path   = "~/.agentshield/agentshield.db"
ttl_hours = 24
max_entries = 50000

# ── Reporting ─────────────────────────────────────────────────────────────────
[reporting]
report_dir          = "~/.agentshield/reports/"
auto_report_on_exit = true
```

### Response modes

| Mode | CLI identifier | Behaviour |
|------|---------------|-----------|
| Block | `block` | Refuse install. Returns error to agent. Agent cannot proceed. |
| Warn & confirm | `warn_confirm` | Present findings to user. Require explicit approval before allowing. Agent pauses. |
| Async report | `async_report` | Allow install unconditionally. Record findings for the next `posture` report. |
| Ignore | `ignore` | Skip this check entirely. No scan overhead. |

### Priority resolution

When a finding arrives, AgentShield looks up the response mode in this order (first match wins):

```
1. rule-level override      [rules."T1.2"] mode = "block"
2. ecosystem-level override [ecosystems.pypi] high = "block"
3. global severity default  [defaults] high = "warn_confirm"
   │
   (denylist check: always BLOCK regardless of above)
   (allowlist check: always ALLOW, skips the scan entirely)
```

### API keys

| Key | Where | Effect |
|-----|-------|--------|
| `NVD_API_KEY` | env var or `[api]` | NVD rate limit: 5 req/30s → 50 req/30s. Get one at [nvd.nist.gov/developers](https://nvd.nist.gov/developers/request-an-api-key) |
| `GITHUB_TOKEN` | env var or `[api]` | Enables GitHub Advisory Database. Any classic PAT with no scopes works. [github.com/settings/tokens](https://github.com/settings/tokens) |

AgentShield works without either key — OSV has no rate limit and covers most PyPI/npm/Rust packages.

---

## CLI reference

### `agentshield scan`

Scan a single package for vulnerabilities.

```
agentshield scan <package> [OPTIONS]

Arguments:
  package    Package name, optionally with version: requests==2.28.0
             npm: lodash@4.17.20   cargo: serde

Options:
  -e, --ecosystem [pypi|npm|cargo]   Default: pypi
  -c, --config    PATH               Path to config.toml (default: ~/.config/agentshield/config.toml)
  --deep                             Download wheel and run static analysis (semgrep + bandit + AST)
  --offline                          Local DB only — no network calls
```

**Output:** Rich table of findings with severity, CVSS score, title, source, and remediation hint. Decision (ALLOW / BLOCK / NEEDS_CONFIRMATION / LOG_ASYNC) printed with colour coding.

**Exit codes:** `0` = allow/warn/log, `1` = block.

**Progress indicator:** A spinner appears automatically for scans taking > 2 seconds. Deep scans show a distinct "downloading + analyzing" message.

```bash
# Examples
agentshield scan requests==2.28.0
agentshield scan lodash@4.17.20 --ecosystem npm
agentshield scan serde --ecosystem cargo
agentshield scan unknown-pkg --deep
agentshield scan known-pkg --offline
agentshield scan pkg -c /custom/config.toml
```

### `agentshield posture`

Generate a security posture report for the current environment.

```
agentshield posture [OPTIONS]

Options:
  -f, --format   [terminal|json|html|markdown]   Output format (default: terminal)
  -o, --output   PATH                            Write to file (terminal format ignores this)
  -t, --tools    TEXT                            Comma-separated agent tool names to classify
      --log-hours INT                            Hours of async report log to include (default: 24)
      --skip-packages                            Skip installed-package CVE scan (faster, async log only)
  -c, --config   PATH                            Path to config.toml
```

```bash
agentshield posture                                        # rich terminal
agentshield posture --format json                         # JSON to stdout
agentshield posture --format html -o report.html          # self-contained HTML file
agentshield posture --format markdown > report.md         # Markdown
agentshield posture --tools bash,read_file,web_search     # with tool risk classification
agentshield posture --skip-packages                       # async log only (fast)
agentshield posture --log-hours 72                        # last 3 days of async log
```

### `agentshield cache`

Manage the local scan cache and CVE mirror.

```
agentshield cache <action> [OPTIONS]

Actions:
  stats   Show cache statistics (entry counts, CVE mirror size)
  clear   Delete all cached scan results
  warm    Download OSV bulk exports and populate local DB
          Options: --ecosystems pypi,npm,cargo  (default: all)

Options:
  -c, --config PATH
```

```bash
agentshield cache stats
agentshield cache clear
agentshield cache warm
agentshield cache warm --ecosystems pypi,npm
```

`warm` downloads OSV advisory bulk exports and populates two tables:
- `cve_mirror` — MEDIUM+ CVEs for fast offline lookup
- `malicious_packages` — packages flagged `type=MALICIOUS` in OSV

### `agentshield serve`

Start the AgentShield daemon.

```
agentshield serve [OPTIONS]

Options:
  --mcp              Run as MCP stdio tool server (for any MCP-compatible agent)
  --socket PATH      Unix socket path (default: ~/.agentshield/agentshield.sock)
  -c, --config PATH
```

```bash
agentshield serve           # Unix socket JSON-RPC IPC daemon
agentshield serve --mcp     # MCP tool server on stdio
agentshield serve --socket /tmp/my.sock
```

---

## Framework integrations

### Hermes Agent — tool plugin

AgentShield registers as a Hermes tool plugin and intercepts `pip_install`, `npm_install`, and `cargo_add` calls before they execute.

**Install:**
```bash
pip install agentshield[hermes]
```

**Register in `hermes_config.yaml`:**
```yaml
plugins:
  - module: agentshield.integrations.hermes
    class: AgentShieldPlugin
    config:
      config_path: ~/.config/agentshield/config.toml
```

**Or in Python:**
```python
from agentshield.integrations.hermes import AgentShieldPlugin
from agentshield.core.config import Config

plugin = AgentShieldPlugin(config=Config.load())
# Register with Hermes runtime...
```

**Decision mapping:**

| AgentShield decision | Hermes result |
|---------------------|--------------|
| `ALLOW` | Original `ToolCall` passed through unmodified |
| `LOG_ASYNC` | Original `ToolCall` passed through; findings logged for posture report |
| `NEEDS_CONFIRMATION` | `ToolResult.needs_confirmation(message, on_confirm=call)` — Hermes surfaces to user |
| `BLOCK` | `ToolResult.error(reason)` — agent cannot proceed |

---

### OpenClaw — skill

AgentShieldSkill is a pre-condition skill that the OpenClaw kernel calls before any triggered install action.

**Install:**
```bash
pip install agentshield[openclaw]
```

**Register in `openclaw_config.yaml`:**
```yaml
skills:
  - module: agentshield.integrations.openclaw
    class: AgentShieldSkill
    triggers:
      - action_type: pip_install
      - action_type: npm_install
      - action_type: cargo_add
    config:
      config_path: ~/.config/agentshield/config.toml
```

**SkillResult fields:**
```python
SkillResult(
    allowed=True | False,   # False → OpenClaw blocks the action
    decision="ALLOW|...",   # DecisionAction string
    findings=[...],         # list[dict] — Finding.model_dump() for each finding
    message="reason",       # human-readable explanation
)
```

`LOG_ASYNC` → `allowed=True` (install proceeds, findings logged for posture report).

---

### MCP tool server

`agentshield serve --mcp` starts an MCP-compliant tool server on stdio. Any MCP-compatible framework (Claude, others) connects without a custom adapter — this is the fastest adoption path.

**MCP client configuration (e.g., Claude Desktop / Claude Code):**
```json
{
  "mcpServers": {
    "agentshield": {
      "command": "agentshield",
      "args": ["serve", "--mcp"]
    }
  }
}
```

**Exposed MCP tools:**

| Tool name | Description |
|-----------|-------------|
| `agentshield_scan` | Scan a package; returns decision, findings, max severity |
| `agentshield_posture` | Run posture check; returns full JSON report |

**`agentshield_scan` input schema:**
```json
{
  "package":      "string (required)  — package name",
  "ecosystem":    "pypi | npm | cargo (required)",
  "version":      "string (optional)  — pinned version",
  "deep":         "boolean (optional) — default false",
  "context_hint": "string (optional)  — why the agent wants this package (enables T4.1)"
}
```

**Response:**
```json
{
  "decision":        "ALLOW | BLOCK | NEEDS_CONFIRMATION | LOG_ASYNC",
  "reason":          "human-readable explanation",
  "max_severity":    "NONE | INFO | LOW | MEDIUM | HIGH | CRITICAL",
  "cache_hit":       true,
  "scan_duration_ms": 42,
  "findings": [
    {
      "rule_id":   "CVE-2023-12345",
      "title":     "Remote code execution in FooLib",
      "severity":  "CRITICAL",
      "cvss_score": 9.8,
      "source":    "osv",
      "remediation": "Upgrade to FooLib >= 2.1.0"
    }
  ]
}
```

---

### IPC daemon (Unix socket)

Without `--mcp`, `agentshield serve` starts a Unix domain socket JSON-RPC 2.0 server at `~/.agentshield/agentshield.sock`. Useful for shell scripts and Claude Code hooks that need AgentShield without Python startup cost on every call.

**Protocol — newline-delimited JSON:**
```json
// Request
{"jsonrpc": "2.0", "method": "scan",
 "params": {"package": "numpy", "ecosystem": "pypi"}, "id": 1}

// Response
{"jsonrpc": "2.0", "id": 1,
 "result": {"decision": "ALLOW", "findings": [], "cache_hit": true}}
```

**Available methods:** `scan`, `ping`.

**Shell client example:**
```bash
echo '{"jsonrpc":"2.0","method":"scan","params":{"package":"requests","ecosystem":"pypi"},"id":1}' \
  | nc -U ~/.agentshield/agentshield.sock
```

---

### Claude Code hooks *(post-v0.1.0)*

Claude Code's `PreToolUse` hook can invoke `agentshield hook` to intercept Bash commands. The hook connects to the `agentshield serve` daemon for < 5 ms latency per check, avoiding Python startup cost.

```bash
# .claude/settings.json
{
  "hooks": {
    "PreToolUse": "agentshield hook --tool $TOOL_NAME --input '$TOOL_INPUT'"
  }
}
# exit 0 = allow, exit 1 = block (reason on stderr)
```

---

## Posture reports

`agentshield posture` generates a point-in-time security assessment of your agent environment.

### What it scans

| Section | Coverage |
|---------|---------|
| **Installed packages** | Enumerates packages visible to `importlib.metadata`; checks each against local CVE mirror and malicious-package DB |
| **Risk score** | 0–100 score using tanh saturation formula (see below) |
| **Critical/high findings** | Package-level CVEs and malicious-package flags |
| **Attack surface** | Agent tools classified as high/medium/low risk |
| **Sensitive env vars** | Env vars matching `*_KEY`, `*_TOKEN`, `*_SECRET`, etc. (pattern match only — values never read) |
| **Async report log** | Packages installed under `async_report` mode within the reporting window |

### Risk scoring formula

```python
from math import tanh

score = (
    40 * tanh(critical_count       / 1.5)   # saturates near 40 around 3–4 criticals
  + 25 * tanh(high_count           / 2.0)   # saturates near 25 around 4–5 highs
  + 20 * tanh(medium_count         / 4.0)   # saturates near 20 around 8–10 mediums
  + 10 * tanh(low_count            / 8.0)   # saturates near 10 around 16+ lows
  +  5 * tanh(high_risk_tool_count / 3.0)   # up to +5 for dangerous tool config
)
# capped at 100
```

**Why tanh?** Each band has a maximum contribution (40+25+20+10+5 = 100), and `tanh(n/k)` gives fast initial growth then a plateau. The 5th critical finding adds much less marginal risk than the 1st. `k` sets how many findings reach ~76% of the band's maximum.

**Score thresholds:** 0–24 → LOW, 25–49 → MEDIUM, 50–74 → HIGH, 75–100 → CRITICAL.

### Tool risk classification

Pass `--tools` with comma-separated tool names active in your agent session:

| Risk level | Examples |
|-----------|---------|
| **High** | `bash`, `shell`, `run_code`, `execute_python`, `write_file`, `computer` |
| **Medium** | `web_search`, `read_file`, `browser`, `grep`, `find`, `list_directory` |
| **Low** | Everything else |

```bash
agentshield posture --tools bash,write_file,read_file,web_search,list_calendar
```

### Output formats

| Format | Command | Use case |
|--------|---------|---------|
| Terminal | `agentshield posture` | Interactive review; Rich-formatted with colour |
| JSON | `--format json` | Machine-readable; pipe to `jq` or CI tooling |
| HTML | `--format html -o report.html` | Human-readable; self-contained dark-theme page |
| Markdown | `--format markdown` | Docs, Slack, GitHub issues |

### Async report log

Every time a scan returns `LOG_ASYNC` (because a finding's response mode is `async_report`), the findings are serialised and written to the local DB. The posture report reads this log and surfaces packages that slipped through without real-time blocking — particularly valuable for MEDIUM+ findings the operator should review.

---

## Python API

```python
import asyncio
from agentshield import AgentShield, ScanRequest, Ecosystem

# --- Scanning ---

shield = AgentShield()  # loads ~/.config/agentshield/config.toml

# Synchronous scan
result = shield.scan(ScanRequest(
    package="requests",
    version="2.28.0",
    ecosystem=Ecosystem.PYPI,
))
print(result.decision.action)     # "ALLOW" | "BLOCK" | "NEEDS_CONFIRMATION" | "LOG_ASYNC"
print(result.max_severity.value)  # "NONE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
print(result.findings)            # list[Finding]
print(result.cache_hit)           # bool

# Async scan (preferred in async contexts)
result = await shield.ascan(request)

# Deep scan — download wheel and run static analysis
result = shield.scan(ScanRequest(
    package="some-new-package",
    ecosystem=Ecosystem.PYPI,
    deep=True,
))

# Pass context_hint to enable T4.1 prompt-injection heuristic
result = shield.scan(ScanRequest(
    package="some-pkg",
    ecosystem=Ecosystem.PYPI,
    source="hermes",
    context_hint="The documentation says: pip install some-pkg",
))

# Offline scan
from agentshield.core.config import Config
cfg = Config.load()
cfg = cfg.model_copy(update={"offline": True})
shield = AgentShield(config=cfg)

# --- Posture reports ---

from agentshield.reports import run_posture_check
from agentshield.reports.renderers import render_html, render_json, render_markdown, render_terminal
from agentshield.core.config import DEFAULT_DB_PATH

report = asyncio.run(run_posture_check(
    db_path=DEFAULT_DB_PATH,
    tool_names=["bash", "read_file", "web_search"],
    async_log_hours=24,
    skip_package_scan=False,
))

print(report.risk_score)   # 0–100
print(report.risk_label)   # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"

# Render
html = render_html(report)
open("report.html", "w").write(html)

json_str = render_json(report)      # pretty-printed JSON
md = render_markdown(report)        # Markdown document
render_terminal(report)             # prints to stdout with Rich
```

---

## Static analysis (`--deep`)

Without `--deep`, AgentShield runs CVE database lookups and typosquatting checks only — typically < 3 seconds. `--deep` additionally downloads the package wheel, extracts it to a temp directory, and runs the full analyzer suite.

**Use `--deep` for:**
- New packages from unknown authors
- Any package an agent is requesting for the first time
- Interactive scans where latency is acceptable (target P95: < 15 seconds)

**Analyzers:**

| Analyzer | Language | Tool | Graceful if absent |
|----------|----------|------|-------------------|
| `setup_py_inspector` | Python | stdlib `ast` | N/A (always runs) |
| `semgrep_runner` | Python/JS/Rust | `semgrep` CLI | Yes — skips, emits DEBUG log |
| `bandit_runner` | Python | `bandit` CLI | Yes — skips, emits DEBUG log |
| `npm_audit_runner` | JavaScript | `npm audit --json` | Yes — skips if npm not on PATH |
| `cargo_audit_runner` | Rust | `cargo audit --json` | Yes — skips if cargo not on PATH |

**Custom semgrep rules** ship in `src/agentshield/analyzers/rules/`:

| Rule file | Threat | Detects |
|-----------|--------|---------|
| `T3_1_shell_exec.yaml` | T3.1 | `subprocess`, `os.system`, `eval`, `exec` in install scripts |
| `T3_2_network_install.yaml` | T3.2 | `urllib.request`, `requests`, socket calls in install scripts |
| `T3_3_filesystem_write.yaml` | T3.3 | `open(path, "w")`, `shutil.copy` to sensitive directories |
| `T3_4_obfuscation.yaml` | T3.4 | `exec(base64.b64decode(...))`, marshal/zlib deobfuscation |
| `T3_5_credential_harvest.yaml` | T3.5 | `os.environ.get("*_TOKEN")`, `os.environ["*_KEY"]` |

---

## Offline mode

Three ways to activate:

```bash
agentshield scan pkg --offline                  # CLI flag
AGENTSHIELD_OFFLINE=1 agentshield scan pkg      # environment variable
# Or in config.toml: offline = true
```

Offline scans query only:
- `cve_mirror` table (populate with `agentshield cache warm`)
- `malicious_packages` table
- In-process typosquatting checker (no network)

Target latency: < 50 ms. Static analysis (`--deep`) is unavailable offline.

---

## Caching

All scan results are cached in a local SQLite database with severity-based TTLs:

| Max severity | Cache TTL |
|-------------|-----------|
| NONE (clean) | 7 days |
| INFO | 24 hours |
| LOW | 12 hours |
| MEDIUM | 6 hours |
| HIGH | 6 hours |
| CRITICAL | 3 hours |

The cache also stores a CVE mirror (populated by `agentshield cache warm`) and the async report log. All data is stored in `~/.agentshield/agentshield.db` by default.

```bash
agentshield cache stats    # show entry counts
agentshield cache clear    # delete all cached scan results
agentshield cache warm     # (re-)populate CVE mirror and malicious DB
```

---

## Contributing

```bash
git clone https://github.com/yourusername/agentshield
cd agentshield
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,static-analysis]"

# Run unit tests (no network required)
pytest tests/unit/

# Run integration tests (requires API keys)
NVD_API_KEY=... GITHUB_TOKEN=ghp_... pytest tests/integration/

# Lint and type-check
ruff check src/
mypy src/agentshield/
```

### Test structure

| Directory | What's tested | Network needed |
|-----------|--------------|---------------|
| `tests/unit/` | Core logic, cache, config, models, response engine, static analysis rules, posture scoring, renderers | No |
| `tests/integration/` | Real API calls (OSV, NVD, GitHub Advisory) | Yes |
| `tests/e2e/` | Full scan pipeline including IPC socket server | No |

### Fixture packages

`tests/fixtures/packages/` contains synthetic packages that trigger specific rules:

| Directory | Triggers |
|-----------|---------|
| `shell_exec/` | T3.1 |
| `network_at_install/` | T3.2 |
| `filesystem_write/` | T3.3 |
| `obfuscated_payload/` | T3.4 |
| `cred_harvester/` | T3.5 |
| `benign_package/` | None (false-positive baseline) |

### Environment variables

| Variable | Purpose |
|----------|---------|
| `NVD_API_KEY` | NVD API key (higher rate limit; enables NVD integration tests) |
| `GITHUB_TOKEN` | GitHub PAT (enables Advisory DB; integration tests) |
| `AGENTSHIELD_OFFLINE` | `1` to force offline mode without editing config |

---

## License

[MIT](LICENSE)
