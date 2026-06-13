# AgentShield

**Security layer for AI agent frameworks** — intercepts package installations, checks for vulnerabilities, and generates security posture reports. Local-first, framework-agnostic, no telemetry.

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](#)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](#)
[![Phase 4 — v0.1.0](https://img.shields.io/badge/status-v0.1.0-brightgreen)](#)

---

## What it does

When an AI agent (Hermes, OpenClaw, Claude Code, or any MCP-compatible framework) tries to install a package, AgentShield:

1. Checks against **three CVE databases** in parallel — OSV, NVD, GitHub Advisory
2. Detects **typosquatting** and **known-malicious packages** (offline-capable)
3. Runs the **T4.1 heuristic**: detects prompt-injected install requests
4. With `--deep`: downloads the wheel and runs **static analysis** — setup.py AST, semgrep, bandit, npm/cargo audit
5. Applies your configured **response policy** (block / warn+confirm / ignore / async-report)
6. Caches results locally for near-zero repeat latency
7. Aggregates **async-report** findings for the next `agentshield posture` run

---

## Quick start

```bash
pip install agentshield

# Scan a package (online — hits OSV + NVD + GitHub Advisory)
agentshield scan requests==2.28.0 --ecosystem pypi

# Deep scan: download wheel, run semgrep + bandit + AST inspector
agentshield scan some-new-package --ecosystem pypi --deep

# Scan without network (local DB populated by cache warm)
agentshield scan requests==2.28.0 --ecosystem pypi --offline

# Generate a posture report (terminal)
agentshield posture

# Generate an HTML report
agentshield posture --format html --output report.html

# Populate the local database (run once; ~2–5 min)
agentshield cache warm
```

---

## Table of Contents

- [Installation](#installation)
- [Configuration](#configuration)
- [CLI reference](#cli-reference)
- [Posture reports](#posture-reports)
- [Framework integrations](#framework-integrations)
- [Python API](#python-api)
- [Static analysis (--deep)](#static-analysis---deep)
- [Offline mode](#offline-mode)
- [Enrichment sources](#enrichment-sources)
- [Threat taxonomy](#threat-taxonomy)
- [Development](#development)

---

## Installation

```bash
pip install agentshield
```

For static analysis features (`--deep`):

```bash
pip install agentshield[static-analysis]   # adds bandit + semgrep
```

Requires Python 3.11+.

---

## Configuration

Create `~/.config/agentshield/config.toml`:

```toml
[defaults]
critical = "block"
high     = "warn_confirm"
medium   = "async_report"
low      = "ignore"
info     = "ignore"

[ecosystems.pypi]
# Stricter for pip installs
high = "block"

[ecosystems.npm]
high = "warn_confirm"

[rules]
  [rules."T1.1"]   # known-malicious: always block
  mode = "block"

  [rules."T1.2"]   # typosquatting: always block
  mode = "block"

  [rules."T2.3"]   # transitive CVEs: async report only
  mode = "async_report"

  [rules."T3.1"]   # shell execution at install time
  mode = "warn_confirm"

  [rules."T3.5"]   # credential harvesting
  mode = "block"

[allowlist]
packages = ["numpy", "requests", "pytest"]

[denylist]
packages = ["evil-pkg"]

[api]
nvd_api_key  = "your-nvd-key"    # or set NVD_API_KEY env var
github_token = "ghp_..."          # or set GITHUB_TOKEN env var

[cache]
db_path   = "~/.agentshield/agentshield.db"
ttl_hours = 24

[reporting]
report_dir          = "~/.agentshield/reports/"
auto_report_on_exit = true
```

### Response modes

| Mode | Identifier | Behaviour |
|------|-----------|-----------|
| Block | `block` | Refuse install; agent cannot proceed |
| Warn & confirm | `warn_confirm` | Show findings; require explicit user approval |
| Async report | `async_report` | Allow install; log findings for next posture report |
| Ignore | `ignore` | Skip this check entirely |

### Priority resolution

```
rule-level override
  ↓ (if not set)
ecosystem-level override
  ↓ (if not set)
global severity default
  ↑ (denylist always blocks — highest priority)
  ↓ (allowlist always allows — bypasses all checks)
```

### API keys (optional)

Without keys, AgentShield still works — OSV has no rate limits, and NVD allows 5 req/30s without a key.

| Key | Purpose | How to get |
|-----|---------|-----------|
| `NVD_API_KEY` | Increase NVD rate limit to 50 req/30s | [nvd.nist.gov/developers](https://nvd.nist.gov/developers/request-an-api-key) |
| `GITHUB_TOKEN` | GitHub Advisory Database (GraphQL) | [github.com/settings/tokens](https://github.com/settings/tokens) — any classic PAT, no scopes needed |

Supply via environment variables or in `[api]` section of `config.toml`.

---

## CLI reference

### `agentshield scan`

```
agentshield scan <package> [OPTIONS]

Arguments:
  package    Name with optional pinned version: requests==2.28.0

Options:
  -e, --ecosystem [pypi|npm|cargo]   Default: pypi
  -c, --config PATH                  Path to config.toml
  --deep                             Also run static analysis (wheel download + semgrep + bandit + AST)
  --offline                          Local DB only — no network calls
```

**Exit codes:** `0` = ALLOW / WARN / LOG_ASYNC, `1` = BLOCK

A progress spinner appears automatically for scans that take longer than 2 seconds.

```bash
# Examples
agentshield scan requests==2.28.0
agentshield scan lodash@4.17.20 --ecosystem npm
agentshield scan serde --ecosystem cargo
agentshield scan some-pkg --deep                  # + static analysis
agentshield scan some-pkg --offline               # local DB only
agentshield scan some-pkg -c /path/to/config.toml
```

### `agentshield posture`

Generate a security posture report for the current environment.

```
agentshield posture [OPTIONS]

Options:
  -f, --format [terminal|json|html|markdown]   Output format (default: terminal)
  -o, --output PATH                            Write to file instead of stdout
  -t, --tools TEXT                             Comma-separated tool names to classify
      --log-hours INT                          Hours of async report log to include (default: 24)
      --skip-packages                          Skip installed-package CVE scan (faster)
  -c, --config PATH                            Path to config.toml
```

```bash
# Examples
agentshield posture                                          # terminal output
agentshield posture --format json                           # JSON to stdout
agentshield posture --format html --output report.html      # HTML file
agentshield posture --format markdown > report.md           # Markdown to file
agentshield posture --tools bash,read_file,web_search       # classify tools
agentshield posture --skip-packages                         # async log only
agentshield posture --log-hours 72                          # last 3 days
```

### `agentshield cache`

```
agentshield cache stats                               # Show counts
agentshield cache clear                               # Delete scan results
agentshield cache warm [--ecosystems pypi,npm,cargo]  # Populate local DB
```

`cache warm` downloads OSV bulk exports and populates:
- `cve_mirror` — MEDIUM+ CVEs for offline lookup
- `malicious_packages` — packages flagged `type=MALICIOUS` in OSV

### `agentshield serve`

```
agentshield serve [OPTIONS]

Options:
  --mcp              Run as MCP tool server (stdio transport)
  --socket PATH      Unix socket path (default: ~/.agentshield/agentshield.sock)
  -c, --config PATH  Path to config.toml
```

Without `--mcp`: starts a Unix domain socket JSON-RPC 2.0 IPC server.  
With `--mcp`: starts an MCP tool server reading from stdin and writing to stdout.

---

## Posture reports

`agentshield posture` generates a point-in-time security assessment of your agent environment.

### What it checks

| Section | What it covers |
|---------|---------------|
| **Risk score** | Aggregated 0–100 score using tanh saturation formula |
| **Critical & High findings** | CVEs and malicious packages in installed libraries |
| **Attack surface** | Agent tools classified as high/medium/low risk |
| **Sensitive env vars** | Environment variables matching `*_KEY`, `*_TOKEN`, `*_SECRET`, etc. (values never read) |
| **Async report log** | Packages installed under `async_report` mode in the last 24h |

### Risk scoring

Risk score (0–100) uses a **tanh-based saturation formula** — each severity band contributes diminishing returns as the count grows:

```python
from math import tanh

score = (
    40 * tanh(critical_count       / 1.5) +   # saturates near 40 around 3–4 criticals
    25 * tanh(high_count           / 2.0) +   # saturates near 25 around 4–5 highs
    20 * tanh(medium_count         / 4.0) +   # saturates near 20 around 8–10 mediums
    10 * tanh(low_count            / 8.0) +   # saturates near 10 around 16+ lows
     5 * tanh(high_risk_tool_count / 3.0)     # up to +5 for dangerous tool config
)
```

**Thresholds:** 0–24 LOW, 25–49 MEDIUM, 50–74 HIGH, 75–100 CRITICAL.

### Output formats

```bash
agentshield posture                          # Rich terminal output
agentshield posture --format json            # Machine-readable JSON
agentshield posture --format html -o r.html  # Self-contained HTML (dark theme)
agentshield posture --format markdown        # Markdown document
```

### Tool risk classification

Pass `--tools` with a comma-separated list of tool names active in your agent session. AgentShield classifies them automatically:

| Risk level | Examples |
|-----------|---------|
| **High** | `bash`, `shell`, `write_file`, `execute_python`, `run_code`, `computer` |
| **Medium** | `web_search`, `read_file`, `browser`, `grep`, `find` |
| **Low** | Everything else |

```bash
agentshield posture --tools bash,read_file,web_search,list_calendar
```

### Async report log

When a scan decision is `LOG_ASYNC` (from the `async_report` response mode), the findings are written to a local database log. The posture report reads this log and surfaces any packages that slipped through without a real-time check — particularly useful for MEDIUM+ findings that should be reviewed.

---

## Framework integrations

### Hermes Agent — tool plugin

AgentShield registers as a Hermes tool plugin and intercepts `pip_install`, `npm_install`, and `cargo_add` calls before they execute.

```python
from agentshield.integrations.hermes import AgentShieldPlugin
```

Register in `hermes_config.yaml`:

```yaml
plugins:
  - module: agentshield.integrations.hermes
    class: AgentShieldPlugin
    config:
      config_path: ~/.config/agentshield/config.toml
```

| Decision | Hermes result |
|----------|--------------|
| `ALLOW` / `LOG_ASYNC` | Original `ToolCall` passed through unmodified |
| `NEEDS_CONFIRMATION` | `ToolResult.needs_confirmation(message, on_confirm=call)` |
| `BLOCK` | `ToolResult.error(reason)` — agent cannot proceed |

### OpenClaw — skill

AgentShieldSkill is a pre-condition skill that the OpenClaw kernel calls before any triggered install action.

```python
from agentshield.integrations.openclaw import AgentShieldSkill
```

Register in `openclaw_config.yaml`:

```yaml
skills:
  - module: agentshield.integrations.openclaw
    class: AgentShieldSkill
    triggers:
      - action_type: pip_install
      - action_type: npm_install
      - action_type: cargo_add
```

`SkillResult` fields: `allowed` (bool), `decision` (string), `findings` (list of Finding dicts), `message` (reason string).

`LOG_ASYNC` → `allowed=True` — install proceeds but findings are logged for the posture report.

### MCP tool server

`agentshield serve --mcp` starts an MCP-compliant tool server on stdio. Any MCP-compatible agent framework can call AgentShield without a custom integration layer.

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

| Tool | Description |
|------|-------------|
| `agentshield_scan` | Scan a package; returns `decision`, `findings`, `max_severity` |
| `agentshield_posture` | Security posture report (JSON format) |

`agentshield_scan` input schema:

```json
{
  "package":      "string (required)",
  "ecosystem":    "pypi | npm | cargo (required)",
  "version":      "string (optional)",
  "deep":         "boolean (default false)",
  "context_hint": "string (optional) — why the agent wants this package"
}
```

Response: JSON string with `decision`, `reason`, `max_severity`, `cache_hit`, `scan_duration_ms`, `findings`.

### IPC daemon

Without `--mcp`, `agentshield serve` starts a Unix domain socket JSON-RPC 2.0 server — useful for shell scripts and Claude Code hooks that need low latency without Python startup cost.

```bash
agentshield serve                               # default: ~/.agentshield/agentshield.sock
agentshield serve --socket /tmp/shield.sock    # custom path
```

**Protocol (newline-delimited JSON):**

```json
// Request
{"jsonrpc": "2.0", "method": "scan",
 "params": {"package": "numpy", "ecosystem": "pypi"}, "id": 1}

// Response
{"jsonrpc": "2.0", "id": 1,
 "result": {"decision": "ALLOW", "findings": [], "cache_hit": false}}
```

Available methods: `scan`, `ping`.

### Claude Code hooks _(post-v1)_

Claude Code's `PreToolUse` hook can invoke `agentshield hook` to intercept Bash commands. Connects to the `agentshield serve` daemon for < 5 ms per hook call. See PLAN.md §10.4.

---

## Python API

```python
from agentshield import AgentShield, ScanRequest, Ecosystem

# Synchronous scan (loads ~/.config/agentshield/config.toml by default)
shield = AgentShield()
result = shield.scan(ScanRequest(
    package="requests",
    version="2.28.0",
    ecosystem=Ecosystem.PYPI,
))

print(result.decision.action)   # ALLOW | BLOCK | NEEDS_CONFIRMATION | LOG_ASYNC
print(result.findings)          # list[Finding]
print(result.max_severity)      # Severity.NONE | LOW | MEDIUM | HIGH | CRITICAL

# Async scan (preferred in async contexts)
result = await shield.ascan(request)

# Deep scan with static analysis
result = shield.scan(ScanRequest(
    package="some-new-package",
    ecosystem=Ecosystem.PYPI,
    deep=True,
))

# Offline scan
from agentshield.core.config import Config
cfg = Config.load()
cfg = cfg.model_copy(update={"offline": True})
shield = AgentShield(config=cfg)
result = shield.scan(request)

# Posture check
import asyncio
from agentshield.reports import run_posture_check
from agentshield.core.config import DEFAULT_DB_PATH

report = asyncio.run(run_posture_check(
    db_path=DEFAULT_DB_PATH,
    tool_names=["bash", "read_file", "web_search"],
))
print(report.risk_score, report.risk_label)
print(report.critical_count, report.high_count)

# Render the report
from agentshield.reports.renderers import render_html, render_json, render_markdown
html = render_html(report)
Path("report.html").write_text(html)
```

---

## Static analysis (`--deep`)

Pass `--deep` to opt in to static analysis. This downloads the package wheel (or sdist), extracts it to a temporary directory, and runs the full analyzer suite. Without `--deep`, only CVE database lookups and typosquatting checks run.

**When to use `--deep`:**
- Interactive scans where latency is acceptable (target: < 15 seconds)
- Packages from unknown authors or new packages
- Any package installed at agent direction

**Latency targets:**

| Scan type | Target P95 |
|-----------|-----------|
| Default (CVE + typosquat) | < 3 seconds |
| `--deep` (+ wheel download + analysis) | < 15 seconds |
| `--offline` | < 50 ms |
| Cache hit | < 5 ms |

### Analyzers

| Analyzer | Detects | Tool |
|----------|---------|------|
| **setup.py AST inspector** | Install-time threats | stdlib `ast` |
| **semgrep runner** | T3.1–T3.5 patterns | `semgrep` CLI (graceful degradation) |
| **bandit runner** | Python security anti-patterns | `bandit` CLI (graceful degradation) |
| **npm audit runner** | npm vulnerabilities | `npm audit --json` (skips if not installed) |
| **cargo audit runner** | Rust crate vulnerabilities | `cargo audit` (skips if not installed) |

### Custom semgrep rules (T3.x)

| Rule file | Threat | Detects |
|-----------|--------|---------|
| `T3_1_shell_exec.yaml` | T3.1 | `subprocess`, `os.system`, `eval`, `exec` at install time |
| `T3_2_network_install.yaml` | T3.2 | `urllib.request`, `requests`, socket calls at install time |
| `T3_3_filesystem_write.yaml` | T3.3 | `open(path, "w")`, `shutil.copy` at install time |
| `T3_4_obfuscation.yaml` | T3.4 | `exec(base64.b64decode(...))` and deobfuscation chains |
| `T3_5_credential_harvest.yaml` | T3.5 | `os.environ.get("*_TOKEN")`, `os.environ["*_KEY"]` |

---

## Offline mode

Set `--offline` on the CLI, `offline = true` in config.toml, or `AGENTSHIELD_OFFLINE=1` in the environment.

Offline scans query only:
- Local `cve_mirror` table (populated by `cache warm`)
- Local `malicious_packages` table
- In-process typosquatting checker

Target latency: < 50ms. Static analysis (`--deep`) is not available offline (wheel download requires network).

---

## Enrichment sources

| Source | Ecosystem coverage | Notes |
|--------|--------------------|-------|
| **OSV.dev** | PyPI, npm, crates.io, Go, … | No rate limit; best structured data |
| **NVD API v2** | All CPEs | 5 req/30s (no key), 50/30s (with key) |
| **GitHub Advisory** | PyPI, npm, Rust, Go, … | Requires GitHub token; GraphQL |
| **Malicious DB** | PyPI, npm | Curated list + OSV `MALICIOUS` type |
| **Typosquatting** | All | Levenshtein distance vs top-N packages |

---

## Threat taxonomy

| ID | Name | Default scan | `--deep` |
|----|------|:-----------:|:--------:|
| T1.1 | Known-malicious package | ✓ | ✓ |
| T1.2 | Typosquatting | ✓ | ✓ |
| T2.1 | Critical CVE (CVSS ≥ 9.0) | ✓ | ✓ |
| T2.2 | High CVE (CVSS 7.0–8.9) | ✓ | ✓ |
| T2.3 | Transitive CVE | Planned | Planned |
| T3.1 | Shell execution at install time | — | ✓ |
| T3.2 | Network call at install time | — | ✓ |
| T3.3 | Filesystem write outside package dir | — | ✓ |
| T3.4 | Obfuscated/encoded payload | — | ✓ |
| T3.5 | Credential harvesting patterns | — | ✓ |
| T4.1 | Prompt-injected install | ✓ heuristic | ✓ heuristic |
| T4.2 | Excessive permissions | Posture report | Posture report |
| T4.3 | Context exfiltration risk | Posture report | Posture report |

### T4.1 prompt-injection heuristic

When a `ScanRequest` arrives with `context_hint`, AgentShield checks whether the package name appears in the hint in patterns consistent with copy-pasted external content rather than the agent's own reasoning:

- Quoted strings: `"package-name"` or `'package-name'`
- Backtick code: `` `package-name` `` or `` `pip install package-name` ``
- Fenced code blocks: ` ```pip install package-name``` `
- Markdown links: `[package-name](https://...)`
- Verbatim install commands: `pip install package-name`

When a pattern matches: **MEDIUM** severity, default response `warn_confirm`.

```python
ScanRequest(
    package="some-pkg",
    ecosystem=Ecosystem.PYPI,
    source="hermes",
    context_hint="The tool documentation says: pip install some-pkg",
)
# → Finding(rule_id="T4.1", severity=MEDIUM, ...)
```

---

## Development

```bash
git clone https://github.com/yourusername/agentshield
cd agentshield
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,static-analysis]"

# Run unit tests (no network required)
pytest tests/unit/

# Run integration tests (needs real API access)
NVD_API_KEY=... GITHUB_TOKEN=ghp_... pytest tests/ -m integration

# Lint
ruff check src/

# Type check
mypy src/agentshield/
```

### Testing static analysis rules

```bash
pytest tests/unit/test_static_analysis.py -v             # all static analysis tests
pytest tests/unit/test_static_analysis.py -k "fixture"   # T3.x fixture packages
pytest tests/unit/test_static_analysis.py -k "benign"    # false-positive baseline
```

### Testing posture reports

```bash
pytest tests/unit/test_risk_score.py -v    # risk scoring formula
pytest tests/unit/test_posture.py -v       # posture scanner, renderers, async log
```

### Fixture packages

`tests/fixtures/packages/` — synthetic packages that trigger each static analysis rule:

| Directory | Triggers |
|-----------|---------|
| `shell_exec/` | T3.1 — `subprocess.run` in `setup.py` |
| `network_at_install/` | T3.2 — `urllib.request.urlopen` in `setup.py` |
| `filesystem_write/` | T3.3 — `open(~/.ssh/..., "w")` in `setup.py` |
| `obfuscated_payload/` | T3.4 — `exec(base64.b64decode(...))` in `setup.py` |
| `cred_harvester/` | T3.5 — `os.environ.get("OPENAI_API_KEY")` in `setup.py` |
| `benign_package/` | No findings (false-positive baseline) |

### Environment variables for testing

| Variable | Purpose |
|----------|---------|
| `NVD_API_KEY` | NVD API key (higher rate limit + integration tests) |
| `GITHUB_TOKEN` | GitHub PAT (enables Advisory DB + integration tests) |
| `AGENTSHIELD_OFFLINE` | Set to `1` to force offline mode |

---

## Status

**v0.1.0 — all phases complete.**

| Phase | Status | Description |
|-------|--------|-------------|
| 0 | ✅ Done | Core engine, OSV client, typosquatting, cache, CLI |
| 1 | ✅ Done | NVD, GitHub Advisory, malicious DB, cache warm, offline mode |
| 2 | ✅ Done | Static analysis (`--deep`): semgrep, bandit, setup.py AST, npm/cargo audit |
| 3 | ✅ Done | Hermes plugin, OpenClaw skill, MCP server, IPC daemon, T4.1 heuristic |
| 4 | ✅ Done | Posture reports (HTML/JSON/Markdown/terminal), risk scoring, async log |

---

## License

MIT — see [LICENSE](LICENSE).
