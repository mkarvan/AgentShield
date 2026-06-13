# AgentShield

Security layer for AI agent frameworks that intercepts package installations and checks for vulnerabilities before agents can use them.

## What it does

When an AI agent (Hermes, OpenClaw, Claude Code, or any MCP-compatible framework) tries to install a package, AgentShield:

1. Checks the package against **three CVE databases** in parallel — OSV, NVD, and GitHub Advisory
2. Detects **typosquatting** and **known-malicious packages** (offline-capable)
3. Applies your configured **response policy** (block / warn+confirm / ignore / async-report)
4. Caches results locally to keep latency near zero on repeated scans

Static analysis (`--deep` flag, Phase 2) will add semgrep, bandit, and `setup.py` AST inspection.

## Quick start

```bash
pip install agentshield

# Scan a package (online — hits OSV + NVD + GitHub Advisory)
agentshield scan requests==2.28.0 --ecosystem pypi

# Scan without network (uses local DB populated by cache warm)
agentshield scan requests==2.28.0 --ecosystem pypi --offline

# Populate the local database (run once; takes up to 5 minutes)
agentshield cache warm

# Show cache statistics
agentshield cache stats

# Generate a posture report (Phase 4)
agentshield posture --format html --output report.html
```

## Setup

### 1. Install

```bash
pip install agentshield
```

### 2. (Optional) Configure API keys

Without keys, AgentShield still works — OSV has no rate limits, and NVD allows 5 req/30s without a key. Keys unlock higher NVD throughput and GitHub Advisory access.

**NVD API key** — increases the NVD rate limit from 5 → 50 req/30s.  
Register at: https://nvd.nist.gov/developers/request-an-api-key

**GitHub token** — required for the GitHub Advisory Database (GraphQL).  
Any classic PAT with no scopes works: https://github.com/settings/tokens

Supply keys via environment variables or `config.toml`:

```bash
export NVD_API_KEY="your-nvd-key"
export GITHUB_TOKEN="ghp_..."
```

Or in `~/.config/agentshield/config.toml`:
```toml
[api]
nvd_api_key = "your-nvd-key"
github_token = "ghp_..."
```

### 3. Warm the local cache (recommended)

Downloads OSV bulk exports for PyPI, npm, and crates.io and populates a local SQLite database with CVEs and known-malicious packages. Required for `--offline` mode.

```bash
agentshield cache warm                        # all ecosystems (~2–5 min)
agentshield cache warm --ecosystems pypi,npm  # specific ecosystems
```

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

[rules]
  [rules."T1.1"]  # known-malicious packages always block
  mode = "block"

  [rules."T1.2"]  # typosquatting always blocks
  mode = "block"

[allowlist]
packages = ["numpy", "requests", "pytest"]

[denylist]
packages = ["evil-pkg"]

[api]
nvd_api_key  = "your-nvd-key"   # or set NVD_API_KEY env var
github_token = "ghp_..."         # or set GITHUB_TOKEN env var

[cache]
db_path   = "~/.agentshield/agentshield.db"
ttl_hours = 24
```

### Response modes

| Mode | Action |
|------|--------|
| `block` | Refuse install; agent cannot proceed |
| `warn_confirm` | Show findings; require explicit user approval |
| `async_report` | Allow install; log for next posture report |
| `ignore` | Skip this check entirely |

### Priority resolution

```
rule-level override → ecosystem-level → global severity default
denylist always blocks (highest priority)
allowlist always allows (bypasses all checks)
```

## CLI reference

### `agentshield scan`

```
agentshield scan <package> [OPTIONS]

Arguments:
  package    Package name, optionally with pinned version: requests==2.28.0

Options:
  -e, --ecosystem [pypi|npm|cargo]   Default: pypi
  -c, --config PATH                  Path to config.toml
  --deep                             Also run static analysis (Phase 2)
  --offline                          Local DB only — no network calls
```

**Exit codes:** `0` = ALLOW / WARN / LOG_ASYNC, `1` = BLOCK

### `agentshield cache`

```
agentshield cache stats                              # Show counts
agentshield cache clear                              # Delete scan results
agentshield cache warm [--ecosystems pypi,npm,cargo] # Populate local DB
```

`cache warm` downloads OSV bulk exports and populates:
- `cve_mirror` — MEDIUM+ CVEs for offline lookup
- `malicious_packages` — packages flagged `type=MALICIOUS` in OSV

### `agentshield posture`

```
agentshield posture [--format terminal|json|html|markdown] [--output FILE]
```

_(Coming in Phase 4)_

## Offline mode

Set `--offline` on the CLI, `offline = true` in config.toml, or `AGENTSHIELD_OFFLINE=1` in the environment.

Offline scans query only:
- Local `cve_mirror` table (populated by `cache warm`)
- Local `malicious_packages` table
- In-process typosquatting checker (no network)

Target latency: < 50ms for a cached package.

## Enrichment sources

| Source | Ecosystem coverage | Notes |
|--------|--------------------|-------|
| **OSV.dev** | PyPI, npm, crates.io, Go, ... | No rate limit; best structured data |
| **NVD API v2** | All CPEs | 5 req/30s (no key), 50/30s (with key) |
| **GitHub Advisory** | PyPI, npm, Rust, Go, ... | Requires GitHub token; GraphQL |
| **Malicious DB** | PyPI, npm | Curated list + OSV `MALICIOUS` type |
| **Typosquatting** | All | Levenshtein distance vs top-N packages |

## Framework integrations

- **Hermes Agent** — `pip install agentshield[hermes]` (Phase 3)
- **OpenClaw** — `pip install agentshield[openclaw]` (Phase 3)
- **MCP server** — `agentshield serve --mcp` (Phase 3)
- **Claude Code hooks** — see docs (Phase 3)

## Python API

```python
from agentshield import AgentShield, ScanRequest, Ecosystem

# Synchronous scan
shield = AgentShield()  # loads ~/.config/agentshield/config.toml
result = shield.scan(ScanRequest(
    package="requests",
    version="2.28.0",
    ecosystem=Ecosystem.PYPI,
))

print(result.decision.action)   # ALLOW | BLOCK | NEEDS_CONFIRMATION | LOG_ASYNC
print(result.findings)          # list[Finding]

# Async scan (preferred in async contexts)
result = await shield.ascan(request)

# Offline scan
from agentshield.core.config import Config
cfg = Config.load()
cfg = cfg.model_copy(update={"offline": True})
shield = AgentShield(config=cfg)
result = shield.scan(request)
```

## Development

```bash
git clone https://github.com/yourusername/agentshield
cd agentshield
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Run unit tests (no network required)
pytest tests/unit/

# Run integration tests (needs real API access)
NVD_API_KEY=... GITHUB_TOKEN=ghp_... pytest tests/ -m integration

# Lint
ruff check src/
```

### Environment variables for testing

| Variable | Purpose |
|----------|---------|
| `NVD_API_KEY` | NVD API key (higher rate limit + integration tests) |
| `GITHUB_TOKEN` | GitHub PAT (enables GitHub Advisory + integration tests) |
| `AGENTSHIELD_OFFLINE` | Set to `1` to force offline mode without editing config |

## Threat taxonomy

| ID | Name | Source |
|----|------|--------|
| T1.1 | Known-malicious package | OSV malicious type + curated list |
| T1.2 | Typosquatting | Levenshtein distance checker |
| T2.1 | Critical CVE (CVSS ≥ 9.0) | OSV / NVD / GitHub Advisory |
| T2.2 | High CVE (CVSS 7.0–8.9) | OSV / NVD / GitHub Advisory |
| T2.3 | Transitive CVE | Planned |
| T3.x | Static analysis findings | `--deep` flag (Phase 2) |
| T4.1 | Prompt-injected install | Heuristic (Phase 3) |

## Status

**Phase 1 complete.** See [PLAN.md](PLAN.md) for the full roadmap.

| Phase | Status | Description |
|-------|--------|-------------|
| 0 | ✅ Done | Core engine, OSV client, typosquatting, cache, CLI |
| 1 | ✅ Done | NVD client, GitHub Advisory, malicious DB, cache warm, offline mode |
| 2 | Planned | Static analysis (`--deep`): semgrep, bandit, setup.py AST |
| 3 | Planned | Framework integrations (Hermes, OpenClaw, MCP server) |
| 4 | Planned | Posture reports (HTML/JSON/Markdown), risk scoring |
