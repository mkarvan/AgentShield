# AgentShield

Security layer for AI agent frameworks that intercepts package installations and checks for vulnerabilities before agents can use them.

## What it does

When an AI agent (Hermes, OpenClaw, Claude Code, or any MCP-compatible framework) tries to install a package, AgentShield:

1. Checks the package against **three CVE databases** in parallel — OSV, NVD, and GitHub Advisory
2. Detects **typosquatting** and **known-malicious packages** (offline-capable)
3. With `--deep`: downloads the wheel and runs **static analysis** — setup.py AST inspection, semgrep, and bandit — to catch install-time malware
4. Applies your configured **response policy** (block / warn+confirm / ignore / async-report)
5. Caches results locally to keep latency near zero on repeated scans

## Quick start

```bash
pip install agentshield

# Scan a package (online — hits OSV + NVD + GitHub Advisory)
agentshield scan requests==2.28.0 --ecosystem pypi

# Deep scan: download wheel and run static analysis
agentshield scan requests==2.28.0 --ecosystem pypi --deep

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

For static analysis features (`--deep`), also install the optional extras:

```bash
pip install agentshield[static-analysis]   # adds bandit + semgrep
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

  [rules."T3.1"]  # shell execution at install time
  mode = "warn_confirm"

  [rules."T3.5"]  # credential harvesting
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
  --deep                             Also run static analysis (download wheel + semgrep + bandit + AST)
  --offline                          Local DB only — no network calls
```

**Exit codes:** `0` = ALLOW / WARN / LOG_ASYNC, `1` = BLOCK

A **progress spinner** appears automatically for scans that take longer than 2 seconds. Deep scans show a distinct message indicating the wheel download and analysis phase.

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

## Static analysis (`--deep`)

Pass `--deep` to opt in to static analysis. This downloads the package wheel (or sdist), extracts it to a temporary directory, and runs the full analyzer suite. Without `--deep`, only CVE database lookups and typosquatting checks run.

**When to use `--deep`:**
- Interactive scans where latency is acceptable (target: < 15 seconds)
- Packages from unknown authors, new packages, or packages installed via agent
- When you want assurance beyond CVE databases

**Latency targets:**

| Scan type | Target P95 |
|-----------|-----------|
| Default (CVE + typosquat) | < 3 seconds |
| `--deep` (+ wheel download + analysis) | < 15 seconds |
| `--offline` | < 50 ms |
| Cache hit | < 5 ms |

### Analyzers

| Analyzer | What it detects | Tool |
|----------|----------------|------|
| **setup.py AST inspector** | Install-time threats in Python packages | stdlib `ast` — no external dependency |
| **semgrep runner** | T3.1–T3.5 patterns using custom YAML rules | `semgrep` CLI (graceful degradation if not installed) |
| **bandit runner** | Python security anti-patterns | `bandit` CLI (graceful degradation if not installed) |
| **npm audit runner** | npm vulnerabilities via lockfile | `npm audit --json` (skips if npm not found) |
| **cargo audit runner** | Rust crate vulnerabilities via Cargo.lock | `cargo audit --json` (skips if cargo not found) |

All analyzers degrade gracefully: if the required tool is not installed, the check is skipped and a `DEBUG`-level log is emitted rather than failing the scan.

### Custom semgrep rules (T3.x)

AgentShield ships five YAML rule files in `src/agentshield/analyzers/rules/`:

| Rule file | Threat ID | Detects |
|-----------|-----------|---------|
| `T3_1_shell_exec.yaml` | T3.1 | `subprocess`, `os.system`, `eval`, `exec` at install time |
| `T3_2_network_install.yaml` | T3.2 | `urllib.request`, `requests`, `httpx`, socket calls at install time |
| `T3_3_filesystem_write.yaml` | T3.3 | `open(path, "w")`, `shutil.copy` at install time |
| `T3_4_obfuscation.yaml` | T3.4 | `exec(base64.b64decode(...))`, marshal/zlib deobfuscation chains |
| `T3_5_credential_harvest.yaml` | T3.5 | `os.environ.get("*_TOKEN")`, `os.environ["*_KEY"]`, `os.environ.items()` |

### Fixture packages (test harness)

`tests/fixtures/packages/` contains synthetic packages that trigger each rule:

| Directory | Triggers |
|-----------|---------|
| `shell_exec/` | T3.1 — `subprocess.run` in `setup.py` |
| `network_at_install/` | T3.2 — `urllib.request.urlopen` in `setup.py` |
| `filesystem_write/` | T3.3 — `open(~/.ssh/..., "w")` in `setup.py` |
| `obfuscated_payload/` | T3.4 — `exec(base64.b64decode(...))` in `setup.py` |
| `cred_harvester/` | T3.5 — `os.environ.get("OPENAI_API_KEY")` in `setup.py` |
| `benign_package/` | No findings (false-positive baseline) |

## Offline mode

Set `--offline` on the CLI, `offline = true` in config.toml, or `AGENTSHIELD_OFFLINE=1` in the environment.

Offline scans query only:
- Local `cve_mirror` table (populated by `cache warm`)
- Local `malicious_packages` table
- In-process typosquatting checker (no network)

Target latency: < 50ms for a cached package. Static analysis (`--deep`) is not available in offline mode — wheel download requires network access.

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

# Deep scan with static analysis
result = shield.scan(ScanRequest(
    package="some-new-package",
    ecosystem=Ecosystem.PYPI,
    deep=True,
))

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
pip install -e ".[dev,static-analysis]"

# Run unit tests (no network required)
pytest tests/unit/

# Run integration tests (needs real API access)
NVD_API_KEY=... GITHUB_TOKEN=ghp_... pytest tests/ -m integration

# Lint
ruff check src/
```

### Testing static analysis rules

The fixture packages are self-contained and do not require network access:

```bash
# Run only static analysis tests
pytest tests/unit/test_static_analysis.py -v

# Verify all T3.x rules fire on their fixtures
pytest tests/unit/test_static_analysis.py -v -k "fixture"

# Verify no false positives on benign code
pytest tests/unit/test_static_analysis.py -v -k "benign"
```

### Environment variables for testing

| Variable | Purpose |
|----------|---------|
| `NVD_API_KEY` | NVD API key (higher rate limit + integration tests) |
| `GITHUB_TOKEN` | GitHub PAT (enables GitHub Advisory + integration tests) |
| `AGENTSHIELD_OFFLINE` | Set to `1` to force offline mode without editing config |

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
| T4.1 | Prompt-injected install | Heuristic (Phase 3) | Heuristic (Phase 3) |

## Status

**Phase 2 complete.** See [PLAN.md](PLAN.md) for the full roadmap.

| Phase | Status | Description |
|-------|--------|-------------|
| 0 | ✅ Done | Core engine, OSV client, typosquatting, cache, CLI |
| 1 | ✅ Done | NVD client, GitHub Advisory, malicious DB, cache warm, offline mode |
| 2 | ✅ Done | Static analysis (`--deep`): semgrep rules, bandit, setup.py AST, npm/cargo audit |
| 3 | Planned | Framework integrations (Hermes, OpenClaw, MCP server) |
| 4 | Planned | Posture reports (HTML/JSON/Markdown), risk scoring |
