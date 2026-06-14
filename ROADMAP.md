# AgentShield Roadmap

## v0.1.0

Core security middleware with CVE scanning (OSV, NVD, GitHub Advisory), typosquatting detection, malicious package database, prompt injection heuristics, and optional deep static analysis. Integrations: Hermes plugin, MCP server, CLI, shell wrappers.

### v0.1.1 — Security hardening (done)

- Zip-slip protection in wheel extractor (`--deep` mode)
- Persistent BLOCK cache — malicious packages stay blocked even when enrichment sources are unavailable
- Shell command parsing hardened against `$VAR`, `${VAR}`, `$(cmd)`, `git+` URL bypasses
- Uniform HTTP error handling across all DB clients
- NVD false positive filtering via word-boundary matching and CPE configuration validation

## v0.2.0 (done)

### Dependency & lockfile scanning (done)

- `scan_file("requirements.txt")` / `scan_file("package.json")` mode — scan all packages in a manifest at once
- Transitive dependency scanning — resolve and scan the full dependency tree via PyPI, npm, and crates.io APIs
- `--transitive` / `-T` CLI flag and `transitive_depth` parameter (default depth 3)

### Performance (done)

- Concurrent batch warm-up for `malicious_db._fetch_malicious_from_osv()` — `asyncio.gather` with `Semaphore(5)`
- Pre-normalized malicious package list as `frozenset[str]` for O(1) lookup
- `_SEVERITY_RANK` as int mapping — O(1) severity comparison

### Integration completeness (done)

- `agentshield_posture` MCP endpoint — wired to real `run_posture_check()` with `tool_names`, `log_hours`, `skip_packages` parameters
- `agentshield_scan_file` MCP endpoint — scan manifest files via MCP

### Testing gaps (done)

- `wheel_extractor` broader extraction scenarios (9 new tests: multi-file wheel, corrupted archive, sdist extraction, zip-format sdist, unknown format, end-to-end download paths)
- GitHub Advisory client standalone tests (8 new tests: Cargo ecosystem, rate-limit handling, malformed responses, missing fields, severity defaults, reference filtering)
- IPC server tests (17 new tests: dispatch-level ping/scan/error handling, real Unix socket lifecycle, malformed JSON, multi-request connections, graceful disconnect)

### v0.2.1 — Hardening (done)

- Python 3.11 compatibility: tarfile.extractall `filter="data"` crashes on 3.11 (added in 3.12). Added version check with manual tar-slip guard fallback.
- IPC `_handle_scan` now returns `transitive_results` (consistent with MCP endpoint)
- Replaced third-party `toml` with stdlib `tomllib` (available since 3.11)
- Tightened bare `except Exception` in `_check_sqlite` and `_cvss3_base_score` — now catches specific exceptions and logs errors
- Fixed `_load_curated()` cache bypass in `malicious_db.warm()` — uses instance cache instead of re-reading JSON from disk
- Added exponential backoff with jitter for 429/5xx responses in OSV and deps resolver
- Shared `httpx.AsyncClient` across deps resolver hops for connection pooling

## v0.3.0 (done)

### Testing (done)

- Renderer test coverage — 62 new tests for Terminal, JSON, HTML, and Markdown renderers (0% → 97%)

### Code quality (done)

- Claude Code stub now raises `NotImplementedError` on import with actionable message
- `prompt_injection.py` converted to async interface; scanner and all tests updated

### Security (done)

- IPC socket authentication — SO_PEERCRED on Linux, LOCAL_PEERCRED on macOS, shared-secret token fallback on other platforms. 28 new tests.

### Features (done)

- SBOM generation — CycloneDX v1.4 JSON output with PURL identifiers and vulnerability mapping. CLI `agentshield sbom`, MCP tool `agentshield_sbom`. 40 new tests.
- Curated malicious package list expanded from ~68 to ~120+ entries across PyPI and npm

### Documentation (done)

- `DecisionAction` docstring clarifying `NEEDS_CONFIRMATION` vs `WARN_CONFIRM` and the `ResponseMode→DecisionAction` mapping
- `docs/deep-mode.md` documenting `--deep` mode supply chain risks and mitigations

## v0.4.0 — Planned

- PyPI publishing (blocked by name conflict — `agentshield` taken by another maintainer)

## v0.5.0 (done)

### License compliance scanning (done)

- `LicensePolicy` config section — four modes: `disabled` (default), `denylist`, `allowlist`, `permissive-only`
- Default denied list: GPL-2.0, GPL-3.0, AGPL-3.0, SSPL-1.0, EUPL-1.1, OSL-3.0
- License metadata fetched from PyPI JSON API (Trove classifiers + `info.license`), npm registry, crates.io API
- SPDX identifier normalization: alias table (GPLv2 → GPL-2.0-only, etc.), OR/AND/WITH expression splitting, Cargo "/" style
- `Finding` with rule_id `L1.1`: CRITICAL for GPL/AGPL/SSPL, HIGH for LGPL/EUPL/OSL/MPL
- `--check-licenses` CLI flag on `agentshield scan` — enables denylist mode ad-hoc without editing config
- `check_licenses` MCP tool parameter for `agentshield_scan`
- Wired into `scanner._run_checks` alongside other analyzers (runs in parallel via `asyncio.gather`)

### pre-commit hook (done)

- `.pre-commit-hooks.yaml` at repo root — hook id `agentshield-scan`, entry `agentshield scan-file`
- Triggers on: `requirements*.txt`, `Pipfile.lock`, `package-lock.json`, `package.json`, `Cargo.lock`, `Cargo.toml`, `pyproject.toml`
- `docs/pre-commit.md` with setup and configuration instructions

## v0.6.0 — Planned

### GitHub Action

- `agentshield-action` — runs `agentshield scan-file` on changed manifest files in a PR
- Posts a markdown report as a PR comment using the existing Markdown renderer

### Drift detection

- Track ALLOW→BLOCK transitions for packages across scans
- Surface drift events on next `agentshield scan` or `agentshield posture`
- Store transition history in SQLite alongside the scan cache

### Agent behavior rate limits

- Per-session limits: max packages per hour, max wheel download size per session
- Session state persisted in SQLite
- Configurable via `[rate_limits]` section in `config.toml`

## v0.7.0 — Planned

### Diff scan mode

- `agentshield diff-scan old.txt new.txt` — scan only packages added or changed between two manifest snapshots
- Useful in CI: scan the delta on a PR rather than the full manifest

### Trust score / reputation system

- Composite score from: PyPI/npm download count, publication age, prior scan history, maintainer account age
- Surfaces as a `Finding` with rule_id `T5.1` when trust score falls below threshold

### Container / Docker scanning

- Parse `Dockerfile` `RUN pip install` / `RUN npm install` / `RUN cargo install` lines
- Treat as a virtual manifest and run `scan-file`-style batch scan

### HTTP daemon mode

- `agentshield serve --http` — FastAPI server on `localhost:PORT`, REST API complement to IPC socket
- Useful for non-Python agent runtimes and web-based dashboards

### `agentshield guard`

- Interactive shell wrapper that intercepts `pip`, `npm`, and `cargo` in real-time
- Wraps the user's shell; every install command goes through AgentShield before execution
