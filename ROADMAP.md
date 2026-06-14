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

## v0.3.0

### Testing (done)

- Renderer test coverage — 62 new tests for Terminal, JSON, HTML, and Markdown renderers (0% → 97%)

### Code quality (done)

- Claude Code stub now raises `NotImplementedError` on import with actionable message
- `prompt_injection.py` converted to async interface; scanner and all tests updated

### Remaining — Planned

- IPC socket authentication — add SO_PEERCRED check or shared secret
- SBOM generation and lockfile auditing
- Curated malicious package list expansion — current list is static and incomplete
- Clarify `DecisionAction.NEEDS_CONFIRMATION` vs `WARN_CONFIRM` distinction in docs
- `--deep` mode supply chain risk documentation — downloading packages for analysis has inherent risk
- PyPI publishing (blocked by name conflict — `agentshield` taken by another maintainer)
