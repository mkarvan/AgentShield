# AgentShield Roadmap

## v0.1.0 (current)

Core security middleware with CVE scanning (OSV, NVD, GitHub Advisory), typosquatting detection, malicious package database, prompt injection heuristics, and optional deep static analysis. Integrations: Hermes plugin, MCP server, CLI, shell wrappers.

### v0.1.1 — Security hardening (done)

- Zip-slip protection in wheel extractor (`--deep` mode)
- Persistent BLOCK cache — malicious packages stay blocked even when enrichment sources are unavailable
- Shell command parsing hardened against `$VAR`, `${VAR}`, `$(cmd)`, `git+` URL bypasses
- Uniform HTTP error handling across all DB clients
- NVD false positive filtering via word-boundary matching and CPE configuration validation

## v0.2.0 — Planned

### Dependency & lockfile scanning

- `scan_file("requirements.txt")` / `scan_file("package.json")` mode — scan all packages in a manifest at once
- Transitive dependency scanning — resolve and scan the full dependency tree, not just the top-level package
- SBOM generation and lockfile auditing

### Performance

- Concurrent batch warm-up for `malicious_db._fetch_malicious_from_osv()` — currently sequential HTTP per package; use `asyncio.gather` with semaphore
- Pre-normalize malicious package list at load time — currently lowercases on every `check()` call; pre-build a `set` for O(1) lookup
- `_SEVERITY_ORDER` as int mapping — `_max_severity()` currently does linear `.index()` on every call

### Integration completeness

- `agentshield_posture` MCP endpoint — currently returns "not yet implemented"
- Claude Code integration — currently a stub `__init__.py`
- IPC socket authentication — no auth on the Unix domain socket; add peer-credential validation or document the limitation

### Testing gaps

- `wheel_extractor` test coverage (zip-slip tests added in v0.1.1, but broader extraction scenarios needed)
- GitHub Advisory client standalone tests
- IPC server tests

### Other

- `prompt_injection.py` is sync while everything else is async — align the interface
- Clarify `DecisionAction.NEEDS_CONFIRMATION` vs `WARN_CONFIRM` distinction in docs
- PyPI publishing (blocked by name conflict — `agentshield` taken by another maintainer)
- Curated malicious package list expansion — current list is static and incomplete
- `--deep` mode supply chain risk documentation — downloading packages for analysis has inherent risk
