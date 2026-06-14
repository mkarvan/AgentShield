# AgentShield pre-commit Hook

AgentShield ships a [pre-commit](https://pre-commit.com/) hook that scans manifest files for vulnerable or malicious packages before every commit.

## Requirements

- Python 3.11+
- `pre-commit` installed in your environment (`pip install pre-commit`)
- `agentshield` installed (see the main README for installation instructions)

## Setup

### 1. Add the hook to `.pre-commit-config.yaml`

```yaml
repos:
  - repo: https://github.com/mkarvan/AgentShield
    rev: v0.7.0          # pin to a specific tag or commit
    hooks:
      - id: agentshield-scan
```

### 2. Install the hooks

```bash
pre-commit install
```

### 3. Test it manually

```bash
pre-commit run agentshield-scan --all-files
```

## What gets scanned

The hook runs `agentshield scan-file` on any staged file matching:

| Pattern | Format |
|---------|--------|
| `requirements*.txt` | pip requirements |
| `Pipfile.lock` | Pipenv lockfile |
| `package.json` | npm package manifest |
| `package-lock.json` | npm lockfile |
| `Cargo.toml` | Rust/Cargo manifest |
| `Cargo.lock` | Rust/Cargo lockfile |
| `pyproject.toml` | PEP 517 / uv manifest |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | All packages ALLOW, WARN, or LOG_ASYNC — commit proceeds |
| `1` | One or more packages BLOCK — commit aborted |

## Configuration

The hook respects `~/.config/agentshield/config.toml`. You can tune response modes, add an allowlist, or configure a license policy there.

### Example: tighten policy for CI

Create `.agentshield.toml` in your repo root (or point to it via `--config`):

```toml
[defaults]
critical = "block"
high     = "block"   # stricter than default warn_confirm
medium   = "async_report"

[license_policy]
mode   = "denylist"
denied = ["GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later",
          "AGPL-3.0-only", "AGPL-3.0-or-later", "SSPL-1.0"]
```

Then reference it in `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/mkarvan/AgentShield
    rev: v0.7.0
    hooks:
      - id: agentshield-scan
        args: ["--config", ".agentshield.toml"]
```

### Example: allow specific packages

```toml
[allowlist]
packages = ["numpy", "pandas", "requests"]
```

## Offline mode

To avoid network calls in CI environments where the cache is pre-warmed:

```yaml
hooks:
  - id: agentshield-scan
    args: ["--offline"]
```

Pre-warm the cache in a separate CI step with `agentshield cache warm`.

## Skipping the hook

To skip for a single commit (not recommended):

```bash
SKIP=agentshield-scan git commit -m "emergency fix"
```
