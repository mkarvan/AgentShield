# AgentShield GitHub Action

The `agentshield-action` is a composite GitHub Action that scans manifest files changed in a pull request, posts a markdown security report as a PR comment, and optionally fails the build when blocked packages are found.

## Quick start

Add a workflow file to your repository:

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on:
  pull_request:
    paths:
      - "**/requirements*.txt"
      - "**/package*.json"
      - "**/Cargo.toml"
      - "**/Cargo.lock"
      - "**/pyproject.toml"
      - "**/Pipfile.lock"

jobs:
  agentshield:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write   # needed to post PR comments
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: ./.github/action/agentshield-action
        with:
          check-licenses: "true"
          fail-on: HIGH
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `manifests` | Comma-separated glob patterns for manifest files to scan | All supported types |
| `check-licenses` | Enable license compliance checking (denylist mode: GPL, AGPL, SSPL…) | `false` |
| `fail-on` | Minimum severity that causes the action to fail: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` | `CRITICAL` |
| `deep` | Run deep static analysis (semgrep, bandit) — slower but more thorough | `false` |
| `transitive` | Resolve and scan transitive (indirect) dependencies | `false` |
| `github-token` | GitHub token for posting PR comments | `${{ github.token }}` |

## Outputs

| Output | Description |
|--------|-------------|
| `blocked` | Number of packages blocked |
| `warned` | Number of packages with warnings |
| `total` | Total packages scanned |
| `report` | Full markdown report text |

## Examples

### Scan only Python manifests with license checks

```yaml
- uses: ./.github/action/agentshield-action
  with:
    manifests: "**/requirements*.txt,**/pyproject.toml"
    check-licenses: "true"
    fail-on: HIGH
```

### Full scan including transitive deps and deep analysis

```yaml
- uses: ./.github/action/agentshield-action
  with:
    deep: "true"
    transitive: "true"
    fail-on: CRITICAL
```

### Soft mode — warn but never fail the build

```yaml
- uses: ./.github/action/agentshield-action
  with:
    fail-on: NONE   # never exit non-zero, just post the report
```

### Access scan results in downstream steps

```yaml
- id: shield
  uses: ./.github/action/agentshield-action

- name: Summarize
  run: |
    echo "Blocked: ${{ steps.shield.outputs.blocked }}"
    echo "Total scanned: ${{ steps.shield.outputs.total }}"
```

## PR comment

When a scan runs on a pull request, the action posts (or updates) a comment with the full markdown report. The comment is identified by an HTML marker so it is updated in place on re-runs rather than creating a new comment each time.

The comment includes:

- Aggregate decision (ALLOW / WARN / BLOCK) per manifest file
- Per-package table with severity, findings count, and status
- Critical and high findings with descriptions and remediation hints
- License violations (when `check-licenses: true`)

## Supported manifest formats

| File | Ecosystem |
|------|-----------|
| `requirements*.txt` | PyPI |
| `pyproject.toml` | PyPI |
| `Pipfile.lock` | PyPI |
| `package.json` | npm |
| `package-lock.json` | npm |
| `Cargo.toml` | Cargo |
| `Cargo.lock` | Cargo |

## Configuration

The action respects an `agentshield.toml` (or `~/.config/agentshield/config.toml`) in the repository root for advanced policy configuration:

```toml
[license_policy]
mode = "denylist"
denied = ["GPL-3.0-only", "AGPL-3.0-only", "SSPL-1.0"]

[rate_limits]
max_packages_per_hour = 100   # increase for large monorepos
max_wheel_mb_per_session = 2000
```

See the main [README](../README.md) for full configuration options.
