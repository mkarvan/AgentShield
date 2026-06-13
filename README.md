# AgentShield

Security layer for AI agent frameworks that intercepts package installations and checks for vulnerabilities before agents can use them.

## What it does

When an AI agent (Hermes, OpenClaw, or Claude Code) tries to install a package, AgentShield:

1. Checks the package against CVE databases (NVD, OSV, GitHub Advisory)
2. Detects typosquatting and known-malicious packages
3. Runs static analysis on the package source
4. Applies your configured response policy (block / warn+confirm / ignore / async-report)

## Quick start

```bash
pip install agentshield

# Scan a package
agentshield scan requests==2.28.0 --ecosystem pypi

# Generate a posture report for your agent environment
agentshield posture --format html --output report.html

# Warm the local cache (first-run setup)
agentshield cache warm
```

## Configuration

Create `~/.config/agentshield/config.toml`:

```toml
[defaults]
critical = "block"
high     = "warn_confirm"
medium   = "async_report"
low      = "ignore"

[allowlist]
packages = ["numpy", "requests", "pytest"]
```

See [PLAN.md](PLAN.md) for full architecture documentation and [docs/config.md](docs/config.md) for the complete configuration reference.

## Framework integrations

- **Hermes Agent** — `pip install agentshield[hermes]`
- **OpenClaw** — `pip install agentshield[openclaw]`
- **Claude Code** — see [docs/claude-code-hooks.md](docs/claude-code-hooks.md)

## Status

Pre-release. See [PLAN.md](PLAN.md) for the development roadmap.
