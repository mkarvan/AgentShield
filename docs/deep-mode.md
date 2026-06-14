# Deep Mode (`--deep`) — Supply Chain Risks and Mitigations

## What `--deep` does

When you pass `--deep` to `agentshield scan` (or set `deep: true` in a scan
request), AgentShield goes beyond CVE database lookups and runs static analysis
directly against the package source code using Bandit and Semgrep.

To do this, AgentShield must **download and extract the package** from the
registry into a temporary directory before analysis.  This is the core tension:
the tool designed to protect you from malicious packages must briefly *fetch*
the package before it can evaluate it.

> **Scope: PyPI only.** Deep static analysis is currently implemented for the
> PyPI ecosystem. For npm and cargo, `--deep` is a no-op beyond the standard
> checks: it emits an informational `DEEP.UNSUPPORTED` finding (severity `INFO`,
> source `deep_scan`) and skips extraction. CVE/advisory coverage for those
> ecosystems still comes from the online checks (OSV / NVD / GitHub Advisory).

## Inherent risks

### 1. Download-time execution

Some malicious packages run code during installation or even during extraction.
Specifically:

- **`setup.py` execution** — `pip download` (used internally) can trigger
  `setup.py` code when building a source distribution (sdist).  AgentShield
  uses `--no-deps --no-build-isolation` flags to minimise this, but it cannot
  fully prevent execution if the tarball's `setup.py` hooks fire during
  metadata extraction.

- **Malicious archive payloads** — A crafted wheel or tarball could contain
  files with names designed to escape the temporary directory (path traversal).
  AgentShield applies a zip-slip guard and uses Python 3.12+'s
  `tarfile.extractall(filter="data")` (with a manual guard on 3.11) to block
  this, but defence-in-depth at the OS level (see mitigations below) is
  recommended.

- **Symlink attacks** — Malicious archives can include symlinks pointing
  outside the extraction directory.  The zip-slip guard rejects these.

### 2. Network exposure

Deep mode downloads the full package tarball or wheel.  For a compromised or
typosquatted package, this transfers potentially hostile bytes to disk and
introduces network-request metadata (IP address, timing) that a sophisticated
attacker could observe.

### 3. Resource exhaustion

A zip bomb or deeply-nested archive could exhaust disk space or CPU during
extraction.  Each download is capped at `max_wheel_mb_per_session` (default
500 MB) and aborts mid-stream once the cap is exceeded, and the cumulative
per-session total is enforced by the rate limiter.  Extraction runs in a
temporary directory and catches `OSError`, but the *decompressed* size is not
yet bounded — a high-ratio archive within the download cap could still expand
significantly.

## Mitigations built into AgentShield

| Risk | Mitigation |
|------|-----------|
| Path traversal (zip-slip) | Member path validated against extraction root before extraction |
| `setup.py` execution | Downloads use `--no-deps --no-build-isolation`; sdist extraction skips `setup.py` |
| Symlink escape | Symlinks outside the target directory are rejected |
| Malicious `tar` entries | Python 3.12 `filter="data"` or manual tar-slip guard on 3.11 |
| Oversized download | Download capped at `max_wheel_mb_per_session` (aborts mid-stream); per-session total enforced by the rate limiter |

## Recommended additional mitigations

1. **Run in a sandbox.** Execute `agentshield scan --deep` inside a container
   or VM with no access to production credentials, secrets, or persistent
   network routes.  A read-only bind-mount of the host filesystem stops most
   exfiltration attempts cold.

2. **Revoke ambient credentials before scanning.** Unset `AWS_*`, `GCP_*`,
   `GITHUB_TOKEN`, and similar environment variables before invoking deep mode.
   A malicious `setup.py` that runs during extraction could read and exfiltrate
   them before AgentShield's static analysis even starts.

3. **Use `--offline` for pre-vetted packages.** If you have already downloaded
   and cached a clean copy of a package, combine `--offline` with a warmed
   local DB (`agentshield cache warm`) to avoid re-downloading.

4. **Prefer shallow mode for CI pipelines.** In automated pipelines the
   default (no `--deep`) mode — which uses only CVE DB lookups, typosquatting
   detection, and malicious-package matching — is usually sufficient and avoids
   the download risk entirely.  Reserve `--deep` for interactive pre-commit
   reviews of new or unfamiliar dependencies.

5. **Limit filesystem permissions.** Run the AgentShield process as a
   dedicated user with a `TMPDIR` on a separate, quota-limited filesystem so
   that a zip bomb cannot fill the root partition.

## Summary

`--deep` mode provides substantially higher-signal findings (static AST
analysis catches obfuscated payloads that CVE lookups miss), but it requires
downloading and briefly hosting potentially hostile code.  The risks are
manageable with the mitigations above; the key principle is *never run deep
mode with production credentials in scope*.
