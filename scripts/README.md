# AgentShield container test scripts

Two scripts for exercising the full AgentShield enforcement stack inside a
container (the reference target is `alpine/arm64` managed via the macOS
`container` CLI, but both scripts are distro-aware / portable).

| Script | Purpose |
| --- | --- |
| `container_install_deps.sh` | Install every toolchain/runtime the harness needs so nothing is environment-skipped. |
| `container_e2e_test.sh` | Self-grading end-to-end harness that drives every enforcement layer with a known-bad sentinel and a known-good package, and prints a PASS/FAIL table. |

## 1. Install dependencies

Run inside the container (as root, or with `sudo`):

```sh
sh scripts/container_install_deps.sh
# or from the host:
container exec <container-id> sh < scripts/container_install_deps.sh
```

It detects the package manager (`apk` / `apt-get` / `dnf` / `yum` / `pacman` /
`zypper`) and installs the C toolchain, `bash`, `python3`+`pip`, `node`+`npm`,
`ruby`, and `go` from the distro; then installs `rust`/`cargo` (rustup), `uv`,
`yarn`, `pnpm`, `pipx`, `poetry`, `bun`, and `micromamba` via their official
cross-distro installers. It is idempotent, prints an
`installed / skipped / failed` summary, and exits non-zero if a hard requirement
(C compiler, `bash`, `python3`) is still missing.

Caveats it reports automatically: `bun` and `micromamba`/conda need glibc and are
skipped on musl (Alpine) — install `gcompat` or use a glibc base image if you
need them. After it runs you may need to add the installer bin dirs to `PATH`:

```sh
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$HOME/.bun/bin:$HOME/bin:$PATH"
```

> The harness only strictly needs the C compiler (execve build) and `bash` (shim
> wrappers); `guard-scan-cmd` parses commands rather than executing the real
> package managers, so most ecosystem tools are for realism/coverage, not hard
> requirements.

## 2. Run the harness

```sh
sh scripts/container_e2e_test.sh
# or from the host:
container exec <container-id> sh < scripts/container_e2e_test.sh
```

What it does:

- Reports the installed AgentShield version/commit, and reinstalls from the repo
  if it is mounted in the container (otherwise prints a note and tests the
  installed build).
- Sets up deterministic state: clears the scan cache, inserts a **known-bad
  sentinel** into the local `malicious_packages` table (the real malicious-
  detection mechanism — works for pypi/npm/cargo), and temporarily backs up +
  removes any warmed offline CVE rows for the **known-good** packages so the
  ALLOW path is deterministic. All of this is reverted on exit (trap).
- Runs every layer with bad-sentinel (expect **BLOCK**) and good-package (expect
  **ALLOW**) cases, self-grading each:
  - openclaw skill + Hermes plugin interception (all shell tool names +
    structured tools + self-verify-registered + fail-closed)
  - `guard-scan-cmd` across all 15 managers + absolute-path + `command X`
  - conda trusted vs untrusted channels
  - general fail-closed (unverifiable manager, unanalyzable args)
  - PATH shim baseline
  - execve `LD_PRELOAD` interceptor (absolute-path / `command` / subprocess)
  - index proxy: env injection + block/allow + transitive-dependency block
  - posture scan

### Determinism notes

- Runs with `AGENTSHIELD_OFFLINE=1` so verdicts never depend on the network.
- Unsets `AGENTSHIELD_SESSION_ID` so the per-session scan rate limiter
  (`max_packages_per_hour`, default 20, which BLOCKs once tripped) cannot
  accumulate across the many CLI invocations.
- The transitive-dependency test needs network for dependency resolution
  (pypi.org); it is skipped with a clear note if offline.

### What a fully-passing run looks like

Per-feature `PASS`/`FAIL`/`SKIP` lines, a final `RESULT TABLE`, then:

```
SUMMARY: N/N passed, K skipped — ALL GRADED CHECKS PASSED.
```

Exit code is `0` when there are no failures, non-zero otherwise (failures are
also reprinted loudly in a `!!! FAILURES !!!` section). `SKIP`s are
environment-gated: missing C compiler (execve build), missing `bash` (shim
wrappers), or no network (proxy transitive resolution) — run
`container_install_deps.sh` first to eliminate the toolchain-related skips.
