# AgentShield container test scripts

Two scripts for exercising the full AgentShield enforcement stack inside a
container (the reference target is `alpine/arm64` managed via the macOS
`container` CLI, but both scripts are distro-aware / portable).

| Script | Purpose |
| --- | --- |
| `container_install_deps.sh` | Install every toolchain/runtime the harness needs so nothing is environment-skipped. |
| `container_e2e_test.sh` | Self-grading end-to-end harness that drives every enforcement layer with a known-bad sentinel and a known-good package, and prints a PASS/FAIL table. |
| `hermes_realtest.sh` | **Real-instance** test for a live Hermes box: loads the plugin through Hermes's own loader and drives its real `get_pre_tool_call_block_message` enforcement. FAILS if the `pre_tool_call` hook never fires. |
| `openclaw_realtest.sh` | **Real-instance** test for a live OpenClaw box: drives the plugin's registered `before_tool_call` handler + the real `agentshield` CLI verdict oracle, blocking a bad `exec` install and allowing a good one. FAILS if the hook never fires. |

## Real-instance tests (Hermes / OpenClaw)

`container_e2e_test.sh` exercises AgentShield's own enforcement surfaces. The two
`*_realtest.sh` scripts go further: they prove interception against the **real
agent runtimes** — the exact failure we were chasing was a plugin that loaded but
whose hook never fired, which only a real-runtime test catches.

```sh
# Hermes (run inside the Hermes box; install agentshield[hermes] + enable the
# plugin in ~/.hermes/config.yaml first):
HERMES_PY=~/.hermes/venv/bin/python ./scripts/hermes_realtest.sh

# OpenClaw (TypeScript/Node; install the Node plugin + the agentshield CLI first):
./scripts/openclaw_realtest.sh
# OpenClaw plugin unit tests (pure decision logic, offline):
cd integrations/openclaw && node --test
```

Both scripts write a deterministic AgentShield config (deny one sentinel, allow
one), run their checks, restore the config, and print a `PASS`/`FAIL` summary
(non-zero exit on any failure). Optional model-driven end-to-ends are gated
behind `HERMES_LLM_E2E=1` / `OPENCLAW_LLM_E2E=1`.

`openclaw_realtest.sh` also **auto-cleans prior agentshield installs** before
installing: it `rm -rf`s any stale `@agentshield-openclaw-plugin-*` extension dir
under `$OPENCLAW_HOME/extensions` (default `~/.openclaw`) and drops stale
`agentshield` / `@agentshield/openclaw-plugin` entries from `openclaw.json`. This
clears the "config invalid: plugin manifest requires configSchema" failure left
by an old manifest (which `openclaw doctor --fix` does not remove). It only ever
touches agentshield-related dirs/entries.

## Validated end-to-end flow

This is the exact sequence used to validate a clean run inside a real
`alpine/arm64` container managed by the macOS `container` CLI (result:
`SUMMARY: 78/78 passed, 0 skipped — ALL GRADED CHECKS PASSED.`). Adapt the
container engine (`docker`, `podman`, …) as needed — the scripts themselves are
distro-aware.

```sh
# 0. Copy the repo into the container so the harness can detect + reinstall it.
#    /work/AgentShield is one of the paths the harness auto-detects.
container cp . <container-id>:/work/AgentShield

# 1. Install AgentShield into the container (see "Installing AgentShield" below
#    for the externally-managed-Python / no-pip variants).
container exec -i <container-id> sh -c 'cd /work/AgentShield && pip install --break-system-packages .'

# 2. Provision the toolchains/runtimes the harness exercises.
container exec -i <container-id> sh < scripts/container_install_deps.sh

# 3. Run the harness.  The -i flag is REQUIRED.
container exec -i <container-id> sh < scripts/container_e2e_test.sh
```

> **`-i` is required.** Both scripts are fed to `sh` over **stdin**
> (`sh < script`). Without `container exec -i` the exec'd shell gets no stdin,
> so `sh` reads an empty program and exits silently — you'll see no output and
> no table, which looks like a hang or a no-op rather than an error. Always pass
> `-i` when piping a script in.

You can run the same scripts from *inside* an interactive container shell
without `-i` (stdin is already a TTY):

```sh
sh /work/AgentShield/scripts/container_install_deps.sh
sh /work/AgentShield/scripts/container_e2e_test.sh
```

## Installing AgentShield

The harness tests whatever `agentshield` build is on `PATH`. Install it from the
copied repo. Which command works depends on the image:

```sh
# Standard case — but on PEP 668 / externally-managed interpreters (Debian,
# Ubuntu, Alpine system Python) pip refuses a global install unless you opt in:
pip install --break-system-packages .

# Minimal Alpine images often ship `uv` but no `pip`. Install with uv instead
# (--system targets the system interpreter the harness uses):
uv pip install --system --reinstall --break-system-packages .

# If neither pip nor uv is present, bootstrap pip first, then retry the above:
python3 -m ensurepip --upgrade
python3 -m pip install --break-system-packages .
```

`container_install_deps.sh` (next section) also installs `python3`+`pip`, so
running it first is another way to get a working `pip`. The harness's own
section-1 "reinstall from repo" step is best-effort and does **not** pass
`--break-system-packages`, so on externally-managed systems do the install
yourself as above and let the harness simply test the build it finds.

## 1. Install dependencies

Run inside the container (as root, or with `sudo`):

```sh
sh scripts/container_install_deps.sh
# or from the host (note the required -i):
container exec -i <container-id> sh < scripts/container_install_deps.sh
```

It detects the package manager (`apk` / `apt-get` / `dnf` / `yum` / `pacman` /
`zypper`) and installs the C toolchain, `bash`, `python3`+`pip`, `node`+`npm`,
`ruby`, and `go` from the distro; then installs `rust`/`cargo` (rustup), `uv`,
`yarn`, `pnpm`, `pipx`, `poetry`, `bun`, and `micromamba` via their official
cross-distro installers. It is idempotent, prints an
`installed / skipped / failed` summary, and exits non-zero if a hard requirement
(C compiler, `bash`, `python3`) is still missing.

Caveats it reports automatically: `bun` and `micromamba`/conda need glibc and are
**skipped on musl (Alpine)** — install `gcompat` or use a glibc base image if you
need those two tools present. This is an *install* skip, not a harness skip:
`guard-scan-cmd` (and the hook) parse command strings rather than executing the
real package managers, so the bun/conda **grading cases still run and pass**
without those binaries installed. After the installer runs you may need to add
the installer bin dirs to `PATH`:

```sh
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$HOME/.bun/bin:$HOME/bin:$PATH"
```

> The harness only strictly needs the C compiler (execve build) and `bash` (shim
> wrappers); `guard-scan-cmd` parses commands rather than executing the real
> package managers, so most ecosystem tools are for realism/coverage, not hard
> requirements. With the C compiler, `bash`, and network present you should see
> **0 harness skips** and a full table (the validated run was `78/78`).

## 2. Run the harness

```sh
sh scripts/container_e2e_test.sh
# or from the host (note the required -i):
container exec -i <container-id> sh < scripts/container_e2e_test.sh
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
  - Hermes plugin interception via the real `register(ctx)` + `pre_tool_call`
    path (terminal/execute_code/shell tool names + structured tools +
    self-verify-registered + fail-closed arg-key). (OpenClaw is a Node plugin —
    see `openclaw_realtest.sh` / `integrations/openclaw`, not this harness.)
  - `guard-scan-cmd` across all 15 managers + absolute-path + `command X`
  - conda trusted vs untrusted channels
  - general fail-closed (unverifiable manager, unanalyzable args)
  - **Claude Code / Codex `PreToolUse` hook** (`agentshield hook`): bad →
    `permissionDecision: "deny"`, good → allow (empty exit-0), unverifiable
    manager + shell-expansion fail-closed, the `--agent codex` dialect, and a
    malformed payload that must **not** block
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

Per-feature `PASS`/`FAIL`/`SKIP` lines, a final `RESULT TABLE`, then a summary.
On a fully-provisioned container with network the validated result is:

```
SUMMARY: 78/78 passed, 0 skipped — ALL GRADED CHECKS PASSED.
```

The general form is `SUMMARY: <passed>/<total> passed, <skipped> skipped — ALL
GRADED CHECKS PASSED.` (the exact case count moves as the harness grows). Exit
code is `0` when there are no failures, non-zero otherwise (failures are also
reprinted loudly in a `!!! FAILURES !!!` section). `SKIP`s are
environment-gated: missing C compiler (execve build), missing `bash` (shim
wrappers), or no network (proxy transitive resolution) — run
`container_install_deps.sh` first, and ensure the container has network, to
reach the 0-skip full table above.
