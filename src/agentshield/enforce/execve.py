"""execve interception — closes the absolute-path / PATH-reset gap (Linux).

The PATH shim (:mod:`agentshield.enforce.shim`) only catches invocations that
resolve through ``PATH``.  An agent calling ``/usr/bin/pip install …`` directly,
or one that resets ``PATH``, slips past it.  This module generates an
``LD_PRELOAD`` library that hooks the ``exec`` family: when a *managed* binary
is about to be executed, it first runs ``agentshield guard-scan-cmd <argv>``
(which fails closed); a non-zero exit aborts the exec with ``EACCES``.

Scope / caveats:
* Linux + a C compiler (``cc``) are required; ``build`` raises otherwise.
* ``LD_PRELOAD`` only affects dynamically linked executables that honour it;
  static binaries and setuid programs are not covered.  For those, a
  ``ptrace``/``seccomp`` supervisor would be needed (future work).
* In-process installs (e.g. ``pip`` used as a Python API) are not exec events
  and cannot be seen here — the index proxy (:mod:`agentshield.enforce.proxy`)
  covers that vector.

The verdict logic is **not** reimplemented here; the preload shells out to
``agentshield guard-scan-cmd`` so coverage and policy stay single-sourced.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

from agentshield.enforce.registry import shadow_binaries

# Basenames the preload should gate on. Anything else is exec'd untouched.
MANAGED_BINARIES: tuple[str, ...] = shadow_binaries()


def is_managed(argv0: str) -> bool:
    """True if *argv0* (path or bare name) is a managed package-manager binary."""
    return os.path.basename(argv0) in MANAGED_BINARIES


def c_source() -> str:
    """Return the C source for the LD_PRELOAD interceptor (binary list embedded)."""
    entries = ",\n    ".join(f'"{b}"' for b in MANAGED_BINARIES)
    return _C_TEMPLATE.replace("/*__MANAGED__*/", entries)


def build(dest: Path | None = None, *, agentshield_bin: str = "agentshield") -> Path:
    """Compile the interceptor to a shared object and return its path.

    Raises ``RuntimeError`` on non-Linux platforms or when no C compiler is
    available.
    """
    if platform.system() != "Linux":
        raise RuntimeError(
            "execve interception via LD_PRELOAD is Linux-only; "
            f"current platform is {platform.system()}. Use the PATH shim instead."
        )
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        raise RuntimeError("no C compiler (cc/gcc/clang) found on PATH; cannot build interceptor")

    out = Path(dest) if dest else (Path.home() / ".agentshield" / "libagentshield_exec.so")
    out.parent.mkdir(parents=True, exist_ok=True)
    src = out.with_suffix(".c")
    src.write_text(c_source())
    cmd = [cc, "-shared", "-fPIC", "-O2", "-o", str(out), str(src), "-ldl"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"compilation failed:\n{proc.stderr}")
    return out


def preload_env_line(so_path: Path) -> str:
    """Shell line that activates the interceptor for the current session."""
    return f'export LD_PRELOAD="{so_path}:${{LD_PRELOAD}}"'


# The preload intercepts execve/execv/execvp. For a managed binary it spawns
# `agentshield guard-scan-cmd <basename> <args...>`; a non-zero exit blocks
# (sets errno=EACCES and returns -1 from exec). The real exec symbol is resolved
# via dlsym(RTLD_NEXT, ...).
_C_TEMPLATE = r"""
/* AgentShield execve interceptor — generated; do not edit. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <libgen.h>
#include <stdarg.h>

static const char *AS_MANAGED[] = {
    /*__MANAGED__*/
};
static const int AS_MANAGED_N = sizeof(AS_MANAGED) / sizeof(AS_MANAGED[0]);

static int as_is_managed(const char *path) {
    if (!path) return 0;
    char buf[4096];
    strncpy(buf, path, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    const char *base = basename(buf);
    for (int i = 0; i < AS_MANAGED_N; i++) {
        if (strcmp(base, AS_MANAGED[i]) == 0) return 1;
    }
    return 0;
}

/* Run `agentshield guard-scan-cmd <base> <args...>`; return 0 to allow. */
static int as_scan_ok(const char *path, char *const argv[]) {
    if (getenv("AGENTSHIELD_EXEC_DISABLE")) return 1;
    char buf[4096];
    strncpy(buf, path, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    const char *base = basename(buf);

    int argc = 0;
    while (argv[argc] != NULL) argc++;

    const char *as_bin = getenv("AGENTSHIELD_BIN");
    if (!as_bin) as_bin = "agentshield";

    /* Build: as_bin guard-scan-cmd base [argv[1..]] NULL */
    int n = argc + 3;
    char **cmd = (char **)calloc(n + 1, sizeof(char *));
    if (!cmd) return 1; /* allocation failure: do not hard-fail the exec */
    int k = 0;
    cmd[k++] = (char *)as_bin;
    cmd[k++] = (char *)"guard-scan-cmd";
    cmd[k++] = (char *)base;
    for (int i = 1; i < argc; i++) cmd[k++] = argv[i];
    cmd[k] = NULL;

    pid_t pid = fork();
    if (pid < 0) { free(cmd); return 1; }
    if (pid == 0) {
        /* Avoid recursive interception inside the scanner subprocess. */
        setenv("AGENTSHIELD_EXEC_DISABLE", "1", 1);
        execvp(as_bin, cmd);
        _exit(127); /* scanner missing: fail open so we don't brick the box */
    }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    free(cmd);
    if (WIFEXITED(status)) {
        int rc = WEXITSTATUS(status);
        if (rc == 127) return 1;      /* scanner not found -> allow */
        return rc == 0 ? 1 : 0;       /* 0 allow, nonzero block */
    }
    return 1;
}

typedef int (*as_execve_t)(const char *, char *const[], char *const[]);
typedef int (*as_execvp_t)(const char *, char *const[]);
typedef int (*as_execv_t)(const char *, char *const[]);

int execve(const char *path, char *const argv[], char *const envp[]) {
    static as_execve_t real = NULL;
    if (!real) real = (as_execve_t)dlsym(RTLD_NEXT, "execve");
    if (as_is_managed(path) && !as_scan_ok(path, argv)) { errno = EACCES; return -1; }
    return real(path, argv, envp);
}

int execvp(const char *file, char *const argv[]) {
    static as_execvp_t real = NULL;
    if (!real) real = (as_execvp_t)dlsym(RTLD_NEXT, "execvp");
    if (as_is_managed(file) && !as_scan_ok(file, argv)) { errno = EACCES; return -1; }
    return real(file, argv);
}

int execv(const char *path, char *const argv[]) {
    static as_execv_t real = NULL;
    if (!real) real = (as_execv_t)dlsym(RTLD_NEXT, "execv");
    if (as_is_managed(path) && !as_scan_ok(path, argv)) { errno = EACCES; return -1; }
    return real(path, argv);
}
"""


if __name__ == "__main__":  # pragma: no cover - manual build helper
    try:
        p = build()
    except RuntimeError as exc:
        print(f"build failed: {exc}", file=sys.stderr)
        sys.exit(1)
    print(f"built {p}")
    print(preload_env_line(p))
