"""exec interception — closes the absolute-path / PATH-reset gap (Linux + macOS).

The PATH shim (:mod:`agentshield.enforce.shim`) only catches invocations that
resolve through ``PATH``.  An agent calling ``/usr/bin/pip install …`` directly,
or one that resets ``PATH``, slips past it.  This module generates a small
injected library that hooks the ``exec`` family: when a *managed* binary is about
to be executed, it first runs ``agentshield guard-scan-cmd <argv>`` (which fails
closed); a non-zero exit aborts the exec with ``EACCES``.

Platforms:
* **Linux** — an ``LD_PRELOAD`` ``.so`` that overrides ``execve``/``execvp``/
  ``execv`` and chains to the real symbols via ``dlsym(RTLD_NEXT, …)``.
* **macOS** — a ``DYLD_INSERT_LIBRARIES`` ``.dylib`` using dyld *interposing*
  (``__DATA,__interpose``).  Calls made from the interposing image itself are
  not re-interposed, so each replacement chains to the real ``exec`` by name.

Scope / caveats:
* A C compiler (``cc``) is required; ``build`` raises otherwise.
* Linux ``LD_PRELOAD`` covers dynamically linked executables; static/setuid
  binaries are not covered.  On macOS, **SIP** strips ``DYLD_INSERT_LIBRARIES``
  for system binaries (``/usr/bin``, ``/bin``, …), so this covers user/Homebrew/
  pyenv-installed managers (``/usr/local``, ``/opt/homebrew``, ``~/.pyenv``) —
  which is where agent installs almost always run — but not Apple-shipped ones.
  A kernel-level EndpointSecurity agent would be required to cover SIP-protected
  binaries; that needs a signed, entitled, root-installed system extension and is
  out of scope for a pip-installable tool.
* In-process installs (``pip`` used as a Python API) are not exec events; the
  index proxy (:mod:`agentshield.enforce.proxy`) covers that vector.

The verdict logic is **not** reimplemented here; the injected library shells out
to ``agentshield guard-scan-cmd`` so coverage and policy stay single-sourced.
"""

from __future__ import annotations

import platform
import shutil
import subprocess
import sys
from pathlib import Path

from agentshield.enforce.registry import shadow_binaries

# Basenames the interceptor should gate on. Anything else is exec'd untouched.
MANAGED_BINARIES: tuple[str, ...] = shadow_binaries()


def is_macos(target: str | None = None) -> bool:
    return (target or platform.system()) == "Darwin"


def is_linux(target: str | None = None) -> bool:
    return (target or platform.system()) == "Linux"


def is_managed(argv0: str) -> bool:
    """True if *argv0* (path or bare name) is a managed package-manager binary."""
    import os

    return os.path.basename(argv0) in MANAGED_BINARIES


def c_source(target: str | None = None) -> str:
    """Return the C source for the interceptor for *target* (default: host OS)."""
    entries = ",\n    ".join(f'"{b}"' for b in MANAGED_BINARIES)
    common = _C_COMMON.replace("/*__MANAGED__*/", entries)
    hooks = _C_MAC_HOOKS if is_macos(target) else _C_LINUX_HOOKS
    return common + hooks


def library_name(target: str | None = None) -> str:
    return "libagentshield_exec.dylib" if is_macos(target) else "libagentshield_exec.so"


def default_library_path(target: str | None = None) -> Path:
    return Path.home() / ".agentshield" / library_name(target)


def build(dest: Path | None = None, *, agentshield_bin: str = "agentshield") -> Path:
    """Compile the interceptor for the **host** platform and return its path.

    Raises ``RuntimeError`` on unsupported platforms or when no C compiler is
    available.
    """
    system = platform.system()
    if system not in ("Linux", "Darwin"):
        raise RuntimeError(
            f"exec interception is supported on Linux and macOS only; host is {system}. "
            "Use the PATH shim instead."
        )
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        raise RuntimeError("no C compiler (cc/gcc/clang) found on PATH; cannot build interceptor")

    out = Path(dest) if dest else default_library_path()
    out.parent.mkdir(parents=True, exist_ok=True)
    src = out.with_suffix(".c")
    src.write_text(c_source())
    if is_macos():
        cmd = [cc, "-dynamiclib", "-fPIC", "-O2", "-o", str(out), str(src)]
    else:
        cmd = [cc, "-shared", "-fPIC", "-O2", "-o", str(out), str(src), "-ldl"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"compilation failed:\n{proc.stderr}")
    return out


def preload_env_var(so_path: Path | None = None, *, target: str | None = None) -> str:
    """Name of the dynamic-linker injection env var for the platform/library."""
    macos = so_path.suffix == ".dylib" if so_path is not None else is_macos(target)
    return "DYLD_INSERT_LIBRARIES" if macos else "LD_PRELOAD"


def preload_env_line(so_path: Path) -> str:
    """Shell line that activates the interceptor for the current session."""
    var = preload_env_var(so_path)
    return f'export {var}="{so_path}:${{{var}}}"'


# ── C sources ─────────────────────────────────────────────────────────────────

# Common: managed-binary table, basename check, and the scan-subprocess helper.
# Portable across Linux and macOS (fork/execvp/waitpid/basename are POSIX).
_C_COMMON = r"""
/* AgentShield exec interceptor — generated; do not edit. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <libgen.h>

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

/* Run `agentshield guard-scan-cmd <base> <args...>`; return 1 to allow, 0 block. */
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
"""

# Linux: override the exec symbols and chain to the real ones via dlsym.
_C_LINUX_HOOKS = r"""
#include <dlfcn.h>

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

# macOS: dyld interposing. Calls from this image are not re-interposed, so each
# replacement chains to the real exec by name.
_C_MAC_HOOKS = r"""
static int as_execve(const char *path, char *const argv[], char *const envp[]) {
    if (as_is_managed(path) && !as_scan_ok(path, argv)) { errno = EACCES; return -1; }
    return execve(path, argv, envp);
}
static int as_execvp(const char *file, char *const argv[]) {
    if (as_is_managed(file) && !as_scan_ok(file, argv)) { errno = EACCES; return -1; }
    return execvp(file, argv);
}
static int as_execv(const char *path, char *const argv[]) {
    if (as_is_managed(path) && !as_scan_ok(path, argv)) { errno = EACCES; return -1; }
    return execv(path, argv);
}

typedef struct { const void *replacement; const void *replacee; } as_interpose_t;
__attribute__((used)) static const as_interpose_t _as_interposers[]
    __attribute__((section("__DATA,__interpose"))) = {
    { (const void *)as_execve, (const void *)execve },
    { (const void *)as_execvp, (const void *)execvp },
    { (const void *)as_execv,  (const void *)execv  },
};
"""


if __name__ == "__main__":  # pragma: no cover - manual build helper
    try:
        p = build()
    except RuntimeError as exc:
        print(f"build failed: {exc}", file=sys.stderr)
        sys.exit(1)
    print(f"built {p}")
    print(preload_env_line(p))
