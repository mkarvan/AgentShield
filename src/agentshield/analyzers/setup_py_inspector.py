"""AST-based inspector for setup.py and other install-time Python files.

Detects network calls, filesystem writes, shell execution, obfuscated payloads,
and credential harvesting that would execute at pip install time — without running
any external tools (pure stdlib AST).
"""

from __future__ import annotations

import ast
import logging
from pathlib import Path

from agentshield.core.models import Finding, ScanRequest, Severity

logger = logging.getLogger(__name__)

# Files executed or parsed at install time that we want to inspect
_INSTALL_TIME_FILES = {"setup.py", "setup.cfg", "pyproject.toml"}

# Patterns per threat category
_SHELL_FUNCS = {
    ("subprocess", "call"),
    ("subprocess", "run"),
    ("subprocess", "Popen"),
    ("subprocess", "check_call"),
    ("subprocess", "check_output"),
    ("subprocess", "getoutput"),
    ("subprocess", "getstatusoutput"),
    ("os", "system"),
    ("os", "popen"),
    ("os", "execv"),
    ("os", "execve"),
    ("os", "execvp"),
    ("os", "spawnl"),
    ("os", "spawnle"),
}

_BUILTINS_EXEC = {"eval", "exec", "compile"}

_NETWORK_FUNCS = {
    ("urllib", "request", "urlopen"),
    ("urllib", "urlopen"),
    ("requests", "get"),
    ("requests", "post"),
    ("requests", "put"),
    ("requests", "delete"),
    ("requests", "head"),
    ("requests", "request"),
    ("httpx", "get"),
    ("httpx", "post"),
    ("httpx", "put"),
    ("http", "client", "HTTPConnection"),
    ("http", "client", "HTTPSConnection"),
}

_SENSITIVE_PATHS = {
    "~/.ssh",
    "~/.aws",
    "~/.gnupg",
    "/etc/",
    "/usr/",
    "/bin/",
    "/sbin/",
}

_CRED_PATTERNS = {"TOKEN", "KEY", "SECRET", "PASSWORD", "PASS", "CRED", "AUTH", "API_KEY"}


class _ASTVisitor(ast.NodeVisitor):
    def __init__(self, source_file: str) -> None:
        self.source_file = source_file
        self.shell_exec_lines: list[int] = []
        self.network_lines: list[int] = []
        self.filesystem_write_lines: list[int] = []
        self.obfuscation_lines: list[int] = []
        self.cred_harvest_lines: list[int] = []

    def _attr_chain(self, node: ast.expr) -> tuple[str, ...]:
        if isinstance(node, ast.Name):
            return (node.id,)
        if isinstance(node, ast.Attribute):
            return self._attr_chain(node.value) + (node.attr,)
        return ()

    def visit_Call(self, node: ast.Call) -> None:
        chain = self._attr_chain(node.func)

        # T3.1 — shell execution
        if (
            len(chain) >= 2
            and chain[-2:] in {t[-2:] for t in _SHELL_FUNCS if len(t) >= 2}
            or len(chain) == 1
            and chain[0] in _BUILTINS_EXEC
        ):
            self.shell_exec_lines.append(node.lineno)

        # T3.2 — network
        if (
            len(chain) >= 2
            and chain[-2:] in {t[-2:] for t in _NETWORK_FUNCS if len(t) >= 2}
            or len(chain) >= 3
            and chain[-3:] in {t for t in _NETWORK_FUNCS if len(t) >= 3}
        ):
            self.network_lines.append(node.lineno)

        # T3.3 — filesystem writes: open(path, "w"/"wb"/"a"/"ab")
        if len(chain) == 1 and chain[0] == "open" and len(node.args) >= 2:
            mode_node = node.args[1]
            if (
                isinstance(mode_node, ast.Constant)
                and isinstance(mode_node.value, str)
                and any(c in mode_node.value for c in ("w", "a", "x"))
            ):
                self.filesystem_write_lines.append(node.lineno)
                # Also check if path string mentions sensitive dirs
                path_node = node.args[0]
                if isinstance(path_node, ast.Constant) and isinstance(path_node.value, str):
                    for sp in _SENSITIVE_PATHS:
                        if sp in path_node.value:
                            self.filesystem_write_lines.append(node.lineno)

        # T3.4 — obfuscation: exec/eval around base64/marshal/zlib
        if len(chain) == 1 and chain[0] in ("exec", "eval") and node.args:
            inner = node.args[0]
            if isinstance(inner, ast.Call):
                inner_chain = self._attr_chain(inner.func)
                if any(
                    "b64decode" in part or "decompress" in part or "loads" in part
                    for part in inner_chain
                ):
                    self.obfuscation_lines.append(node.lineno)

        # T3.5 — credential harvesting: os.environ.get("*_TOKEN") etc.
        if (
            len(chain) >= 3
            and chain[-3:] == ("os", "environ", "get")
            and node.args
            and isinstance(node.args[0], ast.Constant)
        ):
            key = str(node.args[0].value).upper()
            if any(p in key for p in _CRED_PATTERNS):
                self.cred_harvest_lines.append(node.lineno)
        if (
            len(chain) >= 2
            and chain[-2:] in {("os", "getenv"), ("os", "environ")}
            and node.args
            and isinstance(node.args[0], ast.Constant)
        ):
            key = str(node.args[0].value).upper()
            if any(p in key for p in _CRED_PATTERNS):
                self.cred_harvest_lines.append(node.lineno)
        # os.environ.items() / dict(os.environ)
        if len(chain) >= 3 and chain[-3:] == ("os", "environ", "items"):
            self.cred_harvest_lines.append(node.lineno)

        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        # os.environ["SECRET_KEY"]
        val_chain = self._attr_chain(node.value)
        if (
            len(val_chain) >= 2
            and val_chain[-2:] == ("os", "environ")
            and isinstance(node.slice, ast.Constant)
            and isinstance(node.slice.value, str)
        ):
            key = node.slice.value.upper()
            if any(p in key for p in _CRED_PATTERNS):
                self.cred_harvest_lines.append(node.lineno)
        self.generic_visit(node)


def _inspect_file(path: Path) -> _ASTVisitor | None:
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        logger.debug("AST parse error in %s: %s", path, exc)
        return None
    except Exception as exc:
        logger.debug("Could not read %s: %s", path, exc)
        return None

    visitor = _ASTVisitor(str(path))
    visitor.visit(tree)
    return visitor


def inspect_package_directory(package_dir: Path, request: ScanRequest) -> list[Finding]:
    """Inspect all install-time Python files in *package_dir* and return findings."""
    # Collect setup.py and any __init__.py / top-level .py files (install hooks)
    targets: list[Path] = []

    for fname in _INSTALL_TIME_FILES:
        candidate = package_dir / fname
        if candidate.exists():
            targets.append(candidate)

    # Recurse one level for nested setup.py (sdist unpacks into a subdirectory)
    for subdir in package_dir.iterdir():
        if not subdir.is_dir():
            continue
        for fname in _INSTALL_TIME_FILES:
            candidate = subdir / fname
            if candidate.exists() and candidate not in targets:
                targets.append(candidate)

    findings: list[Finding] = []
    for target in targets:
        if target.suffix not in (".py", ""):
            continue
        visitor = _inspect_file(target)
        if visitor is None:
            continue

        rel = target.relative_to(package_dir)

        if visitor.shell_exec_lines:
            findings.append(
                Finding(
                    rule_id="T3.1",
                    title="Shell execution detected at install time",
                    description=(
                        f"Shell/subprocess/exec calls found in {rel} at lines "
                        f"{visitor.shell_exec_lines}. These execute during 'pip install'."
                    ),
                    severity=Severity.HIGH,
                    source="setup_py_inspector",
                    references=[],
                    remediation="Inspect the package source before installing.",
                    metadata={"file": str(rel), "lines": visitor.shell_exec_lines},
                )
            )

        if visitor.network_lines:
            findings.append(
                Finding(
                    rule_id="T3.2",
                    title="Network call detected at install time",
                    description=(
                        f"Outbound network calls found in {rel} at lines "
                        f"{visitor.network_lines}. These execute during 'pip install'."
                    ),
                    severity=Severity.HIGH,
                    source="setup_py_inspector",
                    references=[],
                    remediation="Inspect the network targets before installing.",
                    metadata={"file": str(rel), "lines": visitor.network_lines},
                )
            )

        if visitor.filesystem_write_lines:
            findings.append(
                Finding(
                    rule_id="T3.3",
                    title="Filesystem write detected at install time",
                    description=(
                        f"File write operations found in {rel} at lines "
                        f"{visitor.filesystem_write_lines}. Writes outside the package "
                        "directory may modify system or user files."
                    ),
                    severity=Severity.MEDIUM,
                    source="setup_py_inspector",
                    references=[],
                    remediation="Verify the write targets are limited to the package directory.",
                    metadata={"file": str(rel), "lines": visitor.filesystem_write_lines},
                )
            )

        if visitor.obfuscation_lines:
            findings.append(
                Finding(
                    rule_id="T3.4",
                    title="Obfuscated/encoded payload detected",
                    description=(
                        f"Base64/marshal/zlib-encoded payloads executed via eval/exec in "
                        f"{rel} at lines {visitor.obfuscation_lines}."
                    ),
                    severity=Severity.CRITICAL,
                    source="setup_py_inspector",
                    references=[],
                    remediation="Do not install this package; review source immediately.",
                    metadata={"file": str(rel), "lines": visitor.obfuscation_lines},
                )
            )

        if visitor.cred_harvest_lines:
            findings.append(
                Finding(
                    rule_id="T3.5",
                    title="Credential harvesting pattern detected",
                    description=(
                        f"Reads of sensitive environment variables (*_KEY, *_TOKEN, *_SECRET, etc.) "
                        f"found in {rel} at lines {visitor.cred_harvest_lines}."
                    ),
                    severity=Severity.CRITICAL,
                    source="setup_py_inspector",
                    references=[],
                    remediation="Do not install; this package may exfiltrate credentials.",
                    metadata={"file": str(rel), "lines": visitor.cred_harvest_lines},
                )
            )

    return findings
