"""AgentShield enforcement layer.

Houses the single source of truth for package-manager coverage
(:mod:`agentshield.enforce.registry`) plus the enforcement mechanisms that
build on it: the PATH shim baseline (:mod:`agentshield.enforce.shim`), the
Linux ``execve`` interceptor (:mod:`agentshield.enforce.execve`), and the
scanning index proxy (:mod:`agentshield.enforce.proxy`).
"""

from __future__ import annotations

from agentshield.enforce.registry import (
    MANAGERS,
    ManagerSpec,
    ParsedInstall,
    find_suspicions,
    parse_argv,
    parse_command,
    parse_manifests,
    parse_packages,
    shadow_binaries,
    tokenize_packages,
)

__all__ = [
    "MANAGERS",
    "ManagerSpec",
    "ParsedInstall",
    "find_suspicions",
    "parse_argv",
    "parse_command",
    "parse_manifests",
    "parse_packages",
    "shadow_binaries",
    "tokenize_packages",
]
