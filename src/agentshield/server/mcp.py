"""MCP (Model Context Protocol) stdio transport server for AgentShield.

Run with ``agentshield serve --mcp`` to expose AgentShield as an MCP tool
server. Any MCP-compatible agent framework can connect via the standard
``stdio`` transport without a custom integration layer.

Exposed tools:
- ``agentshield_scan``    — scan a package before installation
- ``agentshield_posture`` — generate a security posture report (Phase 4)
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any

from agentshield.core.models import Ecosystem, ScanRequest
from agentshield.core.scanner import AgentShield

_SERVER_INFO = {"name": "agentshield", "version": "0.1.0"}
_PROTOCOL_VERSION = "2024-11-05"

_TOOLS: list[dict[str, Any]] = [
    {
        "name": "agentshield_scan",
        "description": (
            "Check a package for security vulnerabilities before installing. "
            "Returns a decision (ALLOW/BLOCK/NEEDS_CONFIRMATION/LOG_ASYNC) "
            "and a list of findings (CVEs, typosquatting, static-analysis hits)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "package": {
                    "type": "string",
                    "description": "Package name as it appears in the registry.",
                },
                "version": {
                    "type": "string",
                    "description": "Pinned version string (optional; None = latest).",
                },
                "ecosystem": {
                    "type": "string",
                    "enum": ["pypi", "npm", "cargo"],
                    "description": "Package registry.",
                },
                "deep": {
                    "type": "boolean",
                    "default": False,
                    "description": "Run static analysis in addition to CVE lookups.",
                },
                "context_hint": {
                    "type": "string",
                    "description": "Brief explanation of why the agent wants this package.",
                },
                "transitive": {
                    "type": "boolean",
                    "default": False,
                    "description": "Resolve and scan all transitive dependencies.",
                },
                "transitive_depth": {
                    "type": "integer",
                    "default": 3,
                    "description": "Maximum depth for transitive dependency resolution (1–10).",
                },
            },
            "required": ["package", "ecosystem"],
        },
    },
    {
        "name": "agentshield_scan_file",
        "description": (
            "Scan all packages declared in a manifest file "
            "(requirements.txt, package.json, Cargo.toml, or package-lock.json). "
            "Returns an aggregate decision and a per-package summary table."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Absolute or relative path to the manifest file. "
                        "Supported filenames: requirements.txt, package.json, "
                        "Cargo.toml, package-lock.json."
                    ),
                },
            },
            "required": ["path"],
        },
    },
    {
        "name": "agentshield_posture",
        "description": "Generate a security posture report for the current environment.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "tool_names": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Agent tool names to classify by risk level.",
                },
                "log_hours": {
                    "type": "integer",
                    "default": 24,
                    "description": "Hours of async report log to include (default: 24).",
                },
                "skip_packages": {
                    "type": "boolean",
                    "default": False,
                    "description": "Skip installed-package CVE scan (faster).",
                },
            },
        },
    },
    {
        "name": "agentshield_sbom",
        "description": (
            "Scan a manifest file and return a CycloneDX v1.4 SBOM (Software Bill of "
            "Materials) in JSON format.  The SBOM lists all packages as components and "
            "includes a vulnerabilities section for any findings."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Absolute or relative path to the manifest file. "
                        "Supported: requirements.txt, package.json, Cargo.toml, "
                        "package-lock.json."
                    ),
                },
            },
            "required": ["path"],
        },
    },
]


class MCPServer:
    """MCP tool server (JSON-RPC 2.0 over stdio)."""

    def __init__(self, shield: AgentShield) -> None:
        self.shield = shield

    # ── public entry points ───────────────────────────────────────────────────

    async def run_stdio(self) -> None:
        """Read messages from stdin and write responses to stdout indefinitely."""
        loop = asyncio.get_event_loop()
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin.buffer)

        while True:
            try:
                line = await reader.readline()
            except Exception:
                break
            if not line:
                break

            try:
                msg = json.loads(line.decode())
            except json.JSONDecodeError:
                continue

            response = await self.handle_message(msg)
            if response is not None:
                out = json.dumps(response) + "\n"
                sys.stdout.buffer.write(out.encode())
                sys.stdout.buffer.flush()

    async def handle_message(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        """Process a single JSON-RPC message.  Returns None for notifications."""
        return await self._dispatch(msg)

    # ── dispatch ──────────────────────────────────────────────────────────────

    async def _dispatch(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        method = msg.get("method", "")
        msg_id = msg.get("id")
        params: dict[str, Any] = msg.get("params") or {}

        if method == "initialize":
            return _ok(
                msg_id,
                {
                    "protocolVersion": _PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": _SERVER_INFO,
                },
            )

        if method == "initialized":
            return None  # notification — no response

        if method == "tools/list":
            return _ok(msg_id, {"tools": _TOOLS})

        if method == "tools/call":
            name = params.get("name", "")
            args: dict[str, Any] = params.get("arguments") or {}
            result = await self._call_tool(name, args)
            return _ok(msg_id, result)

        if method == "ping":
            return _ok(msg_id, {})

        if msg_id is not None:
            return _method_not_found(msg_id, method)
        return None  # unknown notification

    # ── tool dispatch ─────────────────────────────────────────────────────────

    async def _call_tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        if name == "agentshield_scan":
            return await self._tool_scan(args)
        if name == "agentshield_scan_file":
            return await self._tool_scan_file(args)
        if name == "agentshield_posture":
            return await self._tool_posture(args)
        if name == "agentshield_sbom":
            return await self._tool_sbom(args)
        return _tool_error(f"Unknown tool: {name!r}")

    async def _tool_scan(self, args: dict[str, Any]) -> dict[str, Any]:
        try:
            ecosystem_str = args.get("ecosystem", "pypi")
            try:
                ecosystem = Ecosystem(ecosystem_str.lower())
            except ValueError:
                return _tool_error(f"Unknown ecosystem: {ecosystem_str!r}")

            request = ScanRequest(
                package=args["package"],
                version=args.get("version"),
                ecosystem=ecosystem,
                deep=bool(args.get("deep", False)),
                context_hint=args.get("context_hint"),
                source="mcp",
                transitive=bool(args.get("transitive", False)),
                transitive_depth=int(args.get("transitive_depth", 3)),
            )
            result = await self.shield.ascan(request)

            payload: dict[str, Any] = {
                "decision": result.decision.action.value,
                "reason": result.decision.reason,
                "max_severity": result.max_severity.value,
                "cache_hit": result.cache_hit,
                "scan_duration_ms": result.scan_duration_ms,
                "findings": [
                    {
                        "rule_id": f.rule_id,
                        "title": f.title,
                        "severity": f.severity.value,
                        "source": f.source,
                        "cvss_score": f.cvss_score,
                        "remediation": f.remediation,
                    }
                    for f in result.findings
                ],
                "transitive_results": [
                    {
                        "package": tr.request.package,
                        "ecosystem": tr.request.ecosystem.value,
                        "decision": tr.decision.action.value,
                        "max_severity": tr.max_severity.value,
                        "findings_count": len(tr.findings),
                    }
                    for tr in result.transitive_results
                ],
            }
            return {"content": [{"type": "text", "text": json.dumps(payload, indent=2)}]}

        except KeyError as exc:
            return _tool_error(f"Missing required argument: {exc}")
        except Exception as exc:
            return _tool_error(f"Scan failed: {exc}")

    async def _tool_scan_file(self, args: dict[str, Any]) -> dict[str, Any]:
        try:
            path_str = args["path"]
        except KeyError:
            return _tool_error("Missing required argument: 'path'")

        try:
            from pathlib import Path as _Path

            result = await self.shield.ascan_file(_Path(path_str))

            payload = {
                "decision": result.aggregate_decision.action.value,
                "reason": result.aggregate_decision.reason,
                "path": result.path,
                "total_packages": result.total_packages,
                "blocked": result.blocked,
                "warned": result.warned,
                "allowed": result.allowed,
                "total_findings": result.total_findings,
                "packages": [
                    {
                        "package": r.request.package,
                        "version": r.request.version,
                        "ecosystem": r.request.ecosystem.value,
                        "decision": r.decision.action.value,
                        "max_severity": r.max_severity.value,
                        "findings_count": len(r.findings),
                    }
                    for r in result.results
                ],
            }
            return {"content": [{"type": "text", "text": json.dumps(payload, indent=2)}]}

        except Exception as exc:
            return _tool_error(f"scan-file failed: {exc}")

    async def _tool_sbom(self, args: dict[str, Any]) -> dict[str, Any]:
        try:
            path_str = args["path"]
        except KeyError:
            return _tool_error("Missing required argument: 'path'")

        try:
            from pathlib import Path as _Path

            from agentshield.core.sbom import generate_sbom_json

            result = await self.shield.ascan_file(_Path(path_str))
            sbom_text = generate_sbom_json(result.results, source_path=path_str)
            return {"content": [{"type": "text", "text": sbom_text}]}
        except Exception as exc:
            return _tool_error(f"SBOM generation failed: {exc}")

    async def _tool_posture(self, args: dict[str, Any]) -> dict[str, Any]:
        try:
            from agentshield.core.config import Config
            from agentshield.reports.posture import run_posture_check
            from agentshield.reports.renderers import render_json

            tool_names: list[str] | None = args.get("tool_names") or None
            log_hours: int = int(args.get("log_hours", 24))
            skip_packages: bool = bool(args.get("skip_packages", False))

            cfg = Config.load(None)
            report = await run_posture_check(
                db_path=cfg.cache.db_path,
                tool_names=tool_names,
                async_log_hours=log_hours,
                skip_package_scan=skip_packages,
            )
            return {"content": [{"type": "text", "text": render_json(report)}]}
        except Exception as exc:
            return _tool_error(f"Posture check failed: {exc}")


# ── helpers ───────────────────────────────────────────────────────────────────


def _ok(msg_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _method_not_found(msg_id: Any, method: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {"code": -32601, "message": f"Method not found: {method!r}"},
    }


def _tool_error(message: str) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": message}],
        "isError": True,
    }
