"""Unix socket JSON-RPC 2.0 IPC server for AgentShield.

Clients send newline-delimited JSON requests; the server replies with
newline-delimited JSON responses.

Request::

    {"jsonrpc": "2.0", "method": "scan",
     "params": {"package": "numpy", "version": "1.24.0", "ecosystem": "pypi"},
     "id": 1}

Response::

    {"jsonrpc": "2.0",
     "result": {"decision": "ALLOW", "findings": [], "cache_hit": true},
     "id": 1}

Start with ``agentshield serve`` (default socket: ``~/.agentshield/agentshield.sock``).
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

from agentshield.core.models import Ecosystem, ScanRequest
from agentshield.core.scanner import AgentShield

logger = logging.getLogger(__name__)

DEFAULT_SOCK_PATH = Path.home() / ".agentshield" / "agentshield.sock"


class IPCServer:
    """JSON-RPC 2.0 server over a Unix domain socket."""

    def __init__(
        self,
        shield: AgentShield,
        sock_path: Path = DEFAULT_SOCK_PATH,
    ) -> None:
        self.shield = shield
        self.sock_path = sock_path

    async def start(self) -> None:
        """Create the socket, start listening, and serve until cancelled."""
        self.sock_path.parent.mkdir(parents=True, exist_ok=True)

        if self.sock_path.exists():
            self.sock_path.unlink()

        server = await asyncio.start_unix_server(
            self._handle_client,
            path=str(self.sock_path),
        )
        logger.info("AgentShield IPC server listening on %s", self.sock_path)

        async with server:
            await server.serve_forever()

    # ── internal ─────────────────────────────────────────────────────────────

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            while True:
                data = await reader.readline()
                if not data:
                    break

                try:
                    msg = json.loads(data.decode())
                except json.JSONDecodeError as exc:
                    resp = _error(None, -32700, f"Parse error: {exc}")
                    writer.write(json.dumps(resp).encode() + b"\n")
                    await writer.drain()
                    continue

                resp = await self._dispatch(msg)
                writer.write(json.dumps(resp).encode() + b"\n")
                await writer.drain()

        except Exception as exc:
            logger.debug("IPC client handler error: %s", exc)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _dispatch(self, msg: dict[str, Any]) -> dict[str, Any]:
        msg_id = msg.get("id")
        method = msg.get("method", "")
        params: dict[str, Any] = msg.get("params") or {}

        try:
            if method == "scan":
                result = await self._handle_scan(params)
                return {"jsonrpc": "2.0", "id": msg_id, "result": result}

            if method == "ping":
                return {"jsonrpc": "2.0", "id": msg_id, "result": "pong"}

            return _error(msg_id, -32601, f"Method not found: {method!r}")

        except Exception as exc:
            logger.error("IPC error in method %r: %s", method, exc)
            return _error(msg_id, -32603, f"Internal error: {exc}")

    async def _handle_scan(self, params: dict[str, Any]) -> dict[str, Any]:
        ecosystem_str = params.get("ecosystem", "pypi")
        try:
            ecosystem = Ecosystem(ecosystem_str.lower())
        except ValueError as err:
            raise ValueError(f"Unknown ecosystem: {ecosystem_str!r}") from err

        request = ScanRequest(
            package=params["package"],
            version=params.get("version"),
            ecosystem=ecosystem,
            deep=bool(params.get("deep", False)),
            context_hint=params.get("context_hint"),
            source=params.get("source", "ipc"),
        )
        result = await self.shield.ascan(request)

        return {
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
        }


def _error(msg_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}
