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

Authentication
--------------
On Linux and macOS the server uses peer credential checks (SO_PEERCRED on
Linux, LOCAL_PEERCRED via getsockopt on macOS) to verify that the connecting
process runs as the same UID as the server.  On platforms that do not support
peer credentials the server falls back to a shared-secret token: a random
64-character hex token is generated at startup and written to
``~/.agentshield/ipc.token`` (mode 0o600).  Clients must send
``AUTH <token>\\n`` as their very first message; the server replies ``OK\\n``
on success or ``ERR unauthorized\\n`` on failure.

Start with ``agentshield serve`` (default socket: ``~/.agentshield/agentshield.sock``).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import socket as _socket
import struct
import sys
from pathlib import Path
from typing import Any

from agentshield.core.models import Ecosystem, ScanRequest
from agentshield.core.scanner import AgentShield

logger = logging.getLogger(__name__)

DEFAULT_SOCK_PATH = Path.home() / ".agentshield" / "agentshield.sock"
_DEFAULT_TOKEN_PATH = Path.home() / ".agentshield" / "ipc.token"


# ── peer credential helpers ───────────────────────────────────────────────────


def peer_cred_supported() -> bool:
    """Return True if this platform natively supports peer credential checks."""
    return sys.platform in ("linux", "darwin")


def get_peer_uid(writer: asyncio.StreamWriter) -> int | None:
    """Return the UID of the connecting process, or None if unavailable.

    Uses SO_PEERCRED on Linux and LOCAL_PEERCRED (via getsockopt) on macOS.
    Both work on the asyncio.trsock.TransportSocket returned by get_extra_info.
    """
    sock: Any = writer.get_extra_info("socket")
    if sock is None:
        return None
    try:
        if sys.platform == "linux":
            # struct ucred { __u32 pid; __u32 uid; __u32 gid; }
            so_peercred = getattr(_socket, "SO_PEERCRED", 17)  # 17 on Linux
            raw = sock.getsockopt(
                _socket.SOL_SOCKET,
                so_peercred,
                struct.calcsize("3I"),
            )
            _, uid, _ = struct.unpack("3I", raw)
            return int(uid)
        if sys.platform == "darwin":
            # struct xucred { u_int cr_version; uid_t cr_uid; short cr_ngroups; gid_t cr_groups[16]; }
            # SOL_LOCAL=0, LOCAL_PEERCRED=0x0001 (from <sys/un.h>)
            _SOL_LOCAL = 0
            _LOCAL_PEERCRED = 0x0001
            raw = sock.getsockopt(_SOL_LOCAL, _LOCAL_PEERCRED, 76)
            _, uid = struct.unpack_from("=II", raw)
            return int(uid)
    except (OSError, AttributeError):
        # AttributeError: SO_PEERCRED not available on this platform build
        pass
    return None


# ── token helper ──────────────────────────────────────────────────────────────


def _write_token(token: str, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(token)
    path.chmod(0o600)


# ── server ────────────────────────────────────────────────────────────────────


class IPCServer:
    """JSON-RPC 2.0 server over a Unix domain socket.

    Authentication
    ~~~~~~~~~~~~~~
    When *require_auth* is True (default):

    * Linux / macOS — peer credential check via SO_PEERCRED / getpeereid().
      The connecting process must run as the same UID as the server.
    * Other platforms — shared-secret token fallback.  The server generates a
      random token, writes it to *token_path* (mode 0o600), and expects each
      client to send ``AUTH <token>\\n`` before any JSON-RPC message.

    Set *require_auth=False* to disable authentication entirely (e.g. for
    testing or when the socket is already protected by filesystem permissions
    on a single-user system).
    """

    def __init__(
        self,
        shield: AgentShield,
        sock_path: Path | None = None,
        token_path: Path | None = None,
        require_auth: bool = True,
    ) -> None:
        self.shield = shield
        self.sock_path = sock_path if sock_path is not None else DEFAULT_SOCK_PATH
        self.token_path = token_path if token_path is not None else _DEFAULT_TOKEN_PATH
        self.require_auth = require_auth

        self._use_peer_cred: bool = False
        self._token: str | None = None

        if require_auth:
            if peer_cred_supported():
                self._use_peer_cred = True
                logger.debug("IPC auth: peer credential (UID check)")
            else:
                self._token = secrets.token_hex(32)
                _write_token(self._token, self.token_path)
                logger.info("IPC auth: token fallback — secret written to %s", self.token_path)

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

    # ── authentication ────────────────────────────────────────────────────────

    async def _authenticate(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> bool:
        """Return True if the client is allowed to proceed."""
        if not self.require_auth:
            return True

        if self._use_peer_cred:
            uid = get_peer_uid(writer)
            if uid is None:
                logger.warning("IPC: could not read peer credentials — rejecting")
                return False
            own_uid = os.getuid()
            if uid != own_uid:
                logger.warning("IPC: rejected connection from UID %d (server UID %d)", uid, own_uid)
                return False
            return True

        # Token fallback: expect "AUTH <token>\n" as the first line
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=5.0)
        except TimeoutError:
            logger.warning("IPC: auth handshake timed out — rejecting")
            return False

        parts = line.decode(errors="replace").strip().split(" ", 1)
        if (
            len(parts) == 2
            and parts[0] == "AUTH"
            and self._token is not None
            and secrets.compare_digest(parts[1], self._token)
        ):
            writer.write(b"OK\n")
            await writer.drain()
            return True

        writer.write(b"ERR unauthorized\n")
        await writer.drain()
        logger.warning("IPC: invalid or missing auth token — rejecting connection")
        return False

    # ── connection handler ────────────────────────────────────────────────────

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            if not await self._authenticate(reader, writer):
                return

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


def _error(msg_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}
