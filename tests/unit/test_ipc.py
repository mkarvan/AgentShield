"""Unit tests for the Unix socket JSON-RPC 2.0 IPC server."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from agentshield.core.models import (
    Decision,
    DecisionAction,
    Ecosystem,
    Finding,
    ScanRequest,
    ScanResult,
    Severity,
)
from agentshield.server.ipc import IPCServer, _error

# ── helpers ───────────────────────────────────────────────────────────────────


def _allow_result(package: str = "requests") -> ScanResult:
    return ScanResult(
        request=ScanRequest(package=package, ecosystem=Ecosystem.PYPI),
        findings=[],
        max_severity=Severity.NONE,
        decision=Decision(action=DecisionAction.ALLOW, reason="clean"),
    )


def _make_shield(result: ScanResult | None = None) -> MagicMock:
    shield = MagicMock()
    shield.ascan = AsyncMock(return_value=result or _allow_result())
    return shield


def _make_server(sock_path: Path, result: ScanResult | None = None) -> IPCServer:
    return IPCServer(shield=_make_shield(result), sock_path=sock_path)


@pytest.fixture
def dummy_sock_path() -> Path:
    """A socket path used only for dispatch-level tests (server.start() never called)."""
    return Path("/tmp/agentshield_unit_dummy.sock")


@pytest.fixture
async def live_server() -> AsyncIterator[IPCServer]:
    """Start an IPCServer on a short-path socket and yield it; cancel on teardown.

    macOS limits sun_path to 104 bytes; pytest's tmp_path can exceed that, so
    we create the socket under /tmp directly.
    """
    fd, p = tempfile.mkstemp(suffix=".sock", dir="/tmp")
    os.close(fd)
    os.unlink(p)
    sock_path = Path(p)

    server = IPCServer(shield=_make_shield(), sock_path=sock_path)
    task: asyncio.Task[None] = asyncio.create_task(server.start())

    # Wait up to 2 s for the socket to appear
    for _ in range(200):
        if sock_path.exists():
            break
        await asyncio.sleep(0.01)
    else:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await task
        pytest.fail("IPC server socket did not appear within 2s")

    yield server

    task.cancel()
    with contextlib.suppress(asyncio.CancelledError, Exception):
        await task
    with contextlib.suppress(FileNotFoundError):
        sock_path.unlink()


# ── _error helper ─────────────────────────────────────────────────────────────


def test_error_helper_format() -> None:
    err = _error(1, -32600, "Invalid Request")
    assert err == {
        "jsonrpc": "2.0",
        "id": 1,
        "error": {"code": -32600, "message": "Invalid Request"},
    }


def test_error_helper_null_id() -> None:
    err = _error(None, -32700, "Parse error")
    assert err["id"] is None
    assert err["error"]["code"] == -32700
    assert err["jsonrpc"] == "2.0"


# ── _dispatch: ping ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_dispatch_ping_returns_pong(dummy_sock_path: Path) -> None:
    server = _make_server(dummy_sock_path)
    resp = await server._dispatch({"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert resp == {"jsonrpc": "2.0", "id": 1, "result": "pong"}


@pytest.mark.asyncio
async def test_dispatch_ping_preserves_string_id(dummy_sock_path: Path) -> None:
    server = _make_server(dummy_sock_path)
    resp = await server._dispatch({"jsonrpc": "2.0", "id": "req-abc", "method": "ping"})
    assert resp["id"] == "req-abc"
    assert resp["result"] == "pong"


# ── _dispatch: unknown method ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_dispatch_unknown_method_returns_error(dummy_sock_path: Path) -> None:
    server = _make_server(dummy_sock_path)
    resp = await server._dispatch({"jsonrpc": "2.0", "id": 7, "method": "nonexistent"})
    assert "error" in resp
    assert resp["error"]["code"] == -32601
    assert "nonexistent" in resp["error"]["message"]
    assert resp["id"] == 7


@pytest.mark.asyncio
async def test_dispatch_preserves_id_across_methods(dummy_sock_path: Path) -> None:
    server = _make_server(dummy_sock_path)
    for msg_id in (None, 0, 99, "abc"):
        resp = await server._dispatch({"jsonrpc": "2.0", "id": msg_id, "method": "ping"})
        assert resp["id"] == msg_id


# ── _dispatch: scan ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_dispatch_scan_returns_valid_result(dummy_sock_path: Path) -> None:
    server = _make_server(dummy_sock_path)
    resp = await server._dispatch(
        {
            "jsonrpc": "2.0",
            "id": 42,
            "method": "scan",
            "params": {"package": "requests", "version": "2.31.0", "ecosystem": "pypi"},
        }
    )
    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == 42
    result = resp["result"]
    assert result["decision"] == "ALLOW"
    assert result["max_severity"] == "NONE"
    assert result["findings"] == []
    assert isinstance(result["cache_hit"], bool)
    assert isinstance(result["scan_duration_ms"], int)
    assert isinstance(result["reason"], str)


@pytest.mark.asyncio
async def test_dispatch_scan_with_findings(dummy_sock_path: Path) -> None:
    finding = Finding(
        rule_id="CVE-2024-1234",
        title="Remote code execution",
        severity=Severity.HIGH,
        source="osv",
        cvss_score=8.1,
        remediation="Upgrade to >= 2.32.0",
    )
    block_result = ScanResult(
        request=ScanRequest(package="vulnerable-pkg", ecosystem=Ecosystem.PYPI),
        findings=[finding],
        max_severity=Severity.HIGH,
        decision=Decision(action=DecisionAction.BLOCK, reason="CVE found"),
    )
    server = _make_server(dummy_sock_path, result=block_result)

    resp = await server._dispatch(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "scan",
            "params": {"package": "vulnerable-pkg", "ecosystem": "pypi"},
        }
    )
    result = resp["result"]
    assert result["decision"] == "BLOCK"
    assert result["max_severity"] == "HIGH"
    assert len(result["findings"]) == 1
    f = result["findings"][0]
    assert f["rule_id"] == "CVE-2024-1234"
    assert f["severity"] == "HIGH"
    assert f["source"] == "osv"
    assert f["cvss_score"] == 8.1
    assert f["remediation"] == "Upgrade to >= 2.32.0"


@pytest.mark.asyncio
async def test_dispatch_scan_npm_ecosystem(dummy_sock_path: Path) -> None:
    npm_result = ScanResult(
        request=ScanRequest(package="lodash", ecosystem=Ecosystem.NPM),
        findings=[],
        max_severity=Severity.NONE,
        decision=Decision(action=DecisionAction.ALLOW, reason="clean"),
    )
    server = _make_server(dummy_sock_path, result=npm_result)
    resp = await server._dispatch(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "scan",
            "params": {"package": "lodash", "ecosystem": "npm"},
        }
    )
    assert "result" in resp
    assert resp["result"]["decision"] == "ALLOW"


@pytest.mark.asyncio
async def test_dispatch_scan_unknown_ecosystem_returns_internal_error(
    dummy_sock_path: Path,
) -> None:
    server = _make_server(dummy_sock_path)
    resp = await server._dispatch(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "scan",
            "params": {"package": "requests", "ecosystem": "maven"},
        }
    )
    assert "error" in resp
    assert resp["error"]["code"] == -32603


@pytest.mark.asyncio
async def test_dispatch_scan_defaults_ecosystem_to_pypi(dummy_sock_path: Path) -> None:
    server = _make_server(dummy_sock_path)
    resp = await server._dispatch(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "scan",
            "params": {"package": "requests"},
        }
    )
    assert "result" in resp
    assert resp["result"]["decision"] == "ALLOW"


# ── connection lifecycle ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_ipc_ping_over_socket(live_server: IPCServer) -> None:
    reader, writer = await asyncio.wait_for(
        asyncio.open_unix_connection(str(live_server.sock_path)), timeout=2.0
    )
    writer.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}).encode() + b"\n")
    await writer.drain()

    data = await asyncio.wait_for(reader.readline(), timeout=2.0)
    resp = json.loads(data)

    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == 1
    assert resp["result"] == "pong"

    writer.close()
    await writer.wait_closed()


@pytest.mark.asyncio
async def test_ipc_malformed_json_returns_parse_error(live_server: IPCServer) -> None:
    reader, writer = await asyncio.wait_for(
        asyncio.open_unix_connection(str(live_server.sock_path)), timeout=2.0
    )
    writer.write(b"{ not valid json at all }\n")
    await writer.drain()

    data = await asyncio.wait_for(reader.readline(), timeout=2.0)
    resp = json.loads(data)

    assert "error" in resp
    assert resp["error"]["code"] == -32700
    assert "Parse error" in resp["error"]["message"]
    assert resp["id"] is None

    writer.close()
    await writer.wait_closed()


@pytest.mark.asyncio
async def test_ipc_scan_over_socket(live_server: IPCServer) -> None:
    reader, writer = await asyncio.wait_for(
        asyncio.open_unix_connection(str(live_server.sock_path)), timeout=2.0
    )
    msg = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "scan",
            "params": {"package": "requests", "version": "2.31.0", "ecosystem": "pypi"},
        }
    )
    writer.write(msg.encode() + b"\n")
    await writer.drain()

    data = await asyncio.wait_for(reader.readline(), timeout=2.0)
    resp = json.loads(data)

    assert resp["id"] == 2
    assert "result" in resp
    assert resp["result"]["decision"] == "ALLOW"

    writer.close()
    await writer.wait_closed()


@pytest.mark.asyncio
async def test_ipc_unknown_method_over_socket(live_server: IPCServer) -> None:
    reader, writer = await asyncio.wait_for(
        asyncio.open_unix_connection(str(live_server.sock_path)), timeout=2.0
    )
    writer.write(
        json.dumps({"jsonrpc": "2.0", "id": 5, "method": "no_such_method"}).encode() + b"\n"
    )
    await writer.drain()

    data = await asyncio.wait_for(reader.readline(), timeout=2.0)
    resp = json.loads(data)

    assert resp["id"] == 5
    assert "error" in resp
    assert resp["error"]["code"] == -32601

    writer.close()
    await writer.wait_closed()


@pytest.mark.asyncio
async def test_ipc_multiple_requests_same_connection(live_server: IPCServer) -> None:
    reader, writer = await asyncio.wait_for(
        asyncio.open_unix_connection(str(live_server.sock_path)), timeout=2.0
    )
    for i in range(3):
        writer.write(json.dumps({"jsonrpc": "2.0", "id": i, "method": "ping"}).encode() + b"\n")
    await writer.drain()

    for i in range(3):
        data = await asyncio.wait_for(reader.readline(), timeout=2.0)
        resp = json.loads(data)
        assert resp["id"] == i
        assert resp["result"] == "pong"

    writer.close()
    await writer.wait_closed()


@pytest.mark.asyncio
async def test_ipc_disconnect_handled_gracefully(live_server: IPCServer) -> None:
    """A client disconnect must not crash the server; subsequent clients still work."""
    # First client connects and immediately disconnects
    reader, writer = await asyncio.wait_for(
        asyncio.open_unix_connection(str(live_server.sock_path)), timeout=2.0
    )
    writer.close()
    await writer.wait_closed()

    await asyncio.sleep(0.05)  # allow server to notice the disconnect

    # Server must still accept a second connection
    reader2, writer2 = await asyncio.wait_for(
        asyncio.open_unix_connection(str(live_server.sock_path)), timeout=2.0
    )
    writer2.write(json.dumps({"jsonrpc": "2.0", "id": 99, "method": "ping"}).encode() + b"\n")
    await writer2.drain()
    data = await asyncio.wait_for(reader2.readline(), timeout=2.0)
    resp = json.loads(data)
    assert resp["result"] == "pong"

    writer2.close()
    await writer2.wait_closed()
