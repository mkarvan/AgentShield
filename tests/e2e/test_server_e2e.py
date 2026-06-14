"""Server integration tests.

Tests the HTTP and IPC servers by starting them in background tasks and
communicating over sockets.  No external network calls; the AgentShield
instance uses allowlist/denylist configs.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import socket
import time
from pathlib import Path

import pytest

from agentshield.core.config import Config
from agentshield.core.scanner import AgentShield

# ── helpers ───────────────────────────────────────────────────────────────────


def _free_port() -> int:
    """Return an unused TCP port on localhost."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _make_config(tmp_path: Path, **overrides: object) -> Config:
    base: dict[str, object] = {
        "cache": {"db_path": str(tmp_path / "server_test.db")},
        "denylist": ["evil-pkg"],
        "allowlist": ["requests", "lodash", "serde"],
        "offline": True,
    }
    base.update(overrides)
    return Config.model_validate(base)


async def _http_request(
    host: str, port: int, method: str, path: str, body: dict | None = None
) -> tuple[int, dict]:
    """Make a raw HTTP/1.1 request and return (status_code, json_body)."""
    reader, writer = await asyncio.open_connection(host, port)
    try:
        payload = json.dumps(body).encode() if body is not None else b""
        headers = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(payload)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        writer.write(headers.encode() + payload)
        await writer.drain()

        response_data = await reader.read(65536)
        response = response_data.decode(errors="replace")

        status_line = response.split("\r\n")[0]
        status_code = int(status_line.split(" ")[1])

        body_start = response.find("\r\n\r\n")
        body_text = response[body_start + 4 :] if body_start != -1 else ""
        parsed_body: dict = json.loads(body_text) if body_text.strip() else {}

        return status_code, parsed_body
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def _wait_for_port(host: str, port: int, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with contextlib.suppress(ConnectionRefusedError, OSError):
            r, w = await asyncio.open_connection(host, port)
            w.close()
            with contextlib.suppress(Exception):
                await w.wait_closed()
            return True
        await asyncio.sleep(0.05)
    return False


async def _wait_for_socket(sock_path: Path, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if sock_path.exists():
            with contextlib.suppress(ConnectionRefusedError, OSError):
                r, w = await asyncio.open_unix_connection(str(sock_path))
                w.close()
                with contextlib.suppress(Exception):
                    await w.wait_closed()
                return True
        await asyncio.sleep(0.05)
    return False


async def _cancel_task(task: asyncio.Task) -> None:  # type: ignore[type-arg]
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError, Exception):
        await task


async def _ipc_request(sock_path: Path, msg: dict, timeout: float = 5.0) -> dict:
    reader, writer = await asyncio.open_unix_connection(str(sock_path))
    try:
        writer.write(json.dumps(msg).encode() + b"\n")
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        return json.loads(line.decode())
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


# ── HTTP server tests ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_http_health_endpoint(tmp_path: Path) -> None:
    from agentshield.server.http_server import HTTPServer

    port = _free_port()
    shield = AgentShield(config=_make_config(tmp_path))
    server = HTTPServer(shield, port=port, allowed_dirs=[tmp_path])

    task = asyncio.create_task(server.start())
    try:
        assert await _wait_for_port("127.0.0.1", port)
        code, body = await _http_request("127.0.0.1", port, "GET", "/health")
        assert code == 200
        assert body.get("status") == "ok"
        assert body.get("service") == "agentshield"
    finally:
        await _cancel_task(task)


@pytest.mark.asyncio
async def test_http_scan_allowlisted_package(tmp_path: Path) -> None:
    from agentshield.server.http_server import HTTPServer

    port = _free_port()
    shield = AgentShield(config=_make_config(tmp_path))
    server = HTTPServer(shield, port=port, allowed_dirs=[tmp_path])

    task = asyncio.create_task(server.start())
    try:
        assert await _wait_for_port("127.0.0.1", port)
        code, body = await _http_request(
            "127.0.0.1",
            port,
            "POST",
            "/scan",
            {"package": "requests", "ecosystem": "pypi"},
        )
        assert code == 200
        assert body["decision"] == "ALLOW"
        assert "findings" in body
        assert "max_severity" in body
    finally:
        await _cancel_task(task)


@pytest.mark.asyncio
async def test_http_scan_denylisted_package(tmp_path: Path) -> None:
    from agentshield.server.http_server import HTTPServer

    port = _free_port()
    shield = AgentShield(config=_make_config(tmp_path))
    server = HTTPServer(shield, port=port, allowed_dirs=[tmp_path])

    task = asyncio.create_task(server.start())
    try:
        assert await _wait_for_port("127.0.0.1", port)
        code, body = await _http_request(
            "127.0.0.1",
            port,
            "POST",
            "/scan",
            {"package": "evil-pkg", "ecosystem": "pypi"},
        )
        assert code == 200
        assert body["decision"] == "BLOCK"
    finally:
        await _cancel_task(task)


@pytest.mark.asyncio
async def test_http_scan_npm_package(tmp_path: Path) -> None:
    from agentshield.server.http_server import HTTPServer

    port = _free_port()
    shield = AgentShield(config=_make_config(tmp_path))
    server = HTTPServer(shield, port=port, allowed_dirs=[tmp_path])

    task = asyncio.create_task(server.start())
    try:
        assert await _wait_for_port("127.0.0.1", port)
        code, body = await _http_request(
            "127.0.0.1",
            port,
            "POST",
            "/scan",
            {"package": "lodash", "ecosystem": "npm"},
        )
        assert code == 200
        assert body["decision"] == "ALLOW"
    finally:
        await _cancel_task(task)


@pytest.mark.asyncio
async def test_http_scan_cargo_package(tmp_path: Path) -> None:
    from agentshield.server.http_server import HTTPServer

    port = _free_port()
    shield = AgentShield(config=_make_config(tmp_path))
    server = HTTPServer(shield, port=port, allowed_dirs=[tmp_path])

    task = asyncio.create_task(server.start())
    try:
        assert await _wait_for_port("127.0.0.1", port)
        code, body = await _http_request(
            "127.0.0.1",
            port,
            "POST",
            "/scan",
            {"package": "serde", "ecosystem": "cargo"},
        )
        assert code == 200
        assert body["decision"] == "ALLOW"
    finally:
        await _cancel_task(task)


@pytest.mark.asyncio
async def test_http_scan_missing_package_field(tmp_path: Path) -> None:
    from agentshield.server.http_server import HTTPServer

    port = _free_port()
    shield = AgentShield(config=_make_config(tmp_path))
    server = HTTPServer(shield, port=port, allowed_dirs=[tmp_path])

    task = asyncio.create_task(server.start())
    try:
        assert await _wait_for_port("127.0.0.1", port)
        code, body = await _http_request("127.0.0.1", port, "POST", "/scan", {"ecosystem": "pypi"})
        assert code == 400
        assert "error" in body
    finally:
        await _cancel_task(task)


@pytest.mark.asyncio
async def test_http_scan_unknown_ecosystem(tmp_path: Path) -> None:
    from agentshield.server.http_server import HTTPServer

    port = _free_port()
    shield = AgentShield(config=_make_config(tmp_path))
    server = HTTPServer(shield, port=port, allowed_dirs=[tmp_path])

    task = asyncio.create_task(server.start())
    try:
        assert await _wait_for_port("127.0.0.1", port)
        code, body = await _http_request(
            "127.0.0.1",
            port,
            "POST",
            "/scan",
            {"package": "requests", "ecosystem": "maven"},
        )
        assert code == 400
        assert "error" in body
    finally:
        await _cancel_task(task)


@pytest.mark.asyncio
async def test_http_scan_file_path_restriction(tmp_path: Path) -> None:
    """Paths outside allowed_dirs return 403."""
    from agentshield.server.http_server import HTTPServer

    port = _free_port()
    shield = AgentShield(config=_make_config(tmp_path))
    server = HTTPServer(shield, port=port, allowed_dirs=[tmp_path])

    task = asyncio.create_task(server.start())
    try:
        assert await _wait_for_port("127.0.0.1", port)
        code, body = await _http_request(
            "127.0.0.1", port, "POST", "/scan-file", {"path": "/etc/passwd"}
        )
        assert code == 403
        assert "error" in body
        assert "denied" in body["error"].lower() or "outside" in body["error"].lower()
    finally:
        await _cancel_task(task)


@pytest.mark.asyncio
async def test_http_scan_file_allowed_path(tmp_path: Path, sample_requirements_txt: Path) -> None:
    """scan-file succeeds for a file inside allowed_dirs."""
    from agentshield.server.http_server import HTTPServer

    port = _free_port()
    config = _make_config(tmp_path, allowlist=["requests", "flask", "numpy"])
    shield = AgentShield(config=config)
    server = HTTPServer(shield, port=port, allowed_dirs=[tmp_path])

    task = asyncio.create_task(server.start())
    try:
        assert await _wait_for_port("127.0.0.1", port)
        code, body = await _http_request(
            "127.0.0.1",
            port,
            "POST",
            "/scan-file",
            {"path": str(sample_requirements_txt)},
        )
        assert code == 200
        assert "decision" in body
        assert "total_packages" in body
        assert body["total_packages"] == 3
    finally:
        await _cancel_task(task)


@pytest.mark.asyncio
async def test_http_posture_endpoint(tmp_path: Path) -> None:
    from agentshield.server.http_server import HTTPServer

    port = _free_port()
    shield = AgentShield(config=_make_config(tmp_path))
    server = HTTPServer(shield, port=port, allowed_dirs=[tmp_path])

    task = asyncio.create_task(server.start())
    try:
        assert await _wait_for_port("127.0.0.1", port)
        code, body = await _http_request("127.0.0.1", port, "GET", "/posture")
        assert code == 200
        assert "risk_score" in body or "packages" in body or "score" in str(body)
    finally:
        await _cancel_task(task)


@pytest.mark.asyncio
async def test_http_sbom_endpoint(tmp_path: Path, sample_requirements_txt: Path) -> None:
    from agentshield.server.http_server import HTTPServer

    port = _free_port()
    config = _make_config(tmp_path, allowlist=["requests", "flask", "numpy"])
    shield = AgentShield(config=config)
    server = HTTPServer(shield, port=port, allowed_dirs=[tmp_path])

    task = asyncio.create_task(server.start())
    try:
        assert await _wait_for_port("127.0.0.1", port)
        code, body = await _http_request(
            "127.0.0.1",
            port,
            "POST",
            "/sbom",
            {"path": str(sample_requirements_txt)},
        )
        assert code == 200
        assert "bomFormat" in body or "components" in body
    finally:
        await _cancel_task(task)


@pytest.mark.asyncio
async def test_http_not_found(tmp_path: Path) -> None:
    from agentshield.server.http_server import HTTPServer

    port = _free_port()
    shield = AgentShield(config=_make_config(tmp_path))
    server = HTTPServer(shield, port=port, allowed_dirs=[tmp_path])

    task = asyncio.create_task(server.start())
    try:
        assert await _wait_for_port("127.0.0.1", port)
        code, body = await _http_request("127.0.0.1", port, "GET", "/nonexistent")
        assert code == 404
        assert "error" in body
    finally:
        await _cancel_task(task)


# ── IPC server tests ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_ipc_ping(tmp_path: Path, short_sock_dir: Path) -> None:
    from agentshield.server.ipc import IPCServer

    sock_path = short_sock_dir / "s.sock"
    shield = AgentShield(config=_make_config(tmp_path))
    server = IPCServer(shield, sock_path=sock_path, require_auth=False)

    task = asyncio.create_task(server.start())
    try:
        assert await _wait_for_socket(sock_path)
        resp = await _ipc_request(sock_path, {"jsonrpc": "2.0", "method": "ping", "id": 1})
        assert resp.get("result") == "pong"
        assert resp.get("id") == 1
    finally:
        await _cancel_task(task)


@pytest.mark.asyncio
async def test_ipc_scan_allowlisted_package(tmp_path: Path, short_sock_dir: Path) -> None:
    from agentshield.server.ipc import IPCServer

    sock_path = short_sock_dir / "s.sock"
    shield = AgentShield(config=_make_config(tmp_path))
    server = IPCServer(shield, sock_path=sock_path, require_auth=False)

    task = asyncio.create_task(server.start())
    try:
        assert await _wait_for_socket(sock_path)
        resp = await _ipc_request(
            sock_path,
            {
                "jsonrpc": "2.0",
                "method": "scan",
                "params": {"package": "requests", "ecosystem": "pypi"},
                "id": 2,
            },
        )
        assert "result" in resp
        assert resp["result"]["decision"] == "ALLOW"
        assert "findings" in resp["result"]
    finally:
        await _cancel_task(task)


@pytest.mark.asyncio
async def test_ipc_scan_denylisted_package(tmp_path: Path, short_sock_dir: Path) -> None:
    from agentshield.server.ipc import IPCServer

    sock_path = short_sock_dir / "s.sock"
    shield = AgentShield(config=_make_config(tmp_path))
    server = IPCServer(shield, sock_path=sock_path, require_auth=False)

    task = asyncio.create_task(server.start())
    try:
        assert await _wait_for_socket(sock_path)
        resp = await _ipc_request(
            sock_path,
            {
                "jsonrpc": "2.0",
                "method": "scan",
                "params": {"package": "evil-pkg", "ecosystem": "pypi"},
                "id": 3,
            },
        )
        assert "result" in resp
        assert resp["result"]["decision"] == "BLOCK"
    finally:
        await _cancel_task(task)


@pytest.mark.asyncio
async def test_ipc_scan_npm_ecosystem(tmp_path: Path, short_sock_dir: Path) -> None:
    from agentshield.server.ipc import IPCServer

    sock_path = short_sock_dir / "s.sock"
    shield = AgentShield(config=_make_config(tmp_path))
    server = IPCServer(shield, sock_path=sock_path, require_auth=False)

    task = asyncio.create_task(server.start())
    try:
        assert await _wait_for_socket(sock_path)
        resp = await _ipc_request(
            sock_path,
            {
                "jsonrpc": "2.0",
                "method": "scan",
                "params": {"package": "lodash", "ecosystem": "npm"},
                "id": 4,
            },
        )
        assert "result" in resp
        assert resp["result"]["decision"] == "ALLOW"
    finally:
        await _cancel_task(task)


@pytest.mark.asyncio
async def test_ipc_scan_cargo_ecosystem(tmp_path: Path, short_sock_dir: Path) -> None:
    from agentshield.server.ipc import IPCServer

    sock_path = short_sock_dir / "s.sock"
    shield = AgentShield(config=_make_config(tmp_path))
    server = IPCServer(shield, sock_path=sock_path, require_auth=False)

    task = asyncio.create_task(server.start())
    try:
        assert await _wait_for_socket(sock_path)
        resp = await _ipc_request(
            sock_path,
            {
                "jsonrpc": "2.0",
                "method": "scan",
                "params": {"package": "serde", "ecosystem": "cargo"},
                "id": 5,
            },
        )
        assert "result" in resp
        assert resp["result"]["decision"] == "ALLOW"
    finally:
        await _cancel_task(task)


@pytest.mark.asyncio
async def test_ipc_unknown_method(tmp_path: Path, short_sock_dir: Path) -> None:
    from agentshield.server.ipc import IPCServer

    sock_path = short_sock_dir / "s.sock"
    shield = AgentShield(config=_make_config(tmp_path))
    server = IPCServer(shield, sock_path=sock_path, require_auth=False)

    task = asyncio.create_task(server.start())
    try:
        assert await _wait_for_socket(sock_path)
        resp = await _ipc_request(
            sock_path,
            {"jsonrpc": "2.0", "method": "nonexistent_method", "id": 6},
        )
        assert "error" in resp
        assert resp["error"]["code"] == -32601
    finally:
        await _cancel_task(task)


@pytest.mark.asyncio
async def test_ipc_invalid_json_parse_error(tmp_path: Path, short_sock_dir: Path) -> None:
    from agentshield.server.ipc import IPCServer

    sock_path = short_sock_dir / "s.sock"
    shield = AgentShield(config=_make_config(tmp_path))
    server = IPCServer(shield, sock_path=sock_path, require_auth=False)

    task = asyncio.create_task(server.start())
    try:
        assert await _wait_for_socket(sock_path)
        reader, writer = await asyncio.open_unix_connection(str(sock_path))
        try:
            writer.write(b"this is not json\n")
            await writer.drain()
            line = await asyncio.wait_for(reader.readline(), timeout=3.0)
            resp = json.loads(line.decode())
            assert "error" in resp
            assert resp["error"]["code"] == -32700
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
    finally:
        await _cancel_task(task)


@pytest.mark.asyncio
async def test_ipc_auth_token_required_on_unsupported_platform(
    tmp_path: Path, short_sock_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On platforms that don't support peer credentials, token auth is used."""
    import agentshield.server.ipc as ipc_mod

    monkeypatch.setattr(ipc_mod, "peer_cred_supported", lambda: False)

    from agentshield.server.ipc import IPCServer

    sock_path = short_sock_dir / "s.sock"
    token_path = tmp_path / "test.token"
    shield = AgentShield(config=_make_config(tmp_path))
    server = IPCServer(shield, sock_path=sock_path, token_path=token_path, require_auth=True)

    task = asyncio.create_task(server.start())
    try:
        assert await _wait_for_socket(sock_path)

        # Wrong token → rejected
        reader, writer = await asyncio.open_unix_connection(str(sock_path))
        try:
            writer.write(b"AUTH wrongtoken\n")
            await writer.drain()
            line = await asyncio.wait_for(reader.readline(), timeout=3.0)
            assert b"ERR" in line or b"unauthorized" in line.lower()
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

        # Correct token → OK + can call ping
        token = token_path.read_text().strip()
        reader2, writer2 = await asyncio.open_unix_connection(str(sock_path))
        try:
            writer2.write(f"AUTH {token}\n".encode())
            await writer2.drain()
            ok_line = await asyncio.wait_for(reader2.readline(), timeout=3.0)
            assert b"OK" in ok_line

            writer2.write(
                json.dumps({"jsonrpc": "2.0", "method": "ping", "id": 99}).encode() + b"\n"
            )
            await writer2.drain()
            resp_line = await asyncio.wait_for(reader2.readline(), timeout=3.0)
            resp = json.loads(resp_line.decode())
            assert resp.get("result") == "pong"
        finally:
            writer2.close()
            with contextlib.suppress(Exception):
                await writer2.wait_closed()
    finally:
        await _cancel_task(task)
