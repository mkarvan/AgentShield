"""Unit tests for server/http_server.py."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

from agentshield.core.models import (
    Decision,
    DecisionAction,
    Ecosystem,
    FileScanResult,
    ScanRequest,
    ScanResult,
    Severity,
)
from agentshield.server.http_server import HTTPServer

# ── helpers ───────────────────────────────────────────────────────────────────


def _make_shield(
    scan_result: ScanResult | None = None,
    file_result: FileScanResult | None = None,
) -> MagicMock:
    shield = MagicMock()
    if scan_result is not None:
        shield.ascan = AsyncMock(return_value=scan_result)
    if file_result is not None:
        shield.ascan_file = AsyncMock(return_value=file_result)
    return shield


def _allow_result(pkg: str = "requests") -> ScanResult:
    req = ScanRequest(package=pkg, version="1.0.0", ecosystem=Ecosystem.PYPI)
    return ScanResult(
        request=req,
        findings=[],
        max_severity=Severity.NONE,
        decision=Decision(action=DecisionAction.ALLOW, reason="ok"),
        trust_score=85,
        trust_label="high-trust",
    )


def _file_result(path: str = "requirements.txt") -> FileScanResult:
    return FileScanResult.from_results(path, [_allow_result()])


# ── /health ───────────────────────────────────────────────────────────────────


async def test_health_endpoint() -> None:
    server = HTTPServer(MagicMock())
    code, body = await server._route("GET", "/health", b"")
    assert code == 200
    assert body["status"] == "ok"
    assert body["service"] == "agentshield"


# ── /scan ─────────────────────────────────────────────────────────────────────


async def test_scan_returns_decision() -> None:
    shield = _make_shield(scan_result=_allow_result())
    server = HTTPServer(shield)
    body_bytes = json.dumps({"package": "requests", "ecosystem": "pypi"}).encode()
    code, body = await server._route("POST", "/scan", body_bytes)
    assert code == 200
    assert body["decision"] == "ALLOW"
    assert body["trust_score"] == 85
    assert body["trust_label"] == "high-trust"


async def test_scan_missing_package_returns_400() -> None:
    server = HTTPServer(MagicMock())
    body_bytes = json.dumps({"ecosystem": "pypi"}).encode()
    code, body = await server._route("POST", "/scan", body_bytes)
    assert code == 400
    assert "error" in body


async def test_scan_unknown_ecosystem_returns_400() -> None:
    server = HTTPServer(MagicMock())
    body_bytes = json.dumps({"package": "foo", "ecosystem": "bad"}).encode()
    code, body = await server._route("POST", "/scan", body_bytes)
    assert code == 400


async def test_scan_invalid_json_returns_400() -> None:
    server = HTTPServer(MagicMock())
    code, body = await server._route("POST", "/scan", b"not json")
    assert code == 400
    assert "error" in body


# ── /scan-file ────────────────────────────────────────────────────────────────


async def test_scan_file_returns_aggregate(tmp_path: Path) -> None:
    reqs = tmp_path / "requirements.txt"
    reqs.write_text("requests==2.28.0\n")

    shield = _make_shield(file_result=_file_result(str(reqs)))
    server = HTTPServer(shield, allowed_dirs=[tmp_path])
    body_bytes = json.dumps({"path": str(reqs)}).encode()
    code, body = await server._route("POST", "/scan-file", body_bytes)
    assert code == 200
    assert "decision" in body
    assert "total_packages" in body


async def test_scan_file_missing_path_returns_400() -> None:
    server = HTTPServer(MagicMock())
    code, body = await server._route("POST", "/scan-file", b"{}")
    assert code == 400


# ── /sbom ─────────────────────────────────────────────────────────────────────


async def test_sbom_missing_path_returns_400() -> None:
    server = HTTPServer(MagicMock())
    code, body = await server._route("POST", "/sbom", b"{}")
    assert code == 400


# ── 404 ───────────────────────────────────────────────────────────────────────


async def test_unknown_route_returns_404() -> None:
    server = HTTPServer(MagicMock())
    code, body = await server._route("GET", "/unknown", b"")
    assert code == 404
    assert "error" in body


async def test_wrong_method_returns_404() -> None:
    server = HTTPServer(MagicMock())
    code, body = await server._route("DELETE", "/scan", b"")
    assert code == 404


# ── HTTPServer constructor ────────────────────────────────────────────────────


def test_default_host_and_port() -> None:
    server = HTTPServer(MagicMock())
    assert server.host == "127.0.0.1"
    assert server.port == 8765


def test_custom_host_and_port() -> None:
    server = HTTPServer(MagicMock(), host="0.0.0.0", port=9000)
    assert server.host == "0.0.0.0"
    assert server.port == 9000


# ── _write_response static ────────────────────────────────────────────────────


def test_write_response_produces_valid_http() -> None:

    written: list[bytes] = []

    writer = MagicMock()
    writer.write = lambda data: written.append(data)

    HTTPServer._write_response(writer, 200, {"status": "ok"})
    assert written
    response = b"".join(written).decode()
    assert response.startswith("HTTP/1.1 200 OK")
    assert "Content-Type: application/json" in response
    assert '"status": "ok"' in response


def test_write_response_400() -> None:
    written: list[bytes] = []
    writer = MagicMock()
    writer.write = lambda data: written.append(data)

    HTTPServer._write_response(writer, 400, {"error": "bad"})
    response = b"".join(written).decode()
    assert "400 Bad Request" in response


# ── scanner error propagation ─────────────────────────────────────────────────


async def test_scan_scanner_error_returns_500() -> None:
    shield = MagicMock()
    shield.ascan = AsyncMock(side_effect=RuntimeError("db failure"))
    server = HTTPServer(shield)
    body_bytes = json.dumps({"package": "requests", "ecosystem": "pypi"}).encode()
    code, body = await server._route("POST", "/scan", body_bytes)
    assert code == 500
    assert "error" in body


# ── path traversal guard ──────────────────────────────────────────────────────


def test_validate_path_allows_cwd_child(tmp_path: Path) -> None:
    server = HTTPServer(MagicMock(), allowed_dirs=[tmp_path])
    child = tmp_path / "requirements.txt"
    child.touch()
    resolved, err = server._validate_path(str(child))
    assert err is None
    assert resolved == child.resolve()


def test_validate_path_rejects_traversal(tmp_path: Path) -> None:
    server = HTTPServer(MagicMock(), allowed_dirs=[tmp_path])
    outside = tmp_path / ".." / "secret.txt"
    _, err = server._validate_path(str(outside))
    assert err is not None
    assert "denied" in err.lower()


def test_validate_path_rejects_etc_passwd() -> None:
    allowed = Path("/tmp/agentshield_test_allowed")
    server = HTTPServer(MagicMock(), allowed_dirs=[allowed])
    _, err = server._validate_path("/etc/passwd")
    assert err is not None


async def test_scan_file_path_traversal_returns_403(tmp_path: Path) -> None:
    server = HTTPServer(MagicMock(), allowed_dirs=[tmp_path])
    body_bytes = json.dumps({"path": "/etc/passwd"}).encode()
    code, body = await server._route("POST", "/scan-file", body_bytes)
    assert code == 403
    assert "error" in body


async def test_sbom_path_traversal_returns_403(tmp_path: Path) -> None:
    server = HTTPServer(MagicMock(), allowed_dirs=[tmp_path])
    body_bytes = json.dumps({"path": "/etc/passwd"}).encode()
    code, body = await server._route("POST", "/sbom", body_bytes)
    assert code == 403
    assert "error" in body


async def test_scan_file_allowed_path_succeeds(tmp_path: Path) -> None:
    reqs = tmp_path / "requirements.txt"
    reqs.write_text("requests==2.28.0\n")
    shield = _make_shield(file_result=_file_result(str(reqs)))
    server = HTTPServer(shield, allowed_dirs=[tmp_path])
    body_bytes = json.dumps({"path": str(reqs)}).encode()
    code, body = await server._route("POST", "/scan-file", body_bytes)
    assert code == 200
    assert "decision" in body


def test_default_allowed_dirs_include_tmp() -> None:
    server = HTTPServer(MagicMock())
    resolved = [d.resolve() for d in server.allowed_dirs]
    import tempfile

    assert Path("/tmp").resolve() in resolved or Path(tempfile.gettempdir()).resolve() in resolved


def test_validate_path_allows_tmp_by_default(tmp_path: Path) -> None:
    import tempfile

    server = HTTPServer(MagicMock())
    tmp_file = Path(tempfile.gettempdir()) / "agentshield_test_file.txt"
    resolved, err = server._validate_path(str(tmp_file))
    assert err is None
