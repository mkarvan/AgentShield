"""End-to-end tests for the MCP tool server.

Tests the full JSON-RPC message lifecycle: initialize → tools/list → tools/call.
The MCPServer.handle_message() method is called directly (no subprocess / real
stdio) to keep tests fast and deterministic.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from agentshield.core.config import Config
from agentshield.core.models import (
    Decision,
    DecisionAction,
    Ecosystem,
    Finding,
    ScanRequest,
    ScanResult,
    Severity,
)
from agentshield.core.scanner import AgentShield
from agentshield.server.mcp import MCPServer


def _make_server(tmp_path: Path, extra_config: dict | None = None) -> MCPServer:
    base: dict = {"cache": {"db_path": str(tmp_path / "mcp_test.db")}}
    if extra_config:
        base.update(extra_config)
    config = Config.model_validate(base)
    shield = AgentShield(config=config)
    return MCPServer(shield)


def _clean_result(request: ScanRequest) -> ScanResult:
    return ScanResult(
        request=request,
        findings=[],
        max_severity=Severity.NONE,
        decision=Decision(action=DecisionAction.ALLOW, reason="No issues found"),
    )


def _block_result(request: ScanRequest) -> ScanResult:
    finding = Finding(
        rule_id="T1.1",
        title="Known malicious package",
        severity=Severity.CRITICAL,
        source="malicious_db",
    )
    return ScanResult(
        request=request,
        findings=[finding],
        max_severity=Severity.CRITICAL,
        decision=Decision(
            action=DecisionAction.BLOCK,
            reason="BLOCK due to T1.1",
            findings=[finding],
        ),
    )


# ── Handshake ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_initialize_returns_server_info(tmp_path):
    server = _make_server(tmp_path)
    response = await server.handle_message({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "clientInfo": {"name": "test"}},
    })

    assert response is not None
    assert response["jsonrpc"] == "2.0"
    assert response["id"] == 1
    result = response["result"]
    assert result["serverInfo"]["name"] == "agentshield"
    assert "protocolVersion" in result


@pytest.mark.asyncio
async def test_initialized_notification_returns_none(tmp_path):
    server = _make_server(tmp_path)
    response = await server.handle_message({
        "jsonrpc": "2.0",
        "method": "initialized",
    })
    assert response is None


# ── tools/list ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_tools_list_returns_expected_tools(tmp_path):
    server = _make_server(tmp_path)
    response = await server.handle_message({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {},
    })

    assert response is not None
    tools = response["result"]["tools"]
    tool_names = {t["name"] for t in tools}
    assert "agentshield_scan" in tool_names
    assert "agentshield_posture" in tool_names


@pytest.mark.asyncio
async def test_scan_tool_has_required_input_schema(tmp_path):
    server = _make_server(tmp_path)
    response = await server.handle_message({
        "jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}
    })
    tools = {t["name"]: t for t in response["result"]["tools"]}
    scan_tool = tools["agentshield_scan"]
    required = scan_tool["inputSchema"]["required"]
    assert "package" in required
    assert "ecosystem" in required


# ── tools/call: agentshield_scan ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_scan_clean_package_returns_allow(tmp_path):
    server = _make_server(tmp_path)
    req = ScanRequest(package="requests", ecosystem=Ecosystem.PYPI)

    with patch.object(server.shield, "ascan", new=AsyncMock(return_value=_clean_result(req))):
        response = await server.handle_message({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "agentshield_scan",
                "arguments": {"package": "requests", "ecosystem": "pypi"},
            },
        })

    assert response is not None
    content = response["result"]["content"][0]["text"]
    payload = json.loads(content)
    assert payload["decision"] == "ALLOW"
    assert payload["findings"] == []


@pytest.mark.asyncio
async def test_scan_blocked_package_returns_block_decision(tmp_path):
    server = _make_server(tmp_path)
    req = ScanRequest(package="evil-pkg", ecosystem=Ecosystem.PYPI)

    with patch.object(server.shield, "ascan", new=AsyncMock(return_value=_block_result(req))):
        response = await server.handle_message({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "agentshield_scan",
                "arguments": {"package": "evil-pkg", "ecosystem": "pypi"},
            },
        })

    content = response["result"]["content"][0]["text"]
    payload = json.loads(content)
    assert payload["decision"] == "BLOCK"
    assert len(payload["findings"]) == 1
    assert payload["findings"][0]["rule_id"] == "T1.1"
    assert payload["max_severity"] == "CRITICAL"


@pytest.mark.asyncio
async def test_mcp_scan_denylist_no_network(tmp_path):
    """Denylisted packages are blocked without any network calls."""
    server = _make_server(tmp_path, {"denylist": ["colouredlogs"]})

    response = await server.handle_message({
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": {
            "name": "agentshield_scan",
            "arguments": {"package": "colouredlogs", "ecosystem": "pypi"},
        },
    })

    content = response["result"]["content"][0]["text"]
    payload = json.loads(content)
    assert payload["decision"] == "BLOCK"


@pytest.mark.asyncio
async def test_scan_missing_package_returns_error(tmp_path):
    server = _make_server(tmp_path)
    response = await server.handle_message({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "agentshield_scan",
            "arguments": {"ecosystem": "pypi"},   # package is missing
        },
    })

    assert response is not None
    result = response["result"]
    assert result.get("isError") is True


@pytest.mark.asyncio
async def test_scan_unknown_ecosystem_returns_error(tmp_path):
    server = _make_server(tmp_path)
    response = await server.handle_message({
        "jsonrpc": "2.0",
        "id": 8,
        "method": "tools/call",
        "params": {
            "name": "agentshield_scan",
            "arguments": {"package": "some-pkg", "ecosystem": "maven"},
        },
    })

    result = response["result"]
    assert result.get("isError") is True


@pytest.mark.asyncio
async def test_scan_context_hint_forwarded(tmp_path):
    server = _make_server(tmp_path)

    captured: list[ScanRequest] = []

    async def _mock_scan(r: ScanRequest) -> ScanResult:
        captured.append(r)
        return _clean_result(r)

    with patch.object(server.shield, "ascan", new=_mock_scan):
        await server.handle_message({
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {
                "name": "agentshield_scan",
                "arguments": {
                    "package": "flask",
                    "ecosystem": "pypi",
                    "context_hint": "Building a web API",
                },
            },
        })

    assert captured[0].context_hint == "Building a web API"
    assert captured[0].source == "mcp"


# ── tools/call: agentshield_posture ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_posture_tool_returns_not_implemented_message(tmp_path):
    server = _make_server(tmp_path)
    response = await server.handle_message({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/call",
        "params": {"name": "agentshield_posture", "arguments": {}},
    })

    content = response["result"]["content"][0]["text"]
    assert "Phase 4" in content or "not yet" in content.lower()


# ── Unknown method / tool ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_unknown_method_returns_error(tmp_path):
    server = _make_server(tmp_path)
    response = await server.handle_message({
        "jsonrpc": "2.0",
        "id": 11,
        "method": "nonexistent/method",
        "params": {},
    })

    assert response is not None
    assert "error" in response
    assert response["error"]["code"] == -32601


@pytest.mark.asyncio
async def test_unknown_tool_returns_is_error(tmp_path):
    server = _make_server(tmp_path)
    response = await server.handle_message({
        "jsonrpc": "2.0",
        "id": 12,
        "method": "tools/call",
        "params": {"name": "nonexistent_tool", "arguments": {}},
    })

    result = response["result"]
    assert result.get("isError") is True


@pytest.mark.asyncio
async def test_notification_without_id_returns_none(tmp_path):
    server = _make_server(tmp_path)
    # Notification: no id, unknown method
    response = await server.handle_message({
        "jsonrpc": "2.0",
        "method": "some/notification",
    })
    assert response is None


# ── ping ──────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_ping_returns_empty_result(tmp_path):
    server = _make_server(tmp_path)
    response = await server.handle_message({
        "jsonrpc": "2.0",
        "id": 13,
        "method": "ping",
        "params": {},
    })
    assert response is not None
    assert response["result"] == {}
