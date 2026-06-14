"""Tests for agentshield_posture MCP tool handler."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agentshield.reports.models import PostureReport
from agentshield.server.mcp import MCPServer


def _make_report(**kwargs: object) -> PostureReport:
    defaults = dict(
        generated_at=datetime(2026, 6, 13, 12, 0, 0, tzinfo=UTC),
        risk_score=10,
        risk_label="LOW",
        packages_scanned=0,
        critical_count=0,
        high_count=0,
        medium_count=0,
        low_count=0,
        info_count=0,
    )
    defaults.update(kwargs)
    return PostureReport(**defaults)  # type: ignore[arg-type]


def _make_server() -> MCPServer:
    return MCPServer(shield=MagicMock())


# ── helper: invoke via handle_message ────────────────────────────────────────


async def _call_posture(server: MCPServer, args: dict) -> dict:
    msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "agentshield_posture", "arguments": args},
    }
    response = await server.handle_message(msg)
    assert response is not None
    return response


# ── tools/list declares the right schema ─────────────────────────────────────


@pytest.mark.asyncio
async def test_tools_list_includes_posture() -> None:
    server = _make_server()
    resp = await server.handle_message(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    )
    assert resp is not None
    tool_names = [t["name"] for t in resp["result"]["tools"]]
    assert "agentshield_posture" in tool_names


@pytest.mark.asyncio
async def test_posture_tool_schema_has_expected_params() -> None:
    server = _make_server()
    resp = await server.handle_message(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    )
    assert resp is not None
    posture_tool = next(t for t in resp["result"]["tools"] if t["name"] == "agentshield_posture")
    props = posture_tool["inputSchema"]["properties"]
    assert "tool_names" in props
    assert "log_hours" in props
    assert "skip_packages" in props


# ── successful posture call ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_posture_returns_json_report() -> None:
    report = _make_report()
    server = _make_server()

    with (
        patch("agentshield.core.config.Config") as mock_cfg_cls,
        patch("agentshield.reports.posture.run_posture_check", new_callable=AsyncMock) as mock_run,
        patch("agentshield.reports.renderers.render_json", return_value=report.model_dump_json()),
    ):
        mock_cfg_cls.load.return_value = MagicMock(cache=MagicMock(db_path=Path("/tmp/test.db")))
        mock_run.return_value = report

        resp = await _call_posture(server, {})

    content = resp["result"]["content"]
    assert len(content) == 1
    assert content[0]["type"] == "text"
    payload = json.loads(content[0]["text"])
    assert payload["risk_score"] == 10
    assert "isError" not in resp["result"]


@pytest.mark.asyncio
async def test_posture_passes_tool_names() -> None:
    report = _make_report()
    server = _make_server()

    with (
        patch("agentshield.core.config.Config") as mock_cfg_cls,
        patch("agentshield.reports.posture.run_posture_check", new_callable=AsyncMock) as mock_run,
        patch("agentshield.reports.renderers.render_json", return_value=report.model_dump_json()),
    ):
        mock_cfg_cls.load.return_value = MagicMock(cache=MagicMock(db_path=Path("/tmp/test.db")))
        mock_run.return_value = report

        await _call_posture(server, {"tool_names": ["bash", "read_file"]})

    mock_run.assert_awaited_once()
    _, kwargs = mock_run.call_args
    assert kwargs["tool_names"] == ["bash", "read_file"]


@pytest.mark.asyncio
async def test_posture_passes_log_hours() -> None:
    report = _make_report()
    server = _make_server()

    with (
        patch("agentshield.core.config.Config") as mock_cfg_cls,
        patch("agentshield.reports.posture.run_posture_check", new_callable=AsyncMock) as mock_run,
        patch("agentshield.reports.renderers.render_json", return_value=report.model_dump_json()),
    ):
        mock_cfg_cls.load.return_value = MagicMock(cache=MagicMock(db_path=Path("/tmp/test.db")))
        mock_run.return_value = report

        await _call_posture(server, {"log_hours": 48})

    _, kwargs = mock_run.call_args
    assert kwargs["async_log_hours"] == 48


@pytest.mark.asyncio
async def test_posture_passes_skip_packages() -> None:
    report = _make_report()
    server = _make_server()

    with (
        patch("agentshield.core.config.Config") as mock_cfg_cls,
        patch("agentshield.reports.posture.run_posture_check", new_callable=AsyncMock) as mock_run,
        patch("agentshield.reports.renderers.render_json", return_value=report.model_dump_json()),
    ):
        mock_cfg_cls.load.return_value = MagicMock(cache=MagicMock(db_path=Path("/tmp/test.db")))
        mock_run.return_value = report

        await _call_posture(server, {"skip_packages": True})

    _, kwargs = mock_run.call_args
    assert kwargs["skip_package_scan"] is True


@pytest.mark.asyncio
async def test_posture_defaults_log_hours_to_24() -> None:
    report = _make_report()
    server = _make_server()

    with (
        patch("agentshield.core.config.Config") as mock_cfg_cls,
        patch("agentshield.reports.posture.run_posture_check", new_callable=AsyncMock) as mock_run,
        patch("agentshield.reports.renderers.render_json", return_value=report.model_dump_json()),
    ):
        mock_cfg_cls.load.return_value = MagicMock(cache=MagicMock(db_path=Path("/tmp/test.db")))
        mock_run.return_value = report

        await _call_posture(server, {})

    _, kwargs = mock_run.call_args
    assert kwargs["async_log_hours"] == 24


@pytest.mark.asyncio
async def test_posture_defaults_skip_packages_to_false() -> None:
    report = _make_report()
    server = _make_server()

    with (
        patch("agentshield.core.config.Config") as mock_cfg_cls,
        patch("agentshield.reports.posture.run_posture_check", new_callable=AsyncMock) as mock_run,
        patch("agentshield.reports.renderers.render_json", return_value=report.model_dump_json()),
    ):
        mock_cfg_cls.load.return_value = MagicMock(cache=MagicMock(db_path=Path("/tmp/test.db")))
        mock_run.return_value = report

        await _call_posture(server, {})

    _, kwargs = mock_run.call_args
    assert kwargs["skip_package_scan"] is False


@pytest.mark.asyncio
async def test_posture_empty_tool_names_becomes_none() -> None:
    report = _make_report()
    server = _make_server()

    with (
        patch("agentshield.core.config.Config") as mock_cfg_cls,
        patch("agentshield.reports.posture.run_posture_check", new_callable=AsyncMock) as mock_run,
        patch("agentshield.reports.renderers.render_json", return_value=report.model_dump_json()),
    ):
        mock_cfg_cls.load.return_value = MagicMock(cache=MagicMock(db_path=Path("/tmp/test.db")))
        mock_run.return_value = report

        await _call_posture(server, {"tool_names": []})

    _, kwargs = mock_run.call_args
    assert kwargs["tool_names"] is None


# ── error handling ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_posture_returns_error_on_exception() -> None:
    server = _make_server()

    with (
        patch("agentshield.core.config.Config") as mock_cfg_cls,
        patch(
            "agentshield.reports.posture.run_posture_check",
            new_callable=AsyncMock,
            side_effect=RuntimeError("db locked"),
        ),
    ):
        mock_cfg_cls.load.return_value = MagicMock(cache=MagicMock(db_path=Path("/tmp/test.db")))

        resp = await _call_posture(server, {})

    result = resp["result"]
    assert result.get("isError") is True
    assert "db locked" in result["content"][0]["text"]
