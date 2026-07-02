"""HTTP daemon mode for AgentShield.

Exposes a minimal REST API on localhost using Python's asyncio stdlib
(no extra dependencies required).

Endpoints:
  GET  /health       — liveness probe
  POST /scan         — scan a single package
  POST /scan-file    — scan a manifest file
  GET  /posture      — generate a posture report
  POST /sbom         — generate a CycloneDX SBOM

Start with: ``agentshield serve --http [--port 8765]``
"""

from __future__ import annotations

import asyncio
import json
import logging
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_STATUS_TEXT = {
    200: "OK",
    400: "Bad Request",
    403: "Forbidden",
    404: "Not Found",
    413: "Payload Too Large",
    500: "Internal Server Error",
}

# Reject request bodies larger than this to avoid unbounded buffering.
_MAX_BODY_BYTES = 10 * 1024 * 1024

# Hosts that keep the server private to the local machine.
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


class HTTPServer:
    """Minimal asyncio HTTP/1.1 server for AgentShield REST API."""

    DEFAULT_HOST = "127.0.0.1"
    DEFAULT_PORT = 8765

    def __init__(
        self,
        shield: Any,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        allowed_dirs: list[Path] | None = None,
    ) -> None:
        self.shield = shield
        self.host = host
        self.port = port
        if allowed_dirs is not None:
            self.allowed_dirs = list(allowed_dirs)
        else:
            # Default: CWD, home, and system temp dirs (covers /tmp for CI/CD)
            seen: set[Path] = set()
            dirs: list[Path] = []
            for d in [
                Path.cwd(),
                Path.home(),
                Path("/tmp"),
                Path(tempfile.gettempdir()),
            ]:
                r = d.resolve()
                if r not in seen:
                    seen.add(r)
                    dirs.append(d)
            self.allowed_dirs = dirs

    async def start(self) -> None:
        """Start the server and serve requests until cancelled."""
        if self.host not in _LOOPBACK_HOSTS:
            logger.warning(
                "AgentShield HTTP server bound to non-loopback host %r — it has no "
                "authentication and must not be exposed to untrusted networks.",
                self.host,
            )
        server = await asyncio.start_server(self._handle_connection, self.host, self.port)
        addr = server.sockets[0].getsockname()
        logger.info("AgentShield HTTP server listening on http://%s:%s", addr[0], addr[1])
        async with server:
            await server.serve_forever()

    # ── connection handler ────────────────────────────────────────────────────

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            request_line = await reader.readline()
            if not request_line:
                return
            parts = request_line.decode(errors="replace").strip().split(" ", 2)
            if len(parts) < 2:
                return
            method, path = parts[0].upper(), parts[1]

            headers: dict[str, str] = {}
            while True:
                line = await reader.readline()
                if not line or line == b"\r\n":
                    break
                if b":" in line:
                    k, _, v = line.decode(errors="replace").partition(":")
                    headers[k.lower().strip()] = v.strip()

            # DNS-rebinding guard: a browser script pointed at attacker.example
            # (rebound to 127.0.0.1) reaches this unauthenticated API with the
            # attacker's hostname in Host. Only accept loopback/self hostnames.
            if not self._host_header_allowed(headers.get("host")):
                self._write_response(
                    writer,
                    403,
                    {"error": "Forbidden: unexpected Host header"},
                )
                await writer.drain()
                return

            content_length = int(headers.get("content-length", "0") or "0")
            if content_length > _MAX_BODY_BYTES:
                self._write_response(
                    writer,
                    413,
                    {"error": f"Request body exceeds {_MAX_BODY_BYTES} bytes"},
                )
                await writer.drain()
                return
            body = b""
            if content_length > 0:
                body = await reader.readexactly(content_length)

            code, payload = await self._route(method, path, body)
            self._write_response(writer, code, payload)
            await writer.drain()
        except Exception as exc:
            logger.debug("HTTP connection error: %s", exc)
        finally:
            writer.close()

    # ── Host header validation (DNS-rebinding guard) ──────────────────────────

    def _host_header_allowed(self, host_header: str | None) -> bool:
        """Accept only loopback names or the configured bind host.

        HTTP/1.1 requires a Host header; requests without one are rejected.
        The port part (``127.0.0.1:8765``) is ignored.
        """
        if not host_header:
            return False
        host = host_header.strip().lower()
        # Strip port: handle "[::1]:8765", "127.0.0.1:8765", "localhost:8765"
        if host.startswith("["):
            host = host.partition("]")[0].lstrip("[")
        elif host.count(":") == 1:
            host = host.partition(":")[0]
        return host in _LOOPBACK_HOSTS or host == self.host.lower()

    # ── routing ───────────────────────────────────────────────────────────────

    async def _route(self, method: str, path: str, body: bytes) -> tuple[int, Any]:
        try:
            if method == "GET" and path == "/health":
                return 200, {"status": "ok", "service": "agentshield"}

            if method == "GET" and path == "/posture":
                return await self._handle_posture({})

            if method == "POST" and path == "/scan":
                args = json.loads(body) if body else {}
                return await self._handle_scan(args)

            if method == "POST" and path == "/scan-file":
                args = json.loads(body) if body else {}
                return await self._handle_scan_file(args)

            if method == "POST" and path == "/sbom":
                args = json.loads(body) if body else {}
                return await self._handle_sbom(args)

            return 404, {"error": f"No route: {method} {path}"}

        except json.JSONDecodeError:
            return 400, {"error": "Invalid JSON body"}
        except Exception as exc:
            logger.exception("Unhandled error in %s %s", method, path)
            return 500, {"error": str(exc)}

    # ── path validation ───────────────────────────────────────────────────────

    def _validate_path(self, path_str: str) -> tuple[Path, str | None]:
        """Resolve *path_str* and verify it is inside an allowed directory.

        Returns ``(resolved_path, None)`` on success or ``(resolved_path,
        error_message)`` when the path escapes every allowed directory.
        """
        path = Path(path_str).resolve()
        for allowed in self.allowed_dirs:
            try:
                if path.is_relative_to(allowed.resolve()):
                    return path, None
            except ValueError:
                continue
        return path, "Access denied: path is outside allowed directories"

    # ── handlers ──────────────────────────────────────────────────────────────

    async def _handle_scan(self, args: dict[str, Any]) -> tuple[int, Any]:
        from agentshield.core.models import Ecosystem, ScanRequest

        try:
            ecosystem_str = str(args.get("ecosystem", "pypi")).lower()
            try:
                ecosystem = Ecosystem(ecosystem_str)
            except ValueError:
                return 400, {"error": f"Unknown ecosystem: {ecosystem_str!r}"}

            request = ScanRequest(
                package=args["package"],
                version=args.get("version"),
                ecosystem=ecosystem,
                deep=bool(args.get("deep", False)),
                context_hint=args.get("context_hint"),
                source="http",
                transitive=bool(args.get("transitive", False)),
                transitive_depth=int(args.get("transitive_depth", 3)),
                check_licenses=bool(args.get("check_licenses", False)),
            )
            result = await self.shield.ascan(request)

            return 200, {
                "decision": result.decision.action.value,
                "reason": result.decision.reason,
                "max_severity": result.max_severity.value,
                "trust_score": result.trust_score,
                "trust_label": result.trust_label,
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
        except KeyError as exc:
            return 400, {"error": f"Missing required field: {exc}"}
        except Exception as exc:
            return 500, {"error": str(exc)}

    async def _handle_scan_file(self, args: dict[str, Any]) -> tuple[int, Any]:
        try:
            path_str = args["path"]
        except KeyError:
            return 400, {"error": "Missing required field: 'path'"}

        resolved, err = self._validate_path(path_str)
        if err:
            return 403, {"error": err}

        try:
            result = await self.shield.ascan_file(resolved)
            return 200, {
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
        except Exception as exc:
            return 500, {"error": str(exc)}

    async def _handle_sbom(self, args: dict[str, Any]) -> tuple[int, Any]:
        from agentshield.core.sbom import generate_sbom_json

        try:
            path_str = args["path"]
        except KeyError:
            return 400, {"error": "Missing required field: 'path'"}

        resolved, err = self._validate_path(path_str)
        if err:
            return 403, {"error": err}

        try:
            result = await self.shield.ascan_file(resolved)
            sbom_text = generate_sbom_json(result.results, source_path=path_str)
            return 200, json.loads(sbom_text)
        except Exception as exc:
            return 500, {"error": str(exc)}

    async def _handle_posture(self, _args: dict[str, Any]) -> tuple[int, Any]:
        from agentshield.core.config import Config
        from agentshield.reports.posture import run_posture_check
        from agentshield.reports.renderers import render_json

        try:
            cfg = Config.load(None)
            report = await run_posture_check(
                db_path=cfg.cache.db_path,
                tool_names=None,
                async_log_hours=24,
                skip_package_scan=False,
            )
            return 200, json.loads(render_json(report))
        except Exception as exc:
            return 500, {"error": str(exc)}

    # ── response writer ───────────────────────────────────────────────────────

    @staticmethod
    def _write_response(writer: asyncio.StreamWriter, code: int, payload: Any) -> None:
        body = json.dumps(payload).encode()
        status_text = _STATUS_TEXT.get(code, "Unknown")
        header = (
            f"HTTP/1.1 {code} {status_text}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()
        writer.write(header + body)
