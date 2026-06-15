"""Scanning index proxy — the manager-agnostic primary gate.

Package managers can be pointed at a proxy instead of the public index
(``PIP_INDEX_URL``, ``npm_config_registry``, …).  Every package the resolver
asks for is scanned *before* it is served: a clean package is redirected to the
real upstream index; a blocked package returns HTTP 403 so the install fails.

Advantages over command parsing: it sees the *actually resolved* package names
(and, via repeated requests, transitive dependencies) regardless of how the
install was invoked, and cannot be fooled by argv tricks.

Caveats: it does not see installs from local files, direct wheel/tarball URLs,
or VCS (``git+…``) references that bypass the index, and per-manager index
configuration must be in place (and is itself unset-able). It therefore
complements — not replaces — the shim and execve layers.

This module is intentionally dependency-light (stdlib ``http.server``); the
scan verdict is delegated to :class:`agentshield.core.scanner.AgentShield`.
"""

from __future__ import annotations

import asyncio
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

from agentshield.core.config import Config
from agentshield.core.models import DecisionAction, Ecosystem, ScanRequest
from agentshield.core.scanner import AgentShield

logger = logging.getLogger(__name__)

# Upstream indexes a cleared package is redirected to.
_UPSTREAM: dict[Ecosystem, str] = {
    Ecosystem.PYPI: "https://pypi.org/simple",
    Ecosystem.NPM: "https://registry.npmjs.org",
}


def parse_request_path(path: str) -> tuple[Ecosystem, str] | None:
    """Map an index request path to ``(ecosystem, package)``.

    Recognises pip's simple-index layout (``/simple/<pkg>/`` or
    ``/pypi/simple/<pkg>/``) and npm's registry layout (``/npm/<pkg>`` or a
    bare ``/<pkg>``).  Returns ``None`` for paths that don't name a package
    (e.g. the index root).
    """
    clean = unquote(path.split("?", 1)[0]).strip("/")
    if not clean:
        return None
    parts = clean.split("/")
    # pip simple index: [pypi/]simple/<pkg>[/...]
    if "simple" in parts:
        idx = parts.index("simple")
        if idx + 1 < len(parts) and parts[idx + 1]:
            return Ecosystem.PYPI, parts[idx + 1]
        return None
    # npm: npm/<pkg> or npm/@scope/pkg
    if parts[0] == "npm" and len(parts) > 1:
        pkg = "/".join(parts[1:3]) if parts[1].startswith("@") and len(parts) > 2 else parts[1]
        return Ecosystem.NPM, pkg
    # bare /<pkg> or /@scope/pkg → treated as npm registry
    pkg = "/".join(parts[:2]) if parts[0].startswith("@") and len(parts) > 1 else parts[0]
    return Ecosystem.NPM, pkg


class ProxyScreen:
    """Wraps the scanner with a single ``decide`` entrypoint for the proxy."""

    def __init__(self, config: Config | None = None) -> None:
        self.shield = AgentShield(config=config)

    def decide(self, package: str, ecosystem: Ecosystem) -> tuple[bool, str]:
        """Return ``(allowed, reason)`` for *package*. Fails closed on error."""
        request = ScanRequest(package=package, ecosystem=ecosystem, source="proxy")
        try:
            result = asyncio.run(self.shield.ascan(request))
        except Exception as exc:  # noqa: BLE001 — fail closed
            logger.warning("proxy scan error for %s: %s", package, exc)
            return False, f"scan failed ({exc}); blocking to fail closed"
        if result.decision.action == DecisionAction.BLOCK:
            return False, result.decision.reason
        return True, result.decision.reason


def _make_handler(screen: ProxyScreen) -> type[BaseHTTPRequestHandler]:
    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 (http.server API)
            parsed = parse_request_path(self.path)
            if parsed is None:
                self.send_error(404, "not a package request")
                return
            ecosystem, package = parsed
            allowed, reason = screen.decide(package, ecosystem)
            if not allowed:
                body = f"AgentShield blocked '{package}': {reason}".encode()
                self.send_response(403)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            upstream = _UPSTREAM.get(ecosystem)
            self.send_response(302)
            self.send_header("Location", f"{upstream}/{package}/")
            self.end_headers()

        def log_message(self, fmt: str, *args: object) -> None:  # quieter logs
            logger.debug("proxy %s", fmt % args)

    return _Handler


def serve(host: str = "127.0.0.1", port: int = 8799, config: Config | None = None) -> None:
    """Run the scanning proxy until interrupted."""
    screen = ProxyScreen(config=config)
    httpd = ThreadingHTTPServer((host, port), _make_handler(screen))
    logger.info("AgentShield index proxy listening on http://%s:%d", host, port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:  # pragma: no cover
        pass
    finally:
        httpd.server_close()
