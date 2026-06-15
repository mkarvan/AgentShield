"""Scanning index proxy — the manager-agnostic **primary** enforcement gate.

Package managers are pointed at this proxy instead of the public index
(``PIP_INDEX_URL``/``UV_INDEX_URL`` for pip/uv, ``npm_config_registry`` for
npm/yarn/pnpm/bun).  Every package the resolver asks for is scanned *before* it
is served: a clean package is redirected to the real upstream index; a blocked
package returns HTTP 403 so the install fails.  This is the primary gate because
it sees the *actually resolved* package names — including transitive
dependencies, which are scanned too — regardless of how the install was invoked,
and cannot be fooled by argv tricks.  The PATH shim and ``execve`` interceptor
are the secondary/baseline layers that cover what the proxy cannot.

Use :func:`proxy_env` / :func:`proxy_export_lines` to obtain the environment
that routes managers through the proxy.

Caveats: it does not see installs from local files, direct wheel/tarball URLs,
or VCS (``git+…``) references that bypass the index; cargo (source-replacement)
and go (``GOPROXY`` speaks a different protocol) are **not** routed through the
proxy and are covered by the shim/execve layers instead.  Per-manager index
configuration must be in place (and is itself unset-able).

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


# ── env injection (route managers through the proxy) ──────────────────────────


def proxy_url(host: str, port: int) -> str:
    return f"http://{host}:{port}"


def proxy_env(host: str = "127.0.0.1", port: int = 8799) -> dict[str, str]:
    """Environment variables that route supported managers through the proxy.

    Covers pip/uv (PyPI simple index) and npm/yarn/pnpm/bun (npm registry).
    cargo and go are intentionally absent — see the module docstring.
    """
    base = proxy_url(host, port)
    return {
        "PIP_INDEX_URL": f"{base}/simple/",
        "UV_INDEX_URL": f"{base}/simple/",
        "npm_config_registry": f"{base}/npm/",
    }


def proxy_export_lines(host: str = "127.0.0.1", port: int = 8799) -> list[str]:
    """Shell ``export`` lines for :func:`proxy_env`."""
    return [f'export {k}="{v}"' for k, v in proxy_env(host, port).items()]


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
    """Wraps the scanner with a single ``decide`` entrypoint for the proxy.

    ``transitive`` (default on) makes each decision also resolve and scan the
    package's dependency tree, so a clean package depending on a malicious one is
    still blocked.
    """

    def __init__(
        self,
        config: Config | None = None,
        *,
        transitive: bool = True,
        transitive_depth: int = 3,
    ) -> None:
        self.shield = AgentShield(config=config)
        self.transitive = transitive
        self.transitive_depth = transitive_depth

    def decide(self, package: str, ecosystem: Ecosystem) -> tuple[bool, str]:
        """Return ``(allowed, reason)`` for *package* and its deps. Fails closed."""
        request = ScanRequest(
            package=package,
            ecosystem=ecosystem,
            source="proxy",
            transitive=self.transitive,
            transitive_depth=self.transitive_depth,
        )
        try:
            result = asyncio.run(self.shield.ascan(request))
        except Exception as exc:  # noqa: BLE001 — fail closed
            logger.warning("proxy scan error for %s: %s", package, exc)
            return False, f"scan failed ({exc}); blocking to fail closed"
        if result.decision.action == DecisionAction.BLOCK:
            return False, result.decision.reason
        # Block if any resolved transitive dependency is itself blocked.
        for dep in result.transitive_results:
            if dep.decision.action == DecisionAction.BLOCK:
                return (
                    False,
                    f"transitive dependency '{dep.request.package}': {dep.decision.reason}",
                )
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


def serve(
    host: str = "127.0.0.1",
    port: int = 8799,
    config: Config | None = None,
    *,
    transitive: bool = True,
) -> None:
    """Run the scanning proxy until interrupted."""
    screen = ProxyScreen(config=config, transitive=transitive)
    httpd = ThreadingHTTPServer((host, port), _make_handler(screen))
    logger.info("AgentShield index proxy listening on http://%s:%d", host, port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:  # pragma: no cover
        pass
    finally:
        httpd.server_close()
