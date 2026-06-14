"""Unit tests for the transitive dependency resolver (deps.py).

All network calls are intercepted by respx; no real HTTP traffic is made.
"""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from agentshield.core.deps import resolve_deps
from agentshield.core.models import Ecosystem

PYPI_BASE = "https://pypi.org/pypi"
NPM_BASE = "https://registry.npmjs.org"
CRATES_BASE = "https://crates.io/api/v1/crates"


# ── helpers ───────────────────────────────────────────────────────────────────


def _pypi_resp(requires_dist: list[str]) -> Response:
    return Response(200, json={"info": {"requires_dist": requires_dist}})


def _npm_resp(deps: dict[str, str]) -> Response:
    return Response(200, json={"dependencies": deps})


def _crates_meta_resp(version: str) -> Response:
    return Response(200, json={"versions": [{"num": version}]})


def _crates_deps_resp(deps: list[dict[str, object]]) -> Response:
    return Response(200, json={"dependencies": deps})


# ── PyPI ──────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_pypi_direct_deps_returned():
    respx.get(f"{PYPI_BASE}/requests/json").mock(
        return_value=_pypi_resp(
            [
                "urllib3 (>=1.21.1,<3)",
                "charset-normalizer (>=2,<4)",
                "idna (>=2.5,<4)",
                "certifi (>=2017.4.17)",
            ]
        )
    )
    deps = await resolve_deps("requests", None, Ecosystem.PYPI, max_depth=1)
    names = {d.package for d in deps}
    assert names == {"urllib3", "charset-normalizer", "idna", "certifi"}


@pytest.mark.asyncio
@respx.mock
async def test_pypi_extras_skipped():
    respx.get(f"{PYPI_BASE}/requests/json").mock(
        return_value=_pypi_resp(
            [
                "certifi",
                "PySocks (!=1.5.7,>=1.5.6) ; extra == 'socks'",
                "brotli>=1.0.9 ; extra == 'brotli'",
            ]
        )
    )
    deps = await resolve_deps("requests", None, Ecosystem.PYPI, max_depth=1)
    names = {d.package for d in deps}
    assert names == {"certifi"}
    assert "pysocks" not in names
    assert "brotli" not in names


@pytest.mark.asyncio
@respx.mock
async def test_pypi_pinned_version_url():
    respx.get(f"{PYPI_BASE}/requests/2.31.0/json").mock(return_value=_pypi_resp(["certifi"]))
    deps = await resolve_deps("requests", "2.31.0", Ecosystem.PYPI, max_depth=1)
    assert any(d.package == "certifi" for d in deps)


@pytest.mark.asyncio
@respx.mock
async def test_pypi_empty_requires_dist():
    respx.get(f"{PYPI_BASE}/simplepkg/json").mock(return_value=_pypi_resp([]))
    deps = await resolve_deps("simplepkg", None, Ecosystem.PYPI, max_depth=1)
    assert deps == []


@pytest.mark.asyncio
@respx.mock
async def test_pypi_http_error_returns_empty():
    respx.get(f"{PYPI_BASE}/ghost-pkg/json").mock(return_value=Response(404))
    deps = await resolve_deps("ghost-pkg", None, Ecosystem.PYPI, max_depth=1)
    assert deps == []


# ── npm ───────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_npm_direct_deps_returned():
    respx.get(f"{NPM_BASE}/express/latest").mock(
        return_value=_npm_resp(
            {
                "accepts": "~1.3.8",
                "array-flatten": "1.1.1",
                "body-parser": "1.20.1",
            }
        )
    )
    deps = await resolve_deps("express", None, Ecosystem.NPM, max_depth=1)
    names = {d.package for d in deps}
    assert names == {"accepts", "array-flatten", "body-parser"}


@pytest.mark.asyncio
@respx.mock
async def test_npm_pinned_version():
    respx.get(f"{NPM_BASE}/lodash/4.17.21").mock(return_value=_npm_resp({}))
    deps = await resolve_deps("lodash", "4.17.21", Ecosystem.NPM, max_depth=1)
    assert deps == []


@pytest.mark.asyncio
@respx.mock
async def test_npm_no_dependencies_key():
    respx.get(f"{NPM_BASE}/minimal/latest").mock(
        return_value=Response(200, json={"name": "minimal"})
    )
    deps = await resolve_deps("minimal", None, Ecosystem.NPM, max_depth=1)
    assert deps == []


# ── Cargo ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_cargo_pinned_version_deps():
    respx.get(f"{CRATES_BASE}/serde/1.0.0/dependencies").mock(
        return_value=_crates_deps_resp(
            [
                {"crate_id": "serde_derive", "req": "=1.0.0", "kind": "normal"},
                {"crate_id": "serde_test", "req": "=1.0.0", "kind": "dev"},
            ]
        )
    )
    deps = await resolve_deps("serde", "1.0.0", Ecosystem.CARGO, max_depth=1)
    names = {d.package for d in deps}
    assert "serde_derive" in names
    assert "serde_test" not in names  # dev dep filtered out


@pytest.mark.asyncio
@respx.mock
async def test_cargo_latest_version_lookup():
    respx.get(f"{CRATES_BASE}/tokio").mock(return_value=_crates_meta_resp("1.35.0"))
    respx.get(f"{CRATES_BASE}/tokio/1.35.0/dependencies").mock(
        return_value=_crates_deps_resp([{"crate_id": "mio", "req": "0.8", "kind": "normal"}])
    )
    deps = await resolve_deps("tokio", None, Ecosystem.CARGO, max_depth=1)
    assert any(d.package == "mio" for d in deps)


@pytest.mark.asyncio
@respx.mock
async def test_cargo_no_versions_returns_empty():
    respx.get(f"{CRATES_BASE}/ghost-crate").mock(return_value=Response(200, json={"versions": []}))
    deps = await resolve_deps("ghost-crate", None, Ecosystem.CARGO, max_depth=1)
    assert deps == []


# ── Depth limiting ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_depth_limit_respected():
    # root → a → b → c  (depth=2 should stop after 'b' deps, not fetch 'c')
    respx.get(f"{PYPI_BASE}/root/json").mock(return_value=_pypi_resp(["a"]))
    respx.get(f"{PYPI_BASE}/a/json").mock(return_value=_pypi_resp(["b"]))
    respx.get(f"{PYPI_BASE}/b/json").mock(return_value=_pypi_resp(["c"]))
    # 'c' should never be fetched — respx will raise if it is

    deps = await resolve_deps("root", None, Ecosystem.PYPI, max_depth=2)
    names = {d.package for d in deps}
    assert "a" in names
    assert "b" in names
    assert "c" not in names


@pytest.mark.asyncio
@respx.mock
async def test_depth_1_returns_only_direct():
    respx.get(f"{PYPI_BASE}/root/json").mock(return_value=_pypi_resp(["a"]))
    # 'a' should never be fetched at depth=1

    deps = await resolve_deps("root", None, Ecosystem.PYPI, max_depth=1)
    names = {d.package for d in deps}
    assert names == {"a"}


# ── Circular dependency handling ──────────────────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_circular_dep_does_not_recurse_infinitely():
    # a → b → a (circular)
    respx.get(f"{PYPI_BASE}/a/json").mock(return_value=_pypi_resp(["b"]))
    respx.get(f"{PYPI_BASE}/b/json").mock(return_value=_pypi_resp(["a"]))

    deps = await resolve_deps("a", None, Ecosystem.PYPI, max_depth=5)
    names = {d.package for d in deps}
    # Both are discovered but no infinite loop
    assert "b" in names
    assert "a" not in names  # root is seeded in visited, never added to collected


@pytest.mark.asyncio
@respx.mock
async def test_diamond_dep_deduplicated():
    # root → [a, b]; a → c; b → c  (diamond: c appears once)
    respx.get(f"{PYPI_BASE}/root/json").mock(return_value=_pypi_resp(["a", "b"]))
    respx.get(f"{PYPI_BASE}/a/json").mock(return_value=_pypi_resp(["c"]))
    respx.get(f"{PYPI_BASE}/b/json").mock(return_value=_pypi_resp(["c"]))

    deps = await resolve_deps("root", None, Ecosystem.PYPI, max_depth=3)
    names = [d.package for d in deps]
    # 'c' must appear exactly once
    assert names.count("c") == 1


# ── Result aggregation in scanner ─────────────────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_scanner_transitive_results_populated(tmp_path):
    from unittest.mock import patch

    from agentshield.core.config import Config
    from agentshield.core.models import ScanRequest
    from agentshield.core.scanner import AgentShield

    OSV_URL = "https://api.osv.dev/v1/query"
    respx.post(OSV_URL).mock(return_value=Response(200, json={"vulns": []}))

    # Only one transitive dep: certifi
    respx.get(f"{PYPI_BASE}/requests/json").mock(return_value=_pypi_resp(["certifi"]))

    cfg = Config.model_validate({"cache": {"db_path": str(tmp_path / "cache.db")}})
    shield = AgentShield(config=cfg)
    request = ScanRequest(
        package="requests",
        ecosystem=Ecosystem.PYPI,
        transitive=True,
        transitive_depth=1,
    )

    with patch("agentshield.analyzers.typosquatting.TyposquattingChecker._load", return_value=[]):
        result = await shield.ascan(request)

    assert len(result.transitive_results) == 1
    assert result.transitive_results[0].request.package == "certifi"


@pytest.mark.asyncio
@respx.mock
async def test_scanner_transitive_false_no_transitive_results(tmp_path):
    from unittest.mock import patch

    from agentshield.core.config import Config
    from agentshield.core.models import ScanRequest
    from agentshield.core.scanner import AgentShield

    OSV_URL = "https://api.osv.dev/v1/query"
    respx.post(OSV_URL).mock(return_value=Response(200, json={"vulns": []}))

    cfg = Config.model_validate({"cache": {"db_path": str(tmp_path / "cache.db")}})
    shield = AgentShield(config=cfg)
    request = ScanRequest(
        package="requests",
        ecosystem=Ecosystem.PYPI,
        transitive=False,
    )

    with patch("agentshield.analyzers.typosquatting.TyposquattingChecker._load", return_value=[]):
        result = await shield.ascan(request)

    assert result.transitive_results == []
