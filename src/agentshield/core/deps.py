"""Transitive dependency resolver for PyPI, npm, and Cargo registries."""

from __future__ import annotations

import logging
import re
from typing import Any, NamedTuple

import httpx

from agentshield.core.models import Ecosystem

logger = logging.getLogger(__name__)

_TIMEOUT = 10.0
_PYPI_BASE = "https://pypi.org/pypi"
_NPM_BASE = "https://registry.npmjs.org"
_CRATES_BASE = "https://crates.io/api/v1/crates"

# Matches the package name at the start of a PEP 508 requirement string.
_REQ_NAME_RE = re.compile(r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)")
# Matches a parenthesised version specifier, e.g. "(>=1.0,<2)".
_REQ_VERSION_RE = re.compile(r"\(([^)]+)\)")


class DepSpec(NamedTuple):
    """A single (direct or transitive) dependency."""

    package: str
    version_constraint: str | None
    ecosystem: Ecosystem


async def resolve_deps(
    package: str,
    version: str | None,
    ecosystem: Ecosystem,
    *,
    max_depth: int = 3,
) -> list[DepSpec]:
    """Resolve all transitive dependencies up to *max_depth* levels deep.

    Returns a flat, deduplicated list of every reachable dependency.
    Circular dependencies are detected via a visited set and silently skipped.
    """
    collected: list[DepSpec] = []
    # Seed visited with the root package so it is never added to collected.
    visited: set[str] = {f"{ecosystem.value}:{package.lower()}"}
    await _resolve_recursive(package, version, ecosystem, max_depth, 0, visited, collected)
    return collected


async def _resolve_recursive(
    package: str,
    version: str | None,
    ecosystem: Ecosystem,
    max_depth: int,
    current_depth: int,
    visited: set[str],
    collected: list[DepSpec],
) -> None:
    if current_depth >= max_depth:
        return

    try:
        direct = await _fetch_direct_deps(package, version, ecosystem)
    except Exception as exc:
        logger.debug(
            "Could not fetch deps for %s/%s@%s: %s", ecosystem.value, package, version, exc
        )
        return

    for dep in direct:
        dep_key = f"{dep.ecosystem.value}:{dep.package.lower()}"
        if dep_key in visited:
            continue
        visited.add(dep_key)
        collected.append(dep)
        await _resolve_recursive(
            dep.package,
            None,  # always resolve latest for transitive hops
            dep.ecosystem,
            max_depth,
            current_depth + 1,
            visited,
            collected,
        )


async def _fetch_direct_deps(
    package: str, version: str | None, ecosystem: Ecosystem
) -> list[DepSpec]:
    if ecosystem == Ecosystem.PYPI:
        return await _fetch_pypi_deps(package, version)
    if ecosystem == Ecosystem.NPM:
        return await _fetch_npm_deps(package, version)
    if ecosystem == Ecosystem.CARGO:
        return await _fetch_cargo_deps(package, version)
    return []


async def _fetch_pypi_deps(package: str, version: str | None) -> list[DepSpec]:
    url = f"{_PYPI_BASE}/{package}/{version}/json" if version else f"{_PYPI_BASE}/{package}/json"
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        data: dict[str, Any] = resp.json()

    info: dict[str, Any] = data.get("info") or {}
    requires_dist: list[Any] = info.get("requires_dist") or []

    deps: list[DepSpec] = []
    for req_str in requires_dist:
        req = str(req_str).strip()
        # Skip extras / optional dependencies (PEP 508 environment markers).
        if "extra ==" in req or "extra==" in req:
            continue

        name_match = _REQ_NAME_RE.match(req)
        if not name_match:
            continue
        dep_name = name_match.group(1)

        # Normalise name: PEP 503 canonical form (lowercase, hyphens).
        dep_name = re.sub(r"[-_.]+", "-", dep_name).lower()

        version_match = _REQ_VERSION_RE.search(req)
        constraint = version_match.group(1) if version_match else None

        deps.append(
            DepSpec(package=dep_name, version_constraint=constraint, ecosystem=Ecosystem.PYPI)
        )

    return deps


async def _fetch_npm_deps(package: str, version: str | None) -> list[DepSpec]:
    ver = version or "latest"
    url = f"{_NPM_BASE}/{package}/{ver}"
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        data: dict[str, Any] = resp.json()

    dependencies: dict[str, Any] = data.get("dependencies") or {}
    return [
        DepSpec(package=str(name), version_constraint=str(ver_spec), ecosystem=Ecosystem.NPM)
        for name, ver_spec in dependencies.items()
    ]


async def _fetch_cargo_deps(package: str, version: str | None) -> list[DepSpec]:
    dep_version: str
    if version is None:
        meta_url = f"{_CRATES_BASE}/{package}"
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            meta_resp = await client.get(meta_url, headers={"User-Agent": "agentshield/0.2"})
            meta_resp.raise_for_status()
            meta: dict[str, Any] = meta_resp.json()
        versions: list[Any] = meta.get("versions") or []
        if not versions:
            return []
        dep_version = str(versions[0]["num"])
    else:
        dep_version = version

    url = f"{_CRATES_BASE}/{package}/{dep_version}/dependencies"
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.get(url, headers={"User-Agent": "agentshield/0.2"})
        resp.raise_for_status()
        data: dict[str, Any] = resp.json()

    dependencies: list[Any] = data.get("dependencies") or []
    return [
        DepSpec(
            package=str(dep["crate_id"]),
            version_constraint=str(dep.get("req") or ""),
            ecosystem=Ecosystem.CARGO,
        )
        for dep in dependencies
        if dep.get("kind") == "normal"
    ]
