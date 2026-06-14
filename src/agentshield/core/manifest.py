"""Manifest file parsers for scan_file() mode.

Supports:
  - requirements.txt  (pip)
  - package.json      (npm)
  - Cargo.toml        (cargo)
  - package-lock.json (npm)

Each parse_* function returns a list of ScanRequests ready to be passed to
AgentShield.ascan(). detect_format() identifies the format from the filename.
parse_manifest() auto-detects and dispatches to the right parser.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from agentshield.core.models import Ecosystem, ScanRequest

_FILENAME_TO_FORMAT: dict[str, str] = {
    "requirements.txt": "requirements_txt",
    "package.json": "package_json",
    "cargo.toml": "cargo_toml",
    "package-lock.json": "package_lock_json",
}


def detect_format(path: Path) -> str:
    """Return a format key for *path*, or raise ValueError if unrecognized."""
    name_lower = path.name.lower()

    # Exact filename match
    fmt = _FILENAME_TO_FORMAT.get(name_lower)
    if fmt is not None:
        return fmt

    # Requirements variants: e.g. test-requirements.txt, requirements-dev.txt
    if name_lower.endswith("requirements.txt") or (
        "requirements" in name_lower and name_lower.endswith(".txt")
    ):
        return "requirements_txt"

    # Extension-based fallback; .json uses content sniffing to distinguish lockfile
    suffix = path.suffix.lower()
    if suffix == ".txt":
        return "requirements_txt"
    if suffix == ".json":
        try:
            data = json.loads(path.read_text())
            if isinstance(data, dict) and "lockfileVersion" in data:
                return "package_lock_json"
        except (json.JSONDecodeError, OSError):
            pass
        return "package_json"
    if suffix == ".toml":
        return "cargo_toml"

    supported = ", ".join(_FILENAME_TO_FORMAT)
    raise ValueError(f"Unrecognized manifest filename: {path.name!r}. Supported: {supported}")


def parse_requirements_txt(path: Path) -> list[ScanRequest]:
    """Parse a pip requirements.txt into ScanRequests.

    Skips comment lines, flag lines (-r, -c, -e, --index-url, …), and URL
    entries. Extracts a pinned version (==X.Y.Z) when present; otherwise
    version is None.
    """
    requests: list[ScanRequest] = []
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-") or "://" in line:
            continue
        # PEP 508 package name: starts with letter/digit, may contain ., -, _
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", line)
        if not m:
            continue
        name = m.group(1)
        rest = line[m.end() :]
        # Strip environment markers before version parsing
        rest_no_marker = re.split(r"\s*;", rest)[0]
        pin = re.search(r"==([^\s,;]+)", rest_no_marker)
        version = pin.group(1) if pin else None
        requests.append(ScanRequest(package=name, version=version, ecosystem=Ecosystem.PYPI))
    return requests


def parse_package_json(path: Path) -> list[ScanRequest]:
    """Parse npm package.json dependencies + devDependencies into ScanRequests."""
    data: dict[str, object] = json.loads(path.read_text())
    requests: list[ScanRequest] = []
    for section in ("dependencies", "devDependencies"):
        section_data = data.get(section)
        if not isinstance(section_data, dict):
            continue
        for name, spec in section_data.items():
            version: str | None = None
            if isinstance(spec, str):
                clean = spec.lstrip("^~>=< ")
                version = clean if clean and re.match(r"^\d", clean) else None
            requests.append(ScanRequest(package=name, version=version, ecosystem=Ecosystem.NPM))
    return requests


def parse_cargo_toml(path: Path) -> list[ScanRequest]:
    """Parse Cargo.toml [dependencies] and [dev-dependencies] into ScanRequests."""
    data: dict[str, object] = tomllib.loads(path.read_text())
    requests: list[ScanRequest] = []
    for section in ("dependencies", "dev-dependencies"):
        section_data = data.get(section)
        if not isinstance(section_data, dict):
            continue
        for name, spec in section_data.items():
            version: str | None = None
            if isinstance(spec, str):
                clean = spec.lstrip("~^=<>! ")
                version = clean if clean and re.match(r"^\d", clean) else None
            elif isinstance(spec, dict):
                v = spec.get("version")
                if isinstance(v, str) and v:
                    clean = v.lstrip("~^=<>! ")
                    version = clean if re.match(r"^\d", clean) else None
            requests.append(ScanRequest(package=name, version=version, ecosystem=Ecosystem.CARGO))
    return requests


def parse_package_lock_json(path: Path) -> list[ScanRequest]:
    """Parse npm package-lock.json (v1/v2/v3) into ScanRequests.

    npm v2/v3 lockfiles use a "packages" key; v1 uses "dependencies".
    Nested/transitive packages inside "node_modules/..." paths are included.
    The root package entry (empty string key) is skipped.
    """
    data: dict[str, object] = json.loads(path.read_text())
    requests: list[ScanRequest] = []

    packages = data.get("packages")
    if isinstance(packages, dict):
        for pkg_path, info in packages.items():
            if not pkg_path:
                continue
            # "node_modules/foo" or "node_modules/@scope/foo"
            name = pkg_path.split("node_modules/")[-1]
            if not name or not isinstance(info, dict):
                continue
            version = info.get("version")
            requests.append(
                ScanRequest(
                    package=name,
                    version=version if isinstance(version, str) else None,
                    ecosystem=Ecosystem.NPM,
                )
            )
        return requests

    deps = data.get("dependencies")
    if isinstance(deps, dict):
        for name, info in deps.items():
            version = info.get("version") if isinstance(info, dict) else None
            requests.append(
                ScanRequest(
                    package=name,
                    version=version if isinstance(version, str) else None,
                    ecosystem=Ecosystem.NPM,
                )
            )

    return requests


def parse_manifest(path: Path) -> list[ScanRequest]:
    """Auto-detect format from *path.name* and parse into ScanRequests."""
    fmt = detect_format(path)
    parsers = {
        "requirements_txt": parse_requirements_txt,
        "package_json": parse_package_json,
        "cargo_toml": parse_cargo_toml,
        "package_lock_json": parse_package_lock_json,
    }
    return parsers[fmt](path)
