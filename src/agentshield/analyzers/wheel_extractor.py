"""Download and extract a PyPI wheel (or sdist) to a temporary directory.

The extracted directory is returned as a context manager; the caller is
responsible for cleanup (tempfile.TemporaryDirectory handles it automatically).
"""

from __future__ import annotations

import logging
import os
import sys
import tarfile
import tempfile
import zipfile
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx

from agentshield.core.models import Ecosystem, ScanRequest

logger = logging.getLogger(__name__)

_PYPI_JSON_URL = "https://pypi.org/pypi/{package}/{version}/json"
_PYPI_LATEST_URL = "https://pypi.org/pypi/{package}/json"


class WheelExtractionError(Exception):
    pass


async def _resolve_pypi_url(package: str, version: str | None) -> str:
    """Return the download URL for the best available wheel (falls back to sdist)."""
    if version:
        url = _PYPI_JSON_URL.format(package=package, version=version)
    else:
        url = _PYPI_LATEST_URL.format(package=package)

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        data = resp.json()

    # Prefer wheels; fall back to sdist
    urls: list[dict[str, Any]] = data.get("urls") or []
    if not urls and "releases" in data:
        ver = data.get("info", {}).get("version", "")
        urls = data.get("releases", {}).get(ver, [])

    wheels = [u for u in urls if u.get("filename", "").endswith(".whl")]
    sdists = [u for u in urls if u.get("packagetype") == "sdist"]

    candidates = wheels or sdists
    if not candidates:
        raise WheelExtractionError(f"No downloadable artifacts found for {package}=={version}")

    return str(candidates[0]["url"])


async def _download(url: str, dest: Path, *, max_bytes: int | None = None) -> int:
    """Stream *url* to *dest*; return the number of bytes written.

    Raises WheelExtractionError if the download exceeds *max_bytes*, guarding
    against oversized-artifact / decompression-bomb DoS during ``--deep`` scans.
    """
    total = 0
    async with (
        httpx.AsyncClient(timeout=60, follow_redirects=True) as client,
        client.stream("GET", url) as resp,
    ):
        resp.raise_for_status()
        with open(dest, "wb") as fh:
            async for chunk in resp.aiter_bytes(65536):
                total += len(chunk)
                if max_bytes is not None and total > max_bytes:
                    raise WheelExtractionError(
                        f"Download exceeds the maximum allowed size of {max_bytes} bytes"
                    )
                fh.write(chunk)
    return total


def _safe_zipfile_extract(zf: zipfile.ZipFile, extract_to: Path) -> None:
    """Extract a zip archive, blocking path-traversal (zip-slip) attacks."""
    target_dir = os.path.realpath(extract_to)
    for member in zf.infolist():
        member_path = os.path.realpath(os.path.join(target_dir, member.filename))
        if not (member_path.startswith(target_dir + os.sep) or member_path == target_dir):
            raise WheelExtractionError(
                f"Zip-slip detected: {member.filename!r} resolves outside extraction directory"
            )
        zf.extract(member, extract_to)


def _extract_wheel(wheel_path: Path, extract_to: Path) -> None:
    with zipfile.ZipFile(wheel_path, "r") as zf:
        _safe_zipfile_extract(zf, extract_to)


def _safe_tarfile_extract(tf: tarfile.TarFile, extract_to: Path) -> None:
    """Extract a tar archive, blocking path-traversal (tar-slip) attacks.

    On Python >= 3.12 we use the built-in ``filter="data"`` guard.

    On 3.11 we validate each member path and **reject any link member**
    (symlink or hardlink). Merely realpath-checking link targets before
    ``extractall`` is not enough: the paths don't exist yet at validation
    time, so a symlink member pointing outside followed by a member that
    writes *through* that symlink passes the pre-check but escapes during
    extraction. Wheels/sdists have no legitimate need for links, so rejecting
    them outright is safe (3.12's ``filter="data"`` is stricter here too —
    it raises on absolute or outside-pointing link targets).
    """
    if sys.version_info >= (3, 12):
        tf.extractall(extract_to, filter="data")
    else:
        target_dir = os.path.realpath(extract_to)
        for member in tf.getmembers():
            if member.issym() or member.islnk():
                raise WheelExtractionError(
                    f"Archive contains a link member {member.name!r} — refusing to "
                    "extract (links can be chained to escape the extraction directory)"
                )
            member_path = os.path.realpath(os.path.join(target_dir, member.name))
            if not (member_path.startswith(target_dir + os.sep) or member_path == target_dir):
                raise WheelExtractionError(
                    f"Tar-slip detected: {member.name!r} resolves outside extraction directory"
                )
        tf.extractall(extract_to)


def _extract_sdist(sdist_path: Path, extract_to: Path) -> None:
    if tarfile.is_tarfile(sdist_path):
        with tarfile.open(sdist_path, "r:*") as tf:
            _safe_tarfile_extract(tf, extract_to)
    elif zipfile.is_zipfile(sdist_path):
        with zipfile.ZipFile(sdist_path, "r") as zf:
            _safe_zipfile_extract(zf, extract_to)
    else:
        raise WheelExtractionError(f"Unknown sdist format: {sdist_path.name}")


@asynccontextmanager
async def extracted_package(
    request: ScanRequest,
    *,
    max_bytes: int | None = None,
    on_download: Callable[[int], Awaitable[None]] | None = None,
) -> AsyncIterator[Path]:
    """Async context manager: downloads and extracts the package, yields the directory path.

    *max_bytes* caps the download size (guards against oversized artifacts).
    *on_download*, if given, is awaited with the number of bytes downloaded so
    the caller can account for session bandwidth (see
    :meth:`RateLimiter.record_wheel_bytes`).
    """
    if request.ecosystem != Ecosystem.PYPI:
        raise WheelExtractionError(
            f"Wheel extraction only supports PyPI; got ecosystem={request.ecosystem}"
        )

    url = await _resolve_pypi_url(request.package, request.version)
    filename = url.split("/")[-1].split("?")[0]

    with tempfile.TemporaryDirectory(prefix="agentshield_") as tmp:
        tmp_path = Path(tmp)
        archive = tmp_path / filename
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()

        logger.debug("Downloading %s → %s", url, archive)
        downloaded = await _download(url, archive, max_bytes=max_bytes)
        if on_download is not None:
            await on_download(downloaded)

        if filename.endswith(".whl"):
            _extract_wheel(archive, extract_dir)
        else:
            _extract_sdist(archive, extract_dir)

        logger.debug("Extracted to %s", extract_dir)
        yield extract_dir
