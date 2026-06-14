"""Unit tests for wheel_extractor: zip-slip protection, extraction helpers, and context manager."""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

import pytest
import respx
from httpx import Response

from agentshield.analyzers.wheel_extractor import (
    WheelExtractionError,
    _extract_sdist,
    _extract_wheel,
    _safe_zipfile_extract,
    extracted_package,
)
from agentshield.core.models import Ecosystem, ScanRequest


def _make_zip_bytes(members: dict[str, bytes]) -> bytes:
    """Build an in-memory zip and return its raw bytes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _make_tar_gz_bytes(members: dict[str, bytes]) -> bytes:
    """Build an in-memory .tar.gz and return its raw bytes."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _make_zip(members: dict[str, bytes]) -> zipfile.ZipFile:
    """Return an in-memory ZipFile with the given filename → content mapping."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    buf.seek(0)
    return zipfile.ZipFile(buf, "r")


# ── Safe extraction ───────────────────────────────────────────────────────────


def test_safe_extract_normal_files(tmp_path: Path) -> None:
    extract_dir = tmp_path / "out"
    extract_dir.mkdir()
    with _make_zip({"pkg/module.py": b"x = 1\n", "pkg/__init__.py": b""}) as zf:
        _safe_zipfile_extract(zf, extract_dir)
    assert (extract_dir / "pkg" / "module.py").exists()
    assert (extract_dir / "pkg" / "__init__.py").exists()


def test_safe_extract_nested_directories(tmp_path: Path) -> None:
    extract_dir = tmp_path / "out"
    extract_dir.mkdir()
    with _make_zip({"a/b/c/d.txt": b"hello"}) as zf:
        _safe_zipfile_extract(zf, extract_dir)
    assert (extract_dir / "a" / "b" / "c" / "d.txt").read_bytes() == b"hello"


# ── Zip-slip detection ────────────────────────────────────────────────────────


def test_safe_extract_blocks_path_traversal(tmp_path: Path) -> None:
    extract_dir = tmp_path / "out"
    extract_dir.mkdir()
    evil_member = "../../../etc/cron.d/backdoor"
    with (
        _make_zip({evil_member: b"* * * * * root id"}) as zf,
        pytest.raises(WheelExtractionError, match="Zip-slip detected"),
    ):
        _safe_zipfile_extract(zf, extract_dir)


def test_safe_extract_blocks_double_dot_in_middle(tmp_path: Path) -> None:
    extract_dir = tmp_path / "out"
    extract_dir.mkdir()
    with (
        _make_zip({"subdir/../../evil.txt": b"evil"}) as zf,
        pytest.raises(WheelExtractionError, match="Zip-slip detected"),
    ):
        _safe_zipfile_extract(zf, extract_dir)


def test_safe_extract_blocks_absolute_path(tmp_path: Path) -> None:
    extract_dir = tmp_path / "out"
    extract_dir.mkdir()
    # zipfile allows absolute paths to be stored; they must be rejected
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("/etc/passwd")
        zf.writestr(info, "root:x:0:0::/root:/bin/bash\n")
    buf.seek(0)
    with (
        zipfile.ZipFile(buf, "r") as zf,
        pytest.raises(WheelExtractionError, match="Zip-slip detected"),
    ):
        _safe_zipfile_extract(zf, extract_dir)


def test_safe_extract_evil_file_not_written(tmp_path: Path) -> None:
    extract_dir = tmp_path / "out"
    extract_dir.mkdir()
    sentinel = tmp_path / "evil_sentinel.txt"
    assert not sentinel.exists()

    with _make_zip({"../evil_sentinel.txt": b"pwned"}) as zf, pytest.raises(WheelExtractionError):
        _safe_zipfile_extract(zf, extract_dir)

    # The file must not have been written outside the extraction directory
    assert not sentinel.exists()


# ── _extract_wheel ────────────────────────────────────────────────────────────


def test_extract_wheel_multiple_files(tmp_path: Path) -> None:
    wheel_path = tmp_path / "test-1.0-py3-none-any.whl"
    wheel_path.write_bytes(
        _make_zip_bytes(
            {
                "test/__init__.py": b"",
                "test/module.py": b"x = 1\n",
                "test-1.0.dist-info/METADATA": b"Name: test\nVersion: 1.0\n",
                "test-1.0.dist-info/WHEEL": b"Wheel-Version: 1.0\n",
            }
        )
    )
    extract_dir = tmp_path / "out"
    extract_dir.mkdir()

    _extract_wheel(wheel_path, extract_dir)

    assert (extract_dir / "test" / "__init__.py").exists()
    assert (extract_dir / "test" / "module.py").read_bytes() == b"x = 1\n"
    assert (extract_dir / "test-1.0.dist-info" / "METADATA").exists()
    assert (extract_dir / "test-1.0.dist-info" / "WHEEL").exists()


def test_extract_wheel_corrupted_raises(tmp_path: Path) -> None:
    wheel_path = tmp_path / "bad.whl"
    wheel_path.write_bytes(b"PK\x00\x00not a real zip at all")
    extract_dir = tmp_path / "out"
    extract_dir.mkdir()

    with pytest.raises(zipfile.BadZipFile):
        _extract_wheel(wheel_path, extract_dir)


# ── _extract_sdist ────────────────────────────────────────────────────────────


def test_extract_sdist_tar_gz(tmp_path: Path) -> None:
    sdist_path = tmp_path / "test-1.0.tar.gz"
    sdist_path.write_bytes(
        _make_tar_gz_bytes(
            {
                "test-1.0/setup.py": b"from setuptools import setup\nsetup(name='test')\n",
                "test-1.0/test/__init__.py": b"",
            }
        )
    )
    extract_dir = tmp_path / "out"
    extract_dir.mkdir()

    _extract_sdist(sdist_path, extract_dir)

    assert (extract_dir / "test-1.0" / "setup.py").exists()
    assert (
        extract_dir / "test-1.0" / "setup.py"
    ).read_bytes() == b"from setuptools import setup\nsetup(name='test')\n"
    assert (extract_dir / "test-1.0" / "test" / "__init__.py").exists()


def test_extract_sdist_zip_fallback(tmp_path: Path) -> None:
    """sdists distributed as .zip files are also supported."""
    sdist_path = tmp_path / "test-1.0.zip"
    sdist_path.write_bytes(
        _make_zip_bytes({"test-1.0/setup.py": b"from setuptools import setup\n"})
    )
    extract_dir = tmp_path / "out"
    extract_dir.mkdir()

    _extract_sdist(sdist_path, extract_dir)

    assert (extract_dir / "test-1.0" / "setup.py").exists()


def test_extract_sdist_unknown_format_raises(tmp_path: Path) -> None:
    sdist_path = tmp_path / "bad.tar.gz"
    sdist_path.write_bytes(b"\x00\x01\x02 not a tar or zip file at all")
    extract_dir = tmp_path / "out"
    extract_dir.mkdir()

    with pytest.raises(WheelExtractionError, match="Unknown sdist format"):
        _extract_sdist(sdist_path, extract_dir)


# ── extracted_package context manager ────────────────────────────────────────

_PYPI_JSON = "https://pypi.org/pypi/{pkg}/{ver}/json"
_DL_BASE = "https://files.pypi.example.com"


@pytest.mark.asyncio
async def test_extracted_package_non_pypi_raises() -> None:
    request = ScanRequest(package="my-crate", ecosystem=Ecosystem.CARGO)
    with pytest.raises(WheelExtractionError, match="Wheel extraction only supports PyPI"):
        async with extracted_package(request):
            pass  # pragma: no cover


@pytest.mark.asyncio
@respx.mock
async def test_extracted_package_downloads_and_extracts_wheel() -> None:
    wheel_bytes = _make_zip_bytes(
        {
            "synth/__init__.py": b"",
            "synth/core.py": b"SECRET = 'nope'\n",
        }
    )
    dl_url = f"{_DL_BASE}/synth_pkg-1.0.0-py3-none-any.whl"

    respx.get(_PYPI_JSON.format(pkg="synth-pkg", ver="1.0.0")).mock(
        return_value=Response(
            200,
            json={
                "info": {"version": "1.0.0"},
                "urls": [
                    {
                        "filename": "synth_pkg-1.0.0-py3-none-any.whl",
                        "packagetype": "bdist_wheel",
                        "url": dl_url,
                    }
                ],
            },
        )
    )
    respx.get(dl_url).mock(return_value=Response(200, content=wheel_bytes))

    request = ScanRequest(package="synth-pkg", version="1.0.0", ecosystem=Ecosystem.PYPI)
    async with extracted_package(request) as pkg_dir:
        assert pkg_dir.is_dir()
        assert (pkg_dir / "synth" / "__init__.py").exists()
        assert (pkg_dir / "synth" / "core.py").read_bytes() == b"SECRET = 'nope'\n"


@pytest.mark.asyncio
@respx.mock
async def test_extracted_package_downloads_and_extracts_sdist() -> None:
    sdist_bytes = _make_tar_gz_bytes(
        {"synth-sdist-1.0.0/setup.py": b"from setuptools import setup\nsetup()\n"}
    )
    dl_url = f"{_DL_BASE}/synth-sdist-1.0.0.tar.gz"

    respx.get(_PYPI_JSON.format(pkg="synth-sdist", ver="1.0.0")).mock(
        return_value=Response(
            200,
            json={
                "info": {"version": "1.0.0"},
                "urls": [
                    {
                        "filename": "synth-sdist-1.0.0.tar.gz",
                        "packagetype": "sdist",
                        "url": dl_url,
                    }
                ],
            },
        )
    )
    respx.get(dl_url).mock(return_value=Response(200, content=sdist_bytes))

    request = ScanRequest(package="synth-sdist", version="1.0.0", ecosystem=Ecosystem.PYPI)
    async with extracted_package(request) as pkg_dir:
        assert pkg_dir.is_dir()
        assert (pkg_dir / "synth-sdist-1.0.0" / "setup.py").exists()


@pytest.mark.asyncio
@respx.mock
async def test_extracted_package_no_artifacts_raises() -> None:
    respx.get(_PYPI_JSON.format(pkg="empty-pkg", ver="1.0.0")).mock(
        return_value=Response(200, json={"info": {"version": "1.0.0"}, "urls": []})
    )
    request = ScanRequest(package="empty-pkg", version="1.0.0", ecosystem=Ecosystem.PYPI)
    with pytest.raises(WheelExtractionError, match="No downloadable artifacts"):
        async with extracted_package(request):
            pass  # pragma: no cover
