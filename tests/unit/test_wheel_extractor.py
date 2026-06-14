"""Unit tests for zip-slip protection in wheel_extractor."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from agentshield.analyzers.wheel_extractor import WheelExtractionError, _safe_zipfile_extract


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
