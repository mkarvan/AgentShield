"""Unit tests for core.versions — tolerant version compare + range matching."""

from __future__ import annotations

import json

import pytest

from agentshield.core.versions import (
    compare_versions,
    parse_version,
    version_in_github_range,
    version_in_osv_ranges,
)

# ── parse_version ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("2.28.1", ((2, 28, 1), "")),
        ("v1.2", ((1, 2), "")),
        ("1.0rc1", ((1, 0), "rc1")),
        ("1.0.0-beta.2", ((1, 0, 0), "-beta.2")),
        ("0", ((0,), "")),
    ],
)
def test_parse_version_ok(raw, expected):
    assert parse_version(raw) == expected


@pytest.mark.parametrize("raw", ["", "abc", "1!2.0", None if False else "latest"])
def test_parse_version_unparseable(raw):
    assert parse_version(raw) is None


# ── compare_versions ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "a,b,expected",
    [
        ("1.0", "2.0", -1),
        ("2.0", "1.9.9", 1),
        ("1.2.3", "1.2.3", 0),
        ("1.2", "1.2.0", 0),  # missing components count as zero
        ("1.0rc1", "1.0", -1),  # pre-release < release
        ("1.0", "1.0rc1", 1),
        ("1.0rc1", "1.0rc1", 0),
    ],
)
def test_compare_versions(a, b, expected):
    assert compare_versions(a, b) == expected


def test_compare_versions_two_different_suffixes_is_unknown():
    assert compare_versions("1.0a1", "1.0b1") is None


def test_compare_versions_unparseable_is_unknown():
    assert compare_versions("garbage", "1.0") is None


# ── version_in_osv_ranges ─────────────────────────────────────────────────────

_RANGES = [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.28.1"}]}]


def test_osv_range_affected():
    assert version_in_osv_ranges("2.27.0", _RANGES) is True


def test_osv_range_fixed_version_not_affected():
    assert version_in_osv_ranges("2.28.1", _RANGES) is False
    assert version_in_osv_ranges("3.0.0", _RANGES) is False


def test_osv_range_accepts_json_string():
    assert version_in_osv_ranges("2.27.0", json.dumps(_RANGES)) is True
    assert version_in_osv_ranges("2.28.1", json.dumps(_RANGES)) is False


def test_osv_range_introduced_lower_bound():
    ranges = [{"type": "SEMVER", "events": [{"introduced": "2.0.0"}, {"fixed": "2.5.0"}]}]
    assert version_in_osv_ranges("1.9.0", ranges) is False
    assert version_in_osv_ranges("2.0.0", ranges) is True
    assert version_in_osv_ranges("2.4.9", ranges) is True
    assert version_in_osv_ranges("2.5.0", ranges) is False


def test_osv_range_last_affected_is_inclusive():
    ranges = [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"last_affected": "1.4"}]}]
    assert version_in_osv_ranges("1.4", ranges) is True
    assert version_in_osv_ranges("1.4.1", ranges) is False


def test_osv_range_open_ended_introduced():
    ranges = [{"type": "ECOSYSTEM", "events": [{"introduced": "3.0"}]}]
    assert version_in_osv_ranges("3.1", ranges) is True
    assert version_in_osv_ranges("2.9", ranges) is False


def test_osv_range_multiple_intervals():
    ranges = [
        {
            "type": "ECOSYSTEM",
            "events": [
                {"introduced": "0"},
                {"fixed": "1.5"},
                {"introduced": "2.0"},
                {"fixed": "2.3"},
            ],
        }
    ]
    assert version_in_osv_ranges("1.0", ranges) is True
    assert version_in_osv_ranges("1.7", ranges) is False
    assert version_in_osv_ranges("2.1", ranges) is True
    assert version_in_osv_ranges("2.4", ranges) is False


def test_osv_range_git_only_is_unknown():
    ranges = [{"type": "GIT", "events": [{"introduced": "deadbeef"}, {"fixed": "cafef00d"}]}]
    assert version_in_osv_ranges("1.0", ranges) is None


@pytest.mark.parametrize("ranges", [None, "", "[]", "not json", [], [{"type": "ECOSYSTEM"}]])
def test_osv_range_missing_or_bad_data_is_unknown(ranges):
    assert version_in_osv_ranges("1.0", ranges) is None


def test_osv_range_unparseable_version_is_unknown():
    assert version_in_osv_ranges("latest", _RANGES) is None
    assert version_in_osv_ranges("", _RANGES) is None


# ── version_in_github_range ───────────────────────────────────────────────────


@pytest.mark.parametrize(
    "version,range_str,expected",
    [
        ("2.27.0", ">= 2.0.0, < 2.28.1", True),
        ("2.28.1", ">= 2.0.0, < 2.28.1", False),
        ("1.9", ">= 2.0.0, < 2.28.1", False),
        ("1.2.2", "< 1.2.3", True),
        ("1.2.3", "< 1.2.3", False),
        ("1.0.0", "= 1.0.0", True),
        ("1.0.1", "= 1.0.0", False),
        ("3.0", "<= 3.0", True),
        ("3.0.1", "<= 3.0", False),
    ],
)
def test_github_range(version, range_str, expected):
    assert version_in_github_range(version, range_str) is expected


@pytest.mark.parametrize(
    "version,range_str",
    [
        ("1.0", ""),  # empty range
        ("1.0", None),
        ("", "< 2.0"),  # no version
        ("latest", "< 2.0"),  # unparseable version
        ("1.0", "^2.0"),  # unrecognised comparator
    ],
)
def test_github_range_unknown(version, range_str):
    assert version_in_github_range(version, range_str) is None
