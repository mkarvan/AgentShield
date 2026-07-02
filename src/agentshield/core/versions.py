"""Tolerant version comparison and vulnerable-range matching.

Used to decide whether a *pinned* requested version is actually inside an
advisory's affected range, instead of reporting every advisory ever filed
against a package.

Design principles:

* **Fail toward reporting.** These helpers return ``None`` ("cannot determine")
  whenever a version or range cannot be parsed confidently; callers must treat
  ``None`` like a match and keep the finding. A finding is only dropped on a
  confident ``False``.
* **No new dependencies.** A tolerant dotted-numeric comparison covers the
  overwhelming majority of PyPI / npm / crates.io versions without pulling in
  ``packaging`` or a semver library. Anything exotic (epochs, local versions,
  pre-releases compared at the same numeric release) degrades to ``None``.

Two range dialects are supported:

* :func:`version_in_osv_ranges` — OSV ``ranges``/``events`` JSON, as stored in
  the ``cve_mirror.affected_versions`` column by ``databases/warm.py``.
* :func:`version_in_github_range` — GitHub Advisory ``vulnerableVersionRange``
  strings such as ``">= 2.0.0, < 2.28.1"`` or ``"< 1.2.3"``.
"""

from __future__ import annotations

import json
import logging
import re

logger = logging.getLogger(__name__)

# Leading dotted-numeric release segment, e.g. "2.28.1" in "2.28.1rc1+local".
_NUMERIC_PREFIX_RE = re.compile(r"^v?(\d+(?:\.\d+)*)(.*)$")

# One comparator in a GitHub Advisory range: ">= 2.0.0", "< 1.2", "= 1.0.0".
_COMPARATOR_RE = re.compile(r"^(>=|<=|>|<|=)\s*(\S+)$")


def parse_version(raw: str) -> tuple[tuple[int, ...], str] | None:
    """Parse *raw* into ``(numeric_parts, suffix)``, or ``None`` if unparseable.

    ``"2.28.1"`` → ``((2, 28, 1), "")``; ``"1.0rc1"`` → ``((1, 0), "rc1")``.
    Epoch markers (``1!2.0``) and wholly non-numeric strings return ``None``.
    """
    if not raw:
        return None
    s = raw.strip()
    if "!" in s:  # PEP 440 epoch — rare enough to punt on
        return None
    m = _NUMERIC_PREFIX_RE.match(s)
    if not m:
        return None
    try:
        parts = tuple(int(p) for p in m.group(1).split("."))
    except ValueError:  # pragma: no cover — regex guarantees digits
        return None
    return parts, m.group(2).strip()


def compare_versions(a: str, b: str) -> int | None:
    """Three-way compare: ``-1`` / ``0`` / ``1``, or ``None`` if not confident.

    Numeric release segments are compared component-wise (missing components
    count as 0). When the numeric segments are equal but exactly one side has a
    suffix (e.g. ``1.0rc1`` vs ``1.0``), the suffixed side is treated as *lower*
    (pre-release ordering — the common case for rc/a/b/dev suffixes). Two
    different non-empty suffixes on equal numeric parts return ``None``.
    """
    pa, pb = parse_version(a), parse_version(b)
    if pa is None or pb is None:
        return None
    na, sa = pa
    nb, sb = pb
    length = max(len(na), len(nb))
    na += (0,) * (length - len(na))
    nb += (0,) * (length - len(nb))
    if na < nb:
        return -1
    if na > nb:
        return 1
    if sa == sb:
        return 0
    if not sa:
        return 1  # release > pre-release
    if not sb:
        return -1
    return None  # two different suffixes — do not guess


def _in_interval(
    version: str,
    introduced: str | None,
    fixed: str | None,
    last_affected: str | None,
) -> bool | None:
    """Is *version* inside [introduced, fixed) or [introduced, last_affected]?"""
    if introduced is not None and introduced != "0":
        cmp_intro = compare_versions(version, introduced)
        if cmp_intro is None:
            return None
        if cmp_intro < 0:
            return False
    if fixed is not None:
        cmp_fixed = compare_versions(version, fixed)
        if cmp_fixed is None:
            return None
        return cmp_fixed < 0
    if last_affected is not None:
        cmp_last = compare_versions(version, last_affected)
        if cmp_last is None:
            return None
        return cmp_last <= 0
    return True  # introduced with no upper bound — affected from there on


def version_in_osv_ranges(version: str, ranges: list[dict] | str | None) -> bool | None:
    """Check *version* against OSV ``ranges`` (list of ``{"type", "events"}``).

    *ranges* may be the JSON string stored in ``cve_mirror.affected_versions``.
    Returns ``True`` (affected), ``False`` (confidently not affected), or
    ``None`` (cannot determine — caller should keep the finding).
    """
    if not version:
        return None
    if isinstance(ranges, str):
        try:
            ranges = json.loads(ranges)
        except (json.JSONDecodeError, TypeError):
            return None
    if not isinstance(ranges, list) or not ranges:
        return None

    saw_checkable = False
    undetermined = False
    for rng in ranges:
        if not isinstance(rng, dict):
            undetermined = True
            continue
        if rng.get("type") == "GIT":
            continue  # commit ranges cannot be compared to a version string
        events = rng.get("events")
        if not isinstance(events, list) or not events:
            undetermined = True
            continue
        saw_checkable = True
        # Walk events in order, building [introduced, fixed/last_affected] intervals.
        introduced: str | None = None
        open_interval = False
        for event in events:
            if not isinstance(event, dict):
                undetermined = True
                continue
            if "introduced" in event:
                introduced = str(event["introduced"])
                open_interval = True
            elif "fixed" in event or "last_affected" in event:
                fixed = str(event["fixed"]) if "fixed" in event else None
                last = str(event["last_affected"]) if "last_affected" in event else None
                result = _in_interval(version, introduced, fixed, last)
                if result is True:
                    return True
                if result is None:
                    undetermined = True
                introduced = None
                open_interval = False
        if open_interval:  # trailing "introduced" with no upper bound
            result = _in_interval(version, introduced, None, None)
            if result is True:
                return True
            if result is None:
                undetermined = True

    if undetermined or not saw_checkable:
        return None
    return False


def version_in_github_range(version: str, range_str: str | None) -> bool | None:
    """Check *version* against a GitHub Advisory ``vulnerableVersionRange``.

    The range is a comma-separated list of comparators that must all hold,
    e.g. ``">= 2.0.0, < 2.28.1"``. Returns ``True``/``False``/``None`` with the
    same fail-toward-reporting semantics as :func:`version_in_osv_ranges`.
    """
    if not version or not range_str or not range_str.strip():
        return None

    for part in range_str.split(","):
        part = part.strip()
        if not part:
            continue
        m = _COMPARATOR_RE.match(part)
        if not m:
            return None  # unrecognised comparator syntax — do not guess
        op, bound = m.group(1), m.group(2)
        cmp_result = compare_versions(version, bound)
        if cmp_result is None:
            return None
        if op == ">=" and not cmp_result >= 0:
            return False
        if op == "<=" and not cmp_result <= 0:
            return False
        if op == ">" and not cmp_result > 0:
            return False
        if op == "<" and not cmp_result < 0:
            return False
        if op == "=" and cmp_result != 0:
            return False
    return True
