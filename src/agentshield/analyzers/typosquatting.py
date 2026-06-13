from __future__ import annotations

import json
from pathlib import Path

from Levenshtein import distance

from agentshield.core.models import Ecosystem, Finding, ScanRequest, Severity

_DATA_FILE = Path(__file__).parent / "data" / "top_packages.json"

# Packages within this edit distance (exclusive) are flagged as potential typosquats.
# Distance 1: single-character typos (reqests → requests)
# Distance 2: transposition + deletion (reqeusts → requests)
_TYPOSQUAT_THRESHOLD = 2

# Very short package names generate too many false positives at d≤2.
_MIN_NAME_LENGTH_FOR_CHECK = 4


def _normalise(name: str) -> str:
    """PyPI normalises package names: lowercase + replace -/. with _."""
    return name.lower().replace("-", "_").replace(".", "_")


class TyposquattingChecker:
    def __init__(self) -> None:
        self._known: dict[str, list[str]] = {}

    def _load(self, ecosystem: Ecosystem) -> list[str]:
        key = ecosystem.value
        if key in self._known:
            return self._known[key]

        if _DATA_FILE.exists():
            data: dict[str, list[str]] = json.loads(_DATA_FILE.read_text())
            self._known[key] = data.get(key, [])
        else:
            self._known[key] = []

        return self._known[key]

    async def scan(self, request: ScanRequest) -> list[Finding]:
        known = self._load(request.ecosystem)
        if not known:
            return []

        name = _normalise(request.package)

        # Very short names produce too many false positives at low thresholds
        if len(name) < _MIN_NAME_LENGTH_FOR_CHECK:
            return []

        closest_dist = _TYPOSQUAT_THRESHOLD + 1
        closest_legit: str | None = None

        for legit in known:
            canonical = _normalise(legit)
            if canonical == name:
                return []  # exact match — not a typosquat

            # Only compare against packages of similar length to avoid
            # short legitimate packages matching long malicious ones.
            if abs(len(canonical) - len(name)) > _TYPOSQUAT_THRESHOLD:
                continue

            d = distance(name, canonical)
            if 0 < d <= _TYPOSQUAT_THRESHOLD and d < closest_dist:
                closest_dist = d
                closest_legit = legit

        if closest_legit is None:
            return []

        return [
            Finding(
                rule_id="T1.2",
                title=f"Possible typosquatting of '{closest_legit}'",
                description=(
                    f"'{request.package}' is {closest_dist} edit(s) away from the popular "
                    f"package '{closest_legit}'. This may be a typosquatting attack."
                ),
                severity=Severity.HIGH,
                source="typosquatting",
                references=[],
                remediation=f"Verify you meant to install '{closest_legit}', not '{request.package}'",
            )
        ]
