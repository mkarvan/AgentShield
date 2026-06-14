"""Drift detection — track ALLOW→BLOCK and ALLOW→WARN transitions across scans.

Each scan records its final decision in the scan_history table. On subsequent
scans of the same package, if the decision has regressed (ALLOW→BLOCK or
ALLOW→WARN), a D1.1 Finding is emitted so the caller knows the package's
security posture has changed since it was last approved.
"""

from __future__ import annotations

from pathlib import Path

from agentshield.core.models import DecisionAction, Finding, Severity


class DriftDetector:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path

    async def check(
        self,
        package: str,
        ecosystem: str,
        current_action: DecisionAction,
    ) -> list[Finding]:
        """Compare *current_action* against the last recorded decision.

        Returns a D1.1 Finding when a security regression is detected:
        - ALLOW → BLOCK  : HIGH severity
        - ALLOW → WARN   : MEDIUM severity (NEEDS_CONFIRMATION or LOG_ASYNC)
        """
        from agentshield.core.cache import ScanCache
        from agentshield.core.config import CacheConfig

        cache = ScanCache(CacheConfig(db_path=self._db_path))
        prev = await cache.get_last_decision(package, ecosystem)

        if prev is None or prev != DecisionAction.ALLOW.value:
            return []

        if current_action == DecisionAction.BLOCK:
            return [
                Finding(
                    rule_id="D1.1",
                    title=f"{package}: previously ALLOWED, now BLOCKED",
                    description=(
                        f"Package '{package}' ({ecosystem}) was previously allowed but is now "
                        "blocked. A newly discovered vulnerability or malicious indicator has "
                        "caused the security posture to regress."
                    ),
                    severity=Severity.HIGH,
                    source="drift_detector",
                    remediation=(
                        f"Review the new security findings for '{package}'. "
                        "Remove it from any allowlists and pin to a safe version or replace it."
                    ),
                )
            ]

        if current_action in (DecisionAction.NEEDS_CONFIRMATION, DecisionAction.LOG_ASYNC):
            return [
                Finding(
                    rule_id="D1.1",
                    title=f"{package}: previously ALLOWED, now requires review",
                    description=(
                        f"Package '{package}' ({ecosystem}) was previously allowed but now has "
                        "findings that require review. New issues have been discovered since the "
                        "last scan."
                    ),
                    severity=Severity.MEDIUM,
                    source="drift_detector",
                    remediation=f"Review the new security findings for '{package}'.",
                )
            ]

        return []

    async def record(
        self,
        package: str,
        ecosystem: str,
        action: DecisionAction,
    ) -> None:
        """Persist the current scan decision in scan_history."""
        from agentshield.core.cache import ScanCache
        from agentshield.core.config import CacheConfig

        cache = ScanCache(CacheConfig(db_path=self._db_path))
        await cache.record_scan_decision(package, ecosystem, action.value)
