from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path

from agentshield.core.cache import ScanCache
from agentshield.core.config import Config
from agentshield.core.models import (
    Decision,
    DecisionAction,
    Finding,
    ScanRequest,
    ScanResult,
    Severity,
)
from agentshield.core.response_engine import ResponseEngine

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = ["NONE", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


class AgentShield:
    def __init__(self, config: Config | None = None, config_path: Path | None = None) -> None:
        self.config = config or Config.load(config_path)
        self.cache = ScanCache(self.config.cache)
        self.response_engine = ResponseEngine(self.config)

    def scan(self, request: ScanRequest) -> ScanResult:
        """Synchronous scan — wraps ascan(). Prefer ascan() in async contexts."""
        return asyncio.run(self.ascan(request))

    async def ascan(self, request: ScanRequest) -> ScanResult:
        """Asynchronous scan — the main entry point for all integrations."""
        start = time.monotonic()

        # Denylist check — short-circuit before any I/O
        if request.package.lower() in {p.lower() for p in self.config.denylist}:
            return ScanResult(
                request=request,
                findings=[],
                max_severity=Severity.CRITICAL,
                decision=Decision(
                    action=DecisionAction.BLOCK,
                    reason=f"Package '{request.package}' is on the denylist",
                ),
                scan_duration_ms=0,
                cache_hit=False,
            )

        # Allowlist check — skip scan entirely
        if request.package.lower() in {p.lower() for p in self.config.allowlist}:
            return ScanResult(
                request=request,
                findings=[],
                max_severity=Severity.NONE,
                decision=Decision(
                    action=DecisionAction.ALLOW,
                    reason="Package is on the allowlist",
                ),
                scan_duration_ms=0,
                cache_hit=True,
            )

        # Cache lookup
        cached = await self.cache.get(request)
        if cached is not None:
            return cached

        # Run enrichment + typosquatting in parallel
        findings = await self._run_checks(request)

        max_sev = _max_severity(findings)
        decision = self.response_engine.decide(findings, request)

        result = ScanResult(
            request=request,
            findings=findings,
            max_severity=max_sev,
            decision=decision,
            scan_duration_ms=int((time.monotonic() - start) * 1000),
            cache_hit=False,
        )
        await self.cache.set(request, result)
        return result

    async def _run_checks(self, request: ScanRequest) -> list[Finding]:
        from agentshield.analyzers.typosquatting import TyposquattingChecker
        from agentshield.databases.osv import OSVClient

        tasks = [
            OSVClient().scan(request),
            TyposquattingChecker().scan(request),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        findings: list[Finding] = []
        for i, r in enumerate(results):
            if isinstance(r, list):
                findings.extend(r)
            elif isinstance(r, Exception):
                source = ["osv", "typosquatting"][i]
                logger.warning("Check '%s' failed for %s: %s", source, request.package, r)

        return findings


def _max_severity(findings: list[Finding]) -> Severity:
    if not findings:
        return Severity.NONE
    return max(findings, key=lambda f: _SEVERITY_ORDER.index(f.severity.value)).severity
