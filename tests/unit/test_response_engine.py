from agentshield.core.config import Config
from agentshield.core.models import (
    DecisionAction,
    Ecosystem,
    Finding,
    ScanRequest,
    Severity,
)
from agentshield.core.response_engine import ResponseEngine


def _finding(rule_id: str, severity: Severity) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="Test finding",
        description="",
        severity=severity,
        source="test",
    )


def _request() -> ScanRequest:
    return ScanRequest(package="test-pkg", ecosystem=Ecosystem.PYPI)


def test_no_findings_allows():
    engine = ResponseEngine(Config())
    decision = engine.decide([], _request())
    assert decision.action == DecisionAction.ALLOW


def test_critical_finding_blocks_by_default():
    engine = ResponseEngine(Config())
    findings = [_finding("T1.1", Severity.CRITICAL)]
    decision = engine.decide(findings, _request())
    assert decision.action == DecisionAction.BLOCK


def test_high_finding_warns_by_default():
    engine = ResponseEngine(Config())
    findings = [_finding("T1.2", Severity.HIGH)]
    decision = engine.decide(findings, _request())
    assert decision.action == DecisionAction.NEEDS_CONFIRMATION


def test_rule_override_trumps_default():
    config = Config.model_validate(
        {
            "rules": {"T1.2": {"mode": "block"}},
        }
    )
    engine = ResponseEngine(config)
    findings = [_finding("T1.2", Severity.HIGH)]
    decision = engine.decide(findings, _request())
    assert decision.action == DecisionAction.BLOCK


def test_strictest_action_wins():
    engine = ResponseEngine(Config())
    findings = [
        _finding("SOME-INFO", Severity.INFO),
        _finding("CVE-CRITICAL", Severity.CRITICAL),
    ]
    decision = engine.decide(findings, _request())
    assert decision.action == DecisionAction.BLOCK


def test_denylist_blocks_before_scan():
    import asyncio

    from agentshield.core.scanner import AgentShield

    config = Config.model_validate({"denylist": ["evil-pkg"]})
    shield = AgentShield(config=config)
    result = asyncio.run(shield.ascan(ScanRequest(package="evil-pkg", ecosystem=Ecosystem.PYPI)))
    assert result.decision.action == DecisionAction.BLOCK


def test_allowlist_skips_scan():
    import asyncio

    from agentshield.core.scanner import AgentShield

    config = Config.model_validate({"allowlist": ["numpy"]})
    shield = AgentShield(config=config)
    result = asyncio.run(shield.ascan(ScanRequest(package="numpy", ecosystem=Ecosystem.PYPI)))
    assert result.decision.action == DecisionAction.ALLOW
    assert result.cache_hit is True


def test_medium_finding_logs_async_by_default():
    """Default config maps MEDIUM → async_report → LOG_ASYNC (not ALLOW)."""
    engine = ResponseEngine(Config())
    findings = [_finding("CVE-MEDIUM", Severity.MEDIUM)]
    decision = engine.decide(findings, _request())
    assert decision.action == DecisionAction.LOG_ASYNC


def test_log_async_beats_allow():
    """A mix of IGNORE and ASYNC_REPORT findings → LOG_ASYNC, not ALLOW."""
    engine = ResponseEngine(Config())
    findings = [
        _finding("LOW-IGNORED", Severity.LOW),  # default: ignore → ALLOW
        _finding("MED-ASYNC", Severity.MEDIUM),  # default: async_report → LOG_ASYNC
    ]
    decision = engine.decide(findings, _request())
    assert decision.action == DecisionAction.LOG_ASYNC


def test_block_beats_log_async():
    """BLOCK still wins when mixed with LOG_ASYNC."""
    engine = ResponseEngine(Config())
    findings = [
        _finding("MED-ASYNC", Severity.MEDIUM),  # LOG_ASYNC
        _finding("CRIT", Severity.CRITICAL),  # BLOCK
    ]
    decision = engine.decide(findings, _request())
    assert decision.action == DecisionAction.BLOCK


def test_reason_contains_finding_info():
    engine = ResponseEngine(Config())
    findings = [_finding("T1.1", Severity.CRITICAL)]
    decision = engine.decide(findings, _request())
    assert "T1.1" in decision.reason
    assert "CRITICAL" in decision.reason


def test_ecosystem_override_affects_decision():
    config = Config.model_validate(
        {
            "ecosystems": {"pypi": {"high": "block"}},
        }
    )
    engine = ResponseEngine(config)
    req = ScanRequest(package="test-pkg", ecosystem=Ecosystem.PYPI)
    findings = [_finding("RULE", Severity.HIGH)]
    decision = engine.decide(findings, req)
    assert decision.action == DecisionAction.BLOCK


def test_all_ignored_findings_returns_allow_with_reason():
    """When every finding is set to IGNORE, decide() returns ALLOW with the
    'suppressed' reason string (exercises the _build_reason ALLOW branch)."""
    config = Config.model_validate(
        {
            "defaults": {
                "critical": "ignore",
                "high": "ignore",
                "medium": "ignore",
                "low": "ignore",
                "info": "ignore",
            }
        }
    )
    engine = ResponseEngine(config)
    findings = [
        _finding("CVE-LOW", Severity.LOW),
        _finding("CVE-HIGH", Severity.HIGH),
    ]
    decision = engine.decide(findings, _request())
    assert decision.action == DecisionAction.ALLOW
    assert "suppressed" in decision.reason.lower() or "ignore" in decision.reason.lower()
