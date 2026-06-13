from __future__ import annotations

from agentshield.core.config import Config
from agentshield.core.models import (
    Decision,
    DecisionAction,
    Finding,
    ResponseMode,
    ScanRequest,
)


class ResponseEngine:
    def __init__(self, config: Config):
        self.config = config

    def decide(self, findings: list[Finding], request: ScanRequest) -> Decision:
        if not findings:
            return Decision(action=DecisionAction.ALLOW, reason="No issues found")

        # Evaluate each finding's mode; take the strictest action
        worst_action = DecisionAction.ALLOW
        worst_finding: Finding | None = None

        action_order = [
            DecisionAction.ALLOW,
            DecisionAction.LOG_ASYNC,
            DecisionAction.NEEDS_CONFIRMATION,
            DecisionAction.BLOCK,
        ]

        for finding in findings:
            mode = self.config.response_mode_for(
                finding.rule_id, finding.severity, request.ecosystem
            )
            action = _mode_to_action(mode)
            if action_order.index(action) > action_order.index(worst_action):
                worst_action = action
                worst_finding = finding

        reason = _build_reason(worst_action, worst_finding, findings)
        return Decision(action=worst_action, reason=reason, findings=findings)


def _mode_to_action(mode: ResponseMode) -> DecisionAction:
    return {
        ResponseMode.BLOCK: DecisionAction.BLOCK,
        ResponseMode.WARN_CONFIRM: DecisionAction.NEEDS_CONFIRMATION,
        ResponseMode.IGNORE: DecisionAction.ALLOW,
        ResponseMode.ASYNC_REPORT: DecisionAction.LOG_ASYNC,
    }[mode]


def _build_reason(action: DecisionAction, worst: Finding | None, all_findings: list[Finding]) -> str:
    count = len(all_findings)
    if action == DecisionAction.ALLOW:
        return f"{count} finding(s) — all suppressed by ignore policy"
    if worst is None:
        return "No actionable findings"
    return f"{action.value} due to {worst.rule_id} [{worst.severity.value}]: {worst.title} ({count} total finding(s))"
