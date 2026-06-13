"""Tests for the tanh-based risk scoring formula (PLAN.md §11.3)."""
from __future__ import annotations

import pytest

from agentshield.reports.scoring import risk_label, risk_score


class TestRiskScore:
    def test_zero_inputs(self) -> None:
        assert risk_score(0, 0, 0, 0, 0) == 0

    def test_single_critical(self) -> None:
        score = risk_score(1, 0, 0, 0, 0)
        # Plan reference: 1 critical → ~23 (LOW)
        assert 20 <= score <= 26, f"Expected ~23, got {score}"

    def test_two_criticals(self) -> None:
        score = risk_score(2, 0, 0, 0, 0)
        # Plan reference: 2 criticals → ~35 (MEDIUM)
        assert 30 <= score <= 40, f"Expected ~35, got {score}"

    def test_three_four_criticals(self) -> None:
        score = risk_score(3, 0, 0, 0, 0)
        # Plan reference: 3–4 criticals → ~41 (MEDIUM)
        assert 38 <= score <= 45

    def test_critical_plus_high(self) -> None:
        score = risk_score(1, 3, 0, 0, 0)
        # Plan reference: 1 critical + 3 high → ~46 (MEDIUM)
        assert 42 <= score <= 52, f"Expected ~46, got {score}"

    def test_high_scenario(self) -> None:
        score = risk_score(3, 5, 0, 0, 0)
        # Plan reference: 3 critical + 5 high → ~64 (HIGH)
        assert 60 <= score <= 68, f"Expected ~64, got {score}"

    def test_high_scenario_with_medium(self) -> None:
        score = risk_score(3, 5, 10, 0, 0)
        # Formula: 40*tanh(2)+25*tanh(2.5)+20*tanh(2.5) ≈ 83 (CRITICAL)
        # Note: PLAN.md reference table shows ~73 which is an approximation
        assert 80 <= score <= 86, f"Expected ~83, got {score}"

    def test_critical_scenario_with_tools(self) -> None:
        score = risk_score(3, 5, 10, 0, 3)
        # Formula: above + 5*tanh(1) ≈ 87 (CRITICAL)
        assert 84 <= score <= 90, f"Expected ~87, got {score}"

    def test_caps_at_100(self) -> None:
        score = risk_score(100, 100, 100, 100, 100)
        assert score == 100

    def test_only_lows(self) -> None:
        score = risk_score(0, 0, 0, 16, 0)
        # 16 lows → ~10 * tanh(16/8) = ~10 * tanh(2) ≈ 9.6 → 10
        assert 8 <= score <= 12

    def test_only_tools(self) -> None:
        score = risk_score(0, 0, 0, 0, 3)
        # 3 high-risk tools → ~5 * tanh(1) ≈ 4.2 → 4
        assert 3 <= score <= 6


class TestRiskLabel:
    @pytest.mark.parametrize(
        "score,expected",
        [
            (0, "LOW"),
            (24, "LOW"),
            (25, "MEDIUM"),
            (49, "MEDIUM"),
            (50, "HIGH"),
            (74, "HIGH"),
            (75, "CRITICAL"),
            (100, "CRITICAL"),
        ],
    )
    def test_thresholds(self, score: int, expected: str) -> None:
        assert risk_label(score) == expected
