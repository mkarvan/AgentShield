"""Risk scoring for posture reports.

Uses a tanh-based saturation formula so each severity band contributes
diminishing returns as the count grows (see PLAN.md §11.3).
"""
from __future__ import annotations

from math import tanh

_THRESHOLDS = [
    (75, "CRITICAL"),
    (50, "HIGH"),
    (25, "MEDIUM"),
    (0, "LOW"),
]


def risk_score(
    critical_count: int,
    high_count: int,
    medium_count: int,
    low_count: int,
    high_risk_tool_count: int,
) -> int:
    """Return a 0–100 integer risk score.

    Each band saturates via tanh so that the 5th critical finding adds much
    less marginal risk than the 1st.  Maximum contributions per band:
    critical=40, high=25, medium=20, low=10, tools=5 → total cap 100.
    """
    score = (
        40 * tanh(critical_count / 1.5)
        + 25 * tanh(high_count / 2.0)
        + 20 * tanh(medium_count / 4.0)
        + 10 * tanh(low_count / 8.0)
        + 5 * tanh(high_risk_tool_count / 3.0)
    )
    return min(100, round(score))


def risk_label(score: int) -> str:
    """Return the human-readable risk label for a numeric score (0–100)."""
    for threshold, label in _THRESHOLDS:
        if score >= threshold:
            return label
    return "LOW"
