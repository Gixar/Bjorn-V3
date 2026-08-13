"""Tests for the redacted on-Pi planner summary helper."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from planner_report import build_rows  # noqa: E402


def test_report_uses_the_same_smoothed_probability_as_the_planner():
    rows = build_rows({"actions": {"SSH": {
        "attempts": 2,
        "successes": 1,
        "duration_ewma_s": 12.5,
        "last_outcome": "failed",
    }}})
    assert rows == [{
        "action": "SSH",
        "attempts": 2,
        "successes": 1,
        "estimated_success": 0.5,
        "duration_ewma_s": 12.5,
        "last_outcome": "failed",
    }]
