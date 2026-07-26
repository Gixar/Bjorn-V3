"""Tests for retry_policy — the action retry-delay window decision (PRD §9 step 5 / P1-4).
Runs under pytest and as `python tests/test_retry_policy.py` (zero install).
"""
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from retry_policy import parse_status_time, retry_wait_remaining, retry_pending  # noqa: E402

BASE = datetime(2025, 1, 1, 12, 0, 0)


def test_parse_status_time():
    assert parse_status_time("success_20250101_120000") == BASE
    assert parse_status_time("failed_20250101_120000") == BASE
    assert parse_status_time("malformed") is None
    assert parse_status_time("IDLE") is None
    assert parse_status_time("success_notadate_here") is None


def test_within_window_is_pending():
    # 300s into a 600s delay -> still waiting.
    assert retry_pending("failed_20250101_120000", 600, now=BASE + timedelta(seconds=300))
    assert retry_wait_remaining("failed_20250101_120000", 600, now=BASE + timedelta(seconds=300)) == 300


def test_past_window_not_pending():
    assert not retry_pending("failed_20250101_120000", 600, now=BASE + timedelta(seconds=700))
    assert retry_wait_remaining("failed_20250101_120000", 600, now=BASE + timedelta(seconds=700)) == 0


def test_malformed_never_blocks():
    # An unparseable status must not lock the action out forever.
    assert not retry_pending("garbage", 600, now=BASE)
    assert not retry_pending("", 600, now=BASE)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
