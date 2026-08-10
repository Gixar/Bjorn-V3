# retry_policy.py
# The "is this action still inside its retry-delay window?" decision, factored out of the
# copy-pasted blocks in orchestrator.py so it can be unit-tested in isolation (no shared_data,
# no hardware/heavy imports). netKB status strings look like 'success_20250101_120000' or
# 'failed_20250101_120000'.

import time
from datetime import datetime, timedelta

_STATUS_TIME_FORMAT = "%Y%m%d_%H%M%S"


def status_settle_seconds(shared_data):
    """How long an action should pause so its name is actually readable on the e-Paper panel.

    Seven actions each hardcoded `time.sleep(5)` with the comment "too fast to see the status
    change". Five seconds was never measured: the display loop renders, calls display_partial
    twice, writes screen.png and sleeps `screen_delay` (default 1s), so two full iterations is the
    real requirement and that is ~2s. At four host actions per cycle the old number spent 20s of
    every working cycle asleep, which on a Pi Zero is throughput, not comfort.

    Derived rather than fixed, so raising screen_delay for a slow panel keeps the status readable
    instead of silently breaking the thing the pause exists for. Floored at 1s so it can never
    vanish, capped at 5s so no config makes it worse than the number it replaced.
    """
    delay = getattr(shared_data, "screen_delay", None)
    # `0` is a real setting ("don't pace the display loop"), not a missing one — `or 1` would have
    # silently promoted it to the default and waited twice as long as asked. Only None/unparseable
    # falls back.
    try:
        delay = 1.0 if delay is None else float(delay)
    except (TypeError, ValueError):
        delay = 1.0
    return max(1.0, min(5.0, 2.0 * delay))


def settle_for_display(shared_data):
    """Pause just long enough for the panel to show the status this action just set."""
    time.sleep(status_settle_seconds(shared_data))


def parse_status_time(status):
    """Extract the timestamp from a status string. Returns a datetime, or None if the
    string has no parseable timestamp (malformed or a bare status)."""
    parts = str(status).split('_')
    if len(parts) < 3:
        return None
    try:
        return datetime.strptime(parts[1] + "_" + parts[2], _STATUS_TIME_FORMAT)
    except ValueError:
        return None


def retry_wait_remaining(status, delay_seconds, now=None):
    """Seconds left before this action's retry delay elapses. 0 means retry is allowed now
    (delay passed, or the status carries no parseable time so it can't block execution)."""
    now = now or datetime.now()
    started = parse_status_time(status)
    if started is None:
        return 0
    # A status stamped in the future means the clock moved backwards, not that the action runs
    # later. The Pi has no RTC: it boots at the fake-hwclock time (a diagnostic pull showed
    # "boot 1970-01-09") and jumps when NTP lands, so anything written before the sync is stamped
    # ahead of everything after it. Taken literally that would park the action until the clock
    # caught up — potentially decades. Treat it as runnable now.
    if started > now:
        return 0
    ready_at = started + timedelta(seconds=delay_seconds)
    if now >= ready_at:
        return 0
    return int((ready_at - now).total_seconds())


def retry_pending(status, delay_seconds, now=None):
    """True if the action is still within its retry-delay window (caller should skip it)."""
    return retry_wait_remaining(status, delay_seconds, now) > 0


if __name__ == "__main__":
    # Minimal self-check (ponytail: money/logic path leaves one runnable check).
    from datetime import datetime as _dt
    base = _dt(2025, 1, 1, 12, 0, 0)
    assert parse_status_time("success_20250101_120000") == base
    assert parse_status_time("malformed") is None
    assert parse_status_time("IDLE") is None
    # Inside the window -> pending; past it -> not pending.
    assert retry_pending("failed_20250101_120000", 600, now=base + timedelta(seconds=300))
    assert not retry_pending("failed_20250101_120000", 600, now=base + timedelta(seconds=700))
    # Unparseable never blocks.
    assert not retry_pending("garbage", 600, now=base)
    print("ok")
