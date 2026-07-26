# retry_policy.py
# The "is this action still inside its retry-delay window?" decision, factored out of the
# copy-pasted blocks in orchestrator.py so it can be unit-tested in isolation (no shared_data,
# no hardware/heavy imports). netKB status strings look like 'success_20250101_120000' or
# 'failed_20250101_120000'.

from datetime import datetime, timedelta

_STATUS_TIME_FORMAT = "%Y%m%d_%H%M%S"


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
