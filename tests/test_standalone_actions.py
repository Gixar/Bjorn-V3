"""Tests for standalone-action scheduling (backlog Wave 4 orchestrator fix).

Two bugs this locks down, both found while adding a 5th standalone action:
  1. The idle loop `break`ed on the first action returning success. Every standalone action
     returns 'success' when it is disabled or throttled, so one switched-off action ate the cycle
     and starved everything registered after it.
  2. A success was recorded permanently and `retry_success_actions` defaults to False, so each
     standalone action ran exactly once per netkb lifetime — which also meant their own interval
     keys (ble_scan_interval etc.) never got a second turn to take effect.

The methods are exercised unbound against a fake `self`, so no Orchestrator (and none of the
hardware/network stack it constructs) is built. Heavy imports stubbed via _stubs.
"""
import sys
import threading
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _stubs  # noqa: E402
_stubs.install()

from orchestrator import Orchestrator  # noqa: E402


class FakeAction:
    """Stands in for a standalone action. `result` mimics what the real ones return — note that
    BLEScan/WpaSecImport/TelegramReport all return 'success' when disabled or throttled."""

    def __init__(self, name, result='success'):
        self.action_name = name
        self.result = result
        self.calls = 0

    def execute(self):
        self.calls += 1
        return self.result


def _fake_self(actions, retry_success_actions=False):
    fake = types.SimpleNamespace(
        standalone_actions=actions,
        semaphore=threading.Semaphore(10),
        shared_data=types.SimpleNamespace(
            retry_success_actions=retry_success_actions,
            success_retry_delay=900,
            failed_retry_delay=600,
        ),
        _record_result=lambda *a, **k: None,
    )
    # run_standalone_actions dispatches through self — bind the real implementation onto the fake
    fake.execute_standalone_action = (
        lambda action, data: Orchestrator.execute_standalone_action(fake, action, data))
    return fake


def _run(fake, data):
    return Orchestrator.run_standalone_actions(fake, data)


def _exec(fake, action, data):
    return Orchestrator.execute_standalone_action(fake, action, data)


def test_disabled_action_no_longer_starves_the_rest():
    """The regression: a disabled BLEScan returns 'success' and used to end the cycle."""
    disabled = FakeAction("BLEScan")          # switched off -> returns success immediately
    later = FakeAction("TelegramReport")
    last = FakeAction("WiFiScan")
    fake = _fake_self([disabled, later, last])
    _run(fake, [])
    assert disabled.calls == 1 and later.calls == 1 and last.calls == 1


def test_every_action_runs_again_next_idle_window():
    """Recurring jobs must not latch off after one success (bug 2)."""
    action = FakeAction("BLEScan")
    fake = _fake_self([action])
    data = []
    for _ in range(3):
        _run(fake, data)
    assert action.calls == 3


def test_success_is_still_recorded_in_netkb():
    action = FakeAction("BLEScan")
    fake = _fake_self([action])
    data = []
    _exec(fake, action, data)
    row = next(r for r in data if r["MAC Address"] == "STANDALONE")
    assert row["BLEScan"].startswith("success_")


def test_failed_action_is_held_off_by_the_failed_retry_delay():
    """The failed-retry gate is deliberately kept — a broken action shouldn't retry every window."""
    action = FakeAction("WiFiScan", result='failed')
    fake = _fake_self([action])
    data = []
    _exec(fake, action, data)      # fails, timestamps the row
    assert action.calls == 1
    _exec(fake, action, data)      # still inside failed_retry_delay -> skipped
    assert action.calls == 1


def test_failed_action_retries_once_the_delay_has_elapsed():
    action = FakeAction("WiFiScan", result='failed')
    fake = _fake_self([action])
    fake.shared_data.failed_retry_delay = 0   # window already over
    data = []
    _exec(fake, action, data)
    _exec(fake, action, data)
    assert action.calls == 2


def test_a_raising_action_does_not_stop_the_others():
    class Boom(FakeAction):
        def execute(self):
            self.calls += 1
            raise RuntimeError("bluetoothctl exploded")

    boom = Boom("BLEScan")
    after = FakeAction("WiFiScan")
    fake = _fake_self([boom, after])
    _run(fake, [])
    assert boom.calls == 1 and after.calls == 1


# --- the 'skipped' outcome (from the 2026-08-05 on-Pi diagnostic) ---------------------------
def test_skipped_action_leaves_no_trace_in_netkb_or_the_run_report():
    """A disabled or throttled action must not look like a working one. A diagnostic pull read
    "WiFiScan: success=4" for an action that had never completed a single capture, because every
    no-op path returned 'success' — the report was reassuring about a feature that was dead."""
    stats = {}
    skipped, working = FakeAction("Disabled", result='skipped'), FakeAction("Working")
    fake = _fake_self([skipped, working])
    fake._record_result = lambda name, ok, **k: stats.setdefault(name, []).append(ok)

    data = []
    _run(fake, data)

    row = next(r for r in data if r["MAC Address"] == "STANDALONE")
    assert skipped.calls == 1, "it must still be given its turn"
    assert row.get("Disabled", "") == "", "a skipped action must not be written to netkb"
    assert "Disabled" not in stats, "a skipped action must not be counted in the run report"
    assert "success" in row["Working"] and stats["Working"] == [True]


def test_skipped_does_not_count_as_work_for_the_cycle():
    """process_alive_ips uses the return value to decide whether the cycle did anything; a no-op
    must not keep Bjorn out of its idle branch."""
    fake = _fake_self([FakeAction("Disabled", result='skipped')])
    assert _exec(fake, fake.standalone_actions[0], []) is False


def test_no_op_paths_in_the_action_modules_return_skipped():
    """Guards the contract in the modules themselves, not just the orchestrator's handling of it."""
    import re
    root = Path(__file__).resolve().parent.parent
    for name in ("ble_scan", "wifi_scan", "wpasec_import", "telegram_report"):
        body = (root / "actions" / f"{name}.py").read_text(encoding="utf-8").split("def execute", 1)[1]
        assert "'skipped'" in body, f"{name}.py has no skipped path — its no-ops read as successes"
        assert not re.search(r"return 'success'\s+# throttled", body), \
            f"{name}.py still reports a throttled no-op as success"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
