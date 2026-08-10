"""Tests for the hunter's place in the offline cycle (docs/BETTERCAP_PLAN.md step C4).

This file exists for ONE property, the plan's acceptance criterion 4:

    with the hunter enabled and Bjorn offline, auto-join must still work.

nmcli cannot associate an interface that is still in monitor mode, and it fails *quietly*. So a
hunter that outlives its window does not produce an error — it produces a Bjorn that sits offline
forever with a growing pile of handshakes it can never deliver, and a log that says only
"nothing joinable in range". The radio therefore has to be back in managed mode before any
reconnect attempt, and that is what is asserted here.

Methods are exercised unbound against a fake `self`, so no Orchestrator (and none of the hardware
stack it constructs) is built.
"""
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _stubs  # noqa: E402
_stubs.install()

import monitor_mode  # noqa: E402
from orchestrator import Orchestrator  # noqa: E402


class FakeHunter:
    """Records start/stop order AND takes the real radio lock.

    Taking the lock matters: without it `monitor_mode.holder()` is always "" and the assertion
    that the radio is free at reconnect time passes no matter what the ordering is. The lock state
    is set directly rather than through acquire(), which would need the whole guard faked — the
    point here is the interleaving, not the guard (that has its own tests)."""

    def __init__(self, events, can_start=True):
        self.events = events
        self._can_start = can_start
        self.running = False

    def start(self):
        if not self._can_start:
            self.events.append("start-refused")
            return False, "only 1 wireless radio"
        monitor_mode._radio_lock.acquire(blocking=False)
        monitor_mode._radio_owner = "pwn"
        self.running = True
        self.events.append("hunt-start")
        return True, "hunting on wlan1"

    def stop(self):
        monitor_mode._radio_owner = ""
        if monitor_mode._radio_lock.locked():
            monitor_mode._radio_lock.release()
        self.running = False
        self.events.append("hunt-stop")
        return True, "stopped; wlan1 back in managed mode"

    def is_running(self):
        return self.running


def _shared(**over):
    base = dict(bettercap_pwn_enabled=True, orchestrator_should_exit=True,
                offline_cycle_interval=15, bjornorch_status="", bjornstatustext2="")
    base.update(over)
    return types.SimpleNamespace(**base)


def _run_idle(shared, hunter, events):
    """Drive _offline_idle unbound. orchestrator_should_exit is already True, so the wait loop
    exits immediately — this test is about ordering, not about spending 15 seconds."""
    me = types.SimpleNamespace(shared_data=shared, last_hunt_detail=None, _hunter=lambda: hunter)
    Orchestrator._offline_idle(me, shared.offline_cycle_interval)
    return events


def test_hunter_really_constructs_one():
    """The real `_hunter()`, not an injected fake.

    Every other test in this file passes `_hunter=lambda: hunter`, which stubs out the exact line
    that was broken: `_hunter` called `bettercap_pwn.Hunter(...)` while orchestrator.py only
    imported `bettercap_client`, so enabling the hunter raised NameError on every offline cycle —
    shipped in v3.0.0-beta and invisible to a suite that mocked the call away. A test that replaces
    the thing under test does not test it.
    """
    import bettercap_pwn
    import orchestrator as orch

    shared = _shared()
    me = types.SimpleNamespace(shared_data=shared)
    hunter = orch.Orchestrator._hunter(me)
    assert isinstance(hunter, bettercap_pwn.Hunter)
    # cached on shared_data so the web panel and the orchestrator see the same object
    assert shared.hunter is hunter
    assert orch.Orchestrator._hunter(me) is hunter


def test_the_hunter_never_outlives_the_idle_window():
    """The invariant the whole feature rests on: whatever happens inside the window, the hunter is
    stopped before it returns — so the next cycle's reconnect always finds a managed radio."""
    events = []
    _run_idle(_shared(), FakeHunter(events), events)
    assert events == ["hunt-start", "hunt-stop"]


def test_the_radio_is_handed_back_even_if_the_wait_is_interrupted():
    """A shutdown mid-window must still return the radio, or Bjorn restarts into an interface
    nothing can associate."""
    events = []
    shared = _shared(orchestrator_should_exit=True)
    _run_idle(shared, FakeHunter(events), events)
    assert events[-1] == "hunt-stop"


def test_a_refused_hunter_does_not_leave_a_stop_pending():
    """can_start refusing (single radio, managed mode on, bettercap missing) must not result in a
    stop() against a hunter that never took the radio — release() would refuse it anyway, but the
    call has no business happening."""
    events = []
    _run_idle(_shared(), FakeHunter(events, can_start=False), events)
    assert events == ["start-refused"]


def test_disabled_means_the_hunter_is_never_even_asked():
    """Off by default has to mean no call at all: constructing and asking a hunter every offline
    cycle would log a refusal every 60 seconds on every device that has no second radio."""
    events = []
    hunter = FakeHunter(events)
    shared = _shared(bettercap_pwn_enabled=False)
    me = types.SimpleNamespace(shared_data=shared, last_hunt_detail=None,
                               _hunter=lambda: (_ for _ in ()).throw(
                                   AssertionError("hunter must not be created when disabled")))
    Orchestrator._offline_idle(me, 15)
    assert events == []
    assert shared.bjornstatustext2 == "offline · resting"


def test_reconnect_only_ever_runs_with_the_radio_free():
    """Acceptance criterion 4, end to end over one offline cycle: at the moment reconnect_best is
    called, nobody holds the radio. This is the check that would have caught a hunter started in
    the wrong half of the cycle."""
    import offline_mode
    import orchestrator as orch

    events = []
    holder_at_reconnect = []

    def spy_reconnect(_shared_data):
        holder_at_reconnect.append(monitor_mode.holder())
        events.append("reconnect")
        return False, "nothing joinable in range"

    shared = _shared(offline_mode_enabled=True, wifi_autojoin=True,
                     orchestrator_should_exit=True, netkbfile="", bettercap_pwn_enabled=True)
    hunter = FakeHunter(events)
    me = types.SimpleNamespace(
        shared_data=shared, offline_since=None, last_autojoin_detail=None,
        last_hunt_detail=None, _hunter=lambda: hunter,
        run_standalone_actions=lambda data, offline=False: events.append("recon"),
        merge_bettercap_hosts=lambda data: None,
    )
    # unbound, like every other method here, so the real ordering is what runs
    me._offline_idle = lambda seconds: orch.Orchestrator._offline_idle(me, seconds)
    shared.read_data = lambda: []
    shared.write_data = lambda data: None

    saved_online, saved_reconnect = offline_mode.is_online, offline_mode.reconnect_best
    offline_mode.is_online = lambda: False
    offline_mode.reconnect_best = spy_reconnect
    try:
        assert orch.Orchestrator.run_offline_cycle(me) is True
    finally:
        offline_mode.is_online, offline_mode.reconnect_best = saved_online, saved_reconnect

    assert events == ["recon", "reconnect", "hunt-start", "hunt-stop"], events
    assert holder_at_reconnect == [""], "the radio must be free when nmcli tries to associate"
    assert not hunter.is_running(), "the cycle must not end with the radio held"


if __name__ == "__main__":
    import inspect
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn) and not inspect.signature(fn).parameters:
            fn()
    print("ok")
