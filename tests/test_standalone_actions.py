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
import queue
import sys
import threading
import time
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

    def __init__(self, name, result='success', needs_internet=False):
        self.action_name = name
        self.result = result
        self.calls = 0
        self.needs_internet = needs_internet

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


def test_offline_skips_internet_actions_but_runs_the_rest():
    """Offline, a reporting action has nowhere to send. Skipping beats failing once every 60s —
    that cadence is how the old idle loop produced 7000 log lines per window."""
    wifi = FakeAction("WiFiScan")
    report = FakeAction("TelegramReport", needs_internet=True)
    fake = _fake_self([wifi, report])
    data = []

    ran = Orchestrator.run_standalone_actions(fake, data, offline=True)

    assert wifi.calls == 1, "offline recon must still run — it is the only work left"
    assert report.calls == 0, "TelegramReport ran with no uplink"
    assert ran == ["WiFiScan"]


def test_online_runs_internet_actions_normally():
    report = FakeAction("TelegramReport", needs_internet=True)
    fake = _fake_self([report])
    Orchestrator.run_standalone_actions(fake, [], offline=False)
    assert report.calls == 1, "skipping must be offline-only, not a permanent gate"


# --- loader: what may be registered as an action at all ------------------------------------

class _FakeModule:
    """Stand-in for an actions/*.py module. b_needs_internet is optional, as in the real ones."""
    def __init__(self, cls, needs_internet=None):
        self.Thing = cls
        if needs_internet is not None:
            self.b_needs_internet = needs_internet


class _Runnable:
    def __init__(self, shared_data):
        self.shared_data = shared_data

    def execute(self, *a, **k):
        return 'success'


class _Stub:
    """actions/IDLE.py: a template with no execute()."""
    def __init__(self, shared_data):
        self.shared_data = shared_data


def _load(cls, b_port, needs_internet=None):
    """Drive the real load_action() against a fake actions module.

    Registered in sys.modules rather than monkeypatched, so this file still runs as
    `python tests/test_standalone_actions.py` (no pytest fixtures).
    """
    module = _FakeModule(cls, needs_internet)
    module.Thing.__name__ = "Thing"
    sys.modules["actions.thing"] = module
    fake = types.SimpleNamespace(actions=[], standalone_actions=[], shared_data=object())
    Orchestrator.load_action(fake, "thing", {"b_class": "Thing", "b_port": b_port})
    return fake


def test_an_action_without_execute_is_never_registered():
    """The IDLE bug: a stub was queued as a host action, chosen by the planner on every host, and
    raised AttributeError every cycle — 7 errors and 7 failed netkb marks per 10 minutes."""
    fake = _load(_Stub, None)
    assert fake.actions == [] and fake.standalone_actions == []


def test_a_none_port_is_portless_not_a_host_action():
    """`None == 0` is False, so b_port=None used to file a portless action under host actions and
    call it with an ip and a port it never had."""
    fake = _load(_Runnable, None)
    assert len(fake.standalone_actions) == 1
    assert fake.actions == []


def test_a_real_port_still_makes_a_host_action():
    fake = _load(_Runnable, 22)
    assert len(fake.actions) == 1
    assert fake.standalone_actions == []


def test_needs_internet_defaults_off():
    fake = _load(_Runnable, 0)
    assert fake.standalone_actions[0].needs_internet is False
    fake = _load(_Runnable, 0, needs_internet=True)
    assert fake.standalone_actions[0].needs_internet is True


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


def _workers(host_parallel, bruteforce_threads, max_host_actions):
    """Bind _host_parallel_workers onto a fake self so we can drive it with no Orchestrator."""
    fake = types.SimpleNamespace(
        shared_data=types.SimpleNamespace(
            host_parallel=host_parallel, bruteforce_threads=bruteforce_threads),
        planner=types.SimpleNamespace(max_host_actions=max_host_actions),
    )
    return lambda n_groups: Orchestrator._host_parallel_workers(fake, n_groups)


def test_host_parallel_worker_count_stays_within_budget():
    """#8: the outer host-worker count must never let outer x bruteforce_threads thrash a Pi Zero,
    and host_parallel=1 must preserve the old serial behaviour. Assertions are core-count
    independent so this holds on any CI box."""
    assert _workers(1, 0, 4)(8) == 1, "host_parallel=1 must stay serial"
    assert _workers(0, 1, 4)(1) == 1, "never more workers than host groups"
    assert _workers(0, 1, 4)(100) == 4, "never exceed the planner's per-cycle host cap"
    assert _workers(16, 1, 4)(2) == 2, "explicit N is still capped by groups and the planner cap"
    # More inner brute-force threads must shrink (never grow) the outer pool — the budget division.
    assert _workers(0, 8, 4)(100) <= _workers(0, 1, 4)(100)


def _vuln_fake(scanner):
    """Fake `self` carrying the #9 background-sweep state. `_vuln_worker` is bound explicitly
    because `_run_vuln_scans` submits it as a callable off the instance."""
    fake = types.SimpleNamespace(
        nmap_vuln_scanner=scanner,
        shared_data=types.SimpleNamespace(
            retry_success_actions=False, success_retry_delay=900, failed_retry_delay=600),
        _vuln_pool=None,
        _vuln_results=queue.Queue(),
        _vuln_inflight=set(),
    )
    fake._vuln_worker = lambda ip, snap: Orchestrator._vuln_worker(fake, ip, snap)
    return fake


class _InlinePool:
    """Runs the work on submit, so the queue is populated deterministically. It still proves the
    contract that matters: the sweep itself never stamps netkb, only the drain does."""
    def submit(self, fn, *args):
        fn(*args)


def test_vuln_scan_submits_only_eligible_hosts_and_drain_stamps_results():
    """#9: the sweep picks eligible alive hosts and hands them to the pool. Dead hosts and hosts
    that succeeded recently (retry-on-success off) are skipped; 'skipped' leaves no netkb mark
    (the contract execute() documents — the old serial loop wrongly stamped it 'failed').

    Stamping now happens in _apply_vuln_results, against a *later* read of netkb: the drain is
    given a fresh list of row dicts, as read_data() would return minutes after the submit, to
    prove results are keyed by IP rather than by the row object that was submitted."""
    scanned = []
    results = {"10.0.0.1": "success", "10.0.0.2": "skipped", "10.0.0.3": "failed"}

    class FakeScanner:
        def execute(self, ip, row, status):
            scanned.append(ip)
            return results[ip]

    fake = _vuln_fake(FakeScanner())
    fake._vuln_pool = _InlinePool()
    data = [
        {"Alive": "1", "IPs": "10.0.0.1", "NmapVulnScanner": ""},
        {"Alive": "0", "IPs": "10.0.0.9", "NmapVulnScanner": ""},                       # dead -> not scanned
        {"Alive": "1", "IPs": "10.0.0.2", "NmapVulnScanner": ""},
        {"Alive": "1", "IPs": "10.0.0.3", "NmapVulnScanner": ""},
        {"Alive": "1", "IPs": "10.0.0.4", "NmapVulnScanner": "success_20990101_000000"},  # recent success, retry off -> skip
    ]
    Orchestrator._run_vuln_scans(fake, data)

    assert set(scanned) == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}, "dead / already-succeeded hosts must not be scanned"
    assert all(r["NmapVulnScanner"] in ("", "success_20990101_000000") for r in data), \
        "the sweep must not stamp netkb itself — that is the main thread's job"

    # A later cycle: same hosts, brand-new dicts, plus one host that has since left the netkb.
    later = [{"Alive": "1", "IPs": ip, "NmapVulnScanner": ""} for ip in ("10.0.0.1", "10.0.0.2")]
    applied = Orchestrator._apply_vuln_results(fake, later)

    assert later[0]["NmapVulnScanner"].startswith("success_")
    assert later[1]["NmapVulnScanner"] == "", "'skipped' must leave no netkb mark"
    assert applied == 1, "only the success stamped; skipped writes nothing and 10.0.0.3 is gone"
    assert fake._vuln_inflight == set(), "every drained result must clear its in-flight entry"


def test_vuln_sweep_returns_while_the_scans_are_still_running():
    """#9, the point of the change: _run_vuln_scans must not block the cycle.

    It used to wait on the pool, so with nmap bounded at 300s (#4) and 2 workers a ten-host sweep
    held the orchestrator for up to 25 minutes — no rescan, no connectors, no stealers, and an
    un-timed join() on shutdown. Here the fake scanner blocks until the test releases it; the
    sweep must still return, and a second sweep must not re-submit a host already in flight."""
    release = threading.Event()
    started = threading.Event()

    class BlockingScanner:
        def execute(self, ip, row, status):
            started.set()
            assert release.wait(timeout=10), "scanner was never released"
            return "success"

    fake = _vuln_fake(BlockingScanner())
    data = [{"Alive": "1", "IPs": "10.0.0.1", "NmapVulnScanner": ""}]
    try:
        began = time.monotonic()
        Orchestrator._run_vuln_scans(fake, data)          # would wait for the scan before the fix
        submit_took = time.monotonic() - began
        # The scan is still blocked and will be for seconds yet. Submitting must not have waited
        # for it — that is the whole of #9. Generous bound: the real block is 10s, nmap's is 300s.
        assert submit_took < 2, f"_run_vuln_scans blocked for {submit_took:.1f}s on a running scan"
        assert started.wait(timeout=10), "the scan never started"
        assert fake._vuln_inflight == {"10.0.0.1"}

        # The interval gate fires again while the scan is still running: no second submit.
        Orchestrator._run_vuln_scans(fake, data)
        assert Orchestrator._apply_vuln_results(fake, data) == 0, "nothing has finished yet"
        assert data[0]["NmapVulnScanner"] == ""

        release.set()
        fake._vuln_pool.shutdown(wait=True)
        assert Orchestrator._apply_vuln_results(fake, data) == 1
        assert data[0]["NmapVulnScanner"].startswith("success_")
    finally:
        release.set()
        if fake._vuln_pool is not None:
            fake._vuln_pool.shutdown(wait=False)


def test_vuln_worker_reports_even_when_execute_raises():
    """A worker that dies must still put a result, or its IP is stuck in _vuln_inflight forever
    and the host is never scanned again — a silent permanent skip, the #5 defect class."""
    class Boom:
        def execute(self, ip, row, status):
            raise RuntimeError("nmap exploded")

    fake = _vuln_fake(Boom())
    fake._vuln_pool = _InlinePool()
    data = [{"Alive": "1", "IPs": "10.0.0.1", "NmapVulnScanner": ""}]
    Orchestrator._run_vuln_scans(fake, data)

    assert Orchestrator._apply_vuln_results(fake, data) == 0, "a raise is not a netkb stamp"
    assert fake._vuln_inflight == set(), "the host must be eligible again, not stuck in flight"


# --- the idle-loop spin fix: a standalone-only cycle must not count as host work ---------------

def _proc_fake(select_result, run_returns=True):
    """Minimal fake self for Orchestrator.process_alive_ips: the planner selects `select_result`
    and every candidate 'runs' with `run_returns`. The vuln/hint loaders read missing files and
    return empty (they catch FileNotFoundError), so no real I/O is needed."""
    return types.SimpleNamespace(
        actions=[], standalone_actions=[],
        planner=types.SimpleNamespace(
            sync_config=lambda *a, **k: None,
            collect=lambda *a, **k: [],
            select=lambda *a, **k: select_result,
        ),
        shared_data=types.SimpleNamespace(
            orchestrator_should_exit=False,
            vuln_summary_file="/nonexistent/vuln.csv",
            scan_results_dir="/nonexistent",
        ),
        _run_candidate=lambda cand, data: run_returns,
        _host_parallel_workers=lambda n: 1,
        _flush_action_telemetry=lambda: None,
    )


def test_a_standalone_only_cycle_does_not_count_as_host_work():
    """The idle-spin fix: a periodic standalone (e.g. SNMPEnum on a hostless net) runs, but
    process_alive_ips must report False so run() takes its paced idle wait instead of spinning the
    CPU — ~10 cycles/s was observed on an empty network."""
    standalone = types.SimpleNamespace(kind="standalone", row=None, ip=None)
    assert Orchestrator.process_alive_ips(_proc_fake([standalone]), []) is False


def test_a_host_action_still_counts_as_work():
    """The other half: a real host action must still return True so the loop keeps attacking
    without an idle wait between cycles."""
    host = types.SimpleNamespace(kind="host", row={"MAC Address": "AA:BB:CC:DD:EE:01"}, ip="10.0.0.5")
    assert Orchestrator.process_alive_ips(_proc_fake([host]), []) is True


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
