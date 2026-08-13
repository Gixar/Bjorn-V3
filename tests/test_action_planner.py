"""Tests for the orchestrator's work-selection heuristic (action_planner).

Pure ranking logic — no SharedData, no hardware, no netkb. Fake actions carry only the three
attributes the planner reads (action_name / port / b_parent_action), which is also a check that it
stays that loosely coupled.
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from action_planner import (  # noqa: E402
    Planner,
    host_gate,
    is_host_action_eligible,
    is_standalone_eligible,
    load_service_hints,
    load_vuln_ips,
    plan_idle_seconds,
    score_host_action,
    score_standalone,
)
from action_outcome import ActionOutcome, OutcomeCode  # noqa: E402
from action_telemetry import ActionTelemetry  # noqa: E402


class FakeAction:
    def __init__(self, name, port=None, parent=None):
        self.action_name = name
        self.port = port
        self.b_parent_action = parent


def _row(ip="192.168.1.10", ports="22;80", alive="1", **statuses):
    row = {"MAC Address": "aa:bb:cc:dd:ee:ff", "IPs": ip, "Hostnames": "host",
           "Ports": ports, "Alive": alive}
    row.update(statuses)
    return row


def _standalone_row(**statuses):
    row = {"MAC Address": "STANDALONE", "IPs": "STANDALONE", "Hostnames": "STANDALONE",
           "Ports": "0", "Alive": "0"}
    row.update(statuses)
    return row


SUCCESS = "success_20260101_120000"  # old enough that no retry window is still open


# --- scoring ------------------------------------------------------------------------------
def test_never_tried_outranks_already_done():
    action = FakeAction("SSHBruteforce", port=22)
    assert (score_host_action(action, _row())[0]
            > score_host_action(action, _row(SSHBruteforce=SUCCESS))[0])


def test_parent_ready_steal_ranks_high_and_says_why():
    steal = FakeAction("StealFilesSSH", port=22, parent="SSHBruteforce")
    ready, reason = score_host_action(steal, _row(SSHBruteforce=SUCCESS))
    assert ready > score_host_action(steal, _row())[0]
    assert "parent ok" in reason


def test_high_value_port_beats_low_value_port():
    ssh, telnet = FakeAction("SSHBruteforce", port=22), FakeAction("TelnetBruteforce", port=23)
    assert (score_host_action(ssh, _row(ports="22"))[0]
            > score_host_action(telnet, _row(ports="23"))[0])


def test_known_cves_boost_the_host():
    action = FakeAction("SSHBruteforce", port=22)
    plain, _ = score_host_action(action, _row(ip="10.0.0.5"))
    vulnerable, reason = score_host_action(action, _row(ip="10.0.0.5"), {"10.0.0.5"})
    assert vulnerable > plain and "has CVEs" in reason


# --- eligibility --------------------------------------------------------------------------
def test_eligibility_requires_open_port_and_succeeded_parent():
    steal = FakeAction("StealFilesSSH", port=22, parent="SSHBruteforce")
    gates = dict(success_retry_delay=900, failed_retry_delay=600, retry_success_actions=False)
    assert not is_host_action_eligible(steal, _row(), **gates)                       # parent unmet
    assert is_host_action_eligible(steal, _row(SSHBruteforce=SUCCESS), **gates)
    assert not is_host_action_eligible(steal, _row(ports="80", SSHBruteforce=SUCCESS), **gates)
    assert not is_host_action_eligible(steal, _row(alive="0", SSHBruteforce=SUCCESS), **gates)


def test_host_action_is_not_repeated_after_success():
    """`retry_success_actions` off means 'don't re-attack a box you already cracked'."""
    action = FakeAction("SSHBruteforce", port=22)
    assert not is_host_action_eligible(
        action, _row(SSHBruteforce=SUCCESS),
        success_retry_delay=900, failed_retry_delay=600, retry_success_actions=False)


def test_standalone_stays_eligible_after_success():
    """The Wave 4 regression this planner must not reintroduce: standalone actions are recurring
    jobs that throttle themselves by interval. If the scheduler applied the host success gate to
    them, one success would retire BLEScan/WiFiScan/TelegramReport for the netkb's lifetime."""
    ble = FakeAction("BLEScan", port=0)
    assert is_standalone_eligible(ble, _standalone_row(BLEScan=SUCCESS), failed_retry_delay=600)


def test_standalone_still_backs_off_after_a_failure():
    """Self-throttling covers success, not breakage — a failing action must still back off."""
    import time
    fresh = time.strftime("failed_%Y%m%d_%H%M%S")
    ble = FakeAction("BLEScan", port=0)
    assert not is_standalone_eligible(ble, _standalone_row(BLEScan=fresh), failed_retry_delay=600)
    assert is_standalone_eligible(ble, _standalone_row(BLEScan=fresh), failed_retry_delay=0)


# --- selection ----------------------------------------------------------------------------
def test_load_order_no_longer_decides_what_runs():
    """The core fix: the old loop walked actions in load order, so whatever loaded first always
    went first. Here the *last*-loaded action targets the better port and must still win."""
    telnet, ssh = FakeAction("TelnetBruteforce", port=23), FakeAction("SSHBruteforce", port=22)
    data = [_row(ip="192.168.1.10", ports="23"), _row(ip="192.168.1.11", ports="22")]
    planner = Planner(standalone_every=99, max_host_actions=1)
    work = planner.select(planner.collect([telnet, ssh], [], data))
    assert len(work) == 1 and work[0].action_name == "SSHBruteforce"


def test_one_action_class_cannot_monopolise_a_cycle():
    """Twenty SSH boxes must not fill the whole window with SSH."""
    ssh, ftp = FakeAction("SSHBruteforce", port=22), FakeAction("FTPBruteforce", port=21)
    data = [_row(ip=f"192.168.1.{i}", ports="22;21") for i in range(2, 22)]
    planner = Planner(standalone_every=99, max_host_actions=4)
    names = [c.action_name for c in planner.select(planner.collect([ssh, ftp], [], data))]
    assert names.count("SSHBruteforce") == 1 and "FTPBruteforce" in names


def test_parent_ready_steals_are_exempt_from_the_diversity_rule():
    """Unlocked loot on several hosts should all be collected in one cycle, unlike brute-force.
    Keyed on 'has a satisfied parent', not a score threshold — a never-tried SSH scores as high as
    a parent-ready steal, so a threshold would readmit the monopoly the rule prevents."""
    steal = FakeAction("StealFilesSSH", port=22, parent="SSHBruteforce")
    data = [_row(ip=f"192.168.1.{i}", ports="22", SSHBruteforce=SUCCESS) for i in range(2, 8)]
    planner = Planner(standalone_every=99, max_host_actions=4)
    work = planner.select(planner.collect([steal], [], data))
    assert len(work) == 4, "every parent-ready steal should fill the window"


def test_standalone_is_interleaved_while_host_work_remains():
    """Standalone recon used to run only once the whole net was idle."""
    ssh = FakeAction("SSHBruteforce", port=22)
    ble = FakeAction("BLEScan", port=0)
    data = [_row(ports="22"), _standalone_row()]
    planner = Planner(standalone_every=1, max_host_actions=2)
    work = planner.select(planner.collect([ssh], [ble], data))
    kinds = [c.kind for c in work]
    assert "host" in kinds and "standalone" in kinds


def test_standalone_runs_when_no_host_work_exists():
    ble = FakeAction("BLEScan", port=0)
    planner = Planner(standalone_every=99, max_host_actions=4)
    work = planner.select(planner.collect([], [ble], [_standalone_row()]))
    assert [c.kind for c in work] == ["standalone"]


def test_recently_run_actions_are_penalised():
    ssh = FakeAction("SSHBruteforce", port=22)
    data = [_row(ip="192.168.1.10", ports="22"), _row(ip="192.168.1.11", ports="22")]
    planner = Planner(standalone_every=99, max_host_actions=1)
    first = planner.select(planner.collect([ssh], [], data))[0].score
    second = planner.collect([ssh], [], data)[0].score
    assert second < first, "an action just run should lose ground to anything else eligible"


def test_sync_config_clamps_hand_edited_values():
    """standalone_every is a modulus — 0 would divide by zero mid-cycle."""
    import types
    planner = Planner()
    planner.sync_config(types.SimpleNamespace(planner_standalone_every=0,
                                              planner_max_host_actions=0))
    assert planner.standalone_every >= 1 and planner.max_host_actions >= 1
    planner.select([])  # must not raise


# --- vuln signal --------------------------------------------------------------------------
def test_load_vuln_ips_reads_only_hosts_with_findings():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "vulnerability_summary.csv"
        path.write_text(
            "IP,Hostname,MAC Address,Port,Vulnerabilities\n"
            "10.0.0.1,a,aa,22,CVE-2021-1234\n"
            "10.0.0.2,b,bb,80,\n",                 # scanned, nothing found -> not a signal
            encoding="utf-8")
        assert load_vuln_ips(path) == {"10.0.0.1"}


def test_load_vuln_ips_missing_file_is_not_an_error():
    assert load_vuln_ips("/nonexistent/vulnerability_summary.csv") == set()


# --- service hints ------------------------------------------------------------------------
def _fingerprint_csv(tmp, *rows):
    path = Path(tmp) / "http_fingerprints.csv"
    body = "IP,Hostname,Port,Status,Server,X-Powered-By,Title,URL\n" + "".join(rows)
    path.write_text(body, encoding="utf-8")
    return path


def test_service_hints_identify_appliances_and_ignore_plain_web_servers():
    with tempfile.TemporaryDirectory() as tmp:
        path = _fingerprint_csv(
            tmp,
            "10.0.0.1,nas,5000,200,nginx,,Synology DiskStation,http://10.0.0.1:5000\n",
            "10.0.0.2,web,80,200,nginx,PHP/8.1,Welcome,http://10.0.0.2\n",
        )
        hints = load_service_hints(path)
        assert hints["10.0.0.1"] == (30, "NAS")
        assert "10.0.0.2" not in hints, "a generic web server says nothing about the host"


def test_service_hints_keep_the_strongest_signal_per_host():
    """One host, several web ports: a NAS behind a plain server must not be downgraded."""
    with tempfile.TemporaryDirectory() as tmp:
        path = _fingerprint_csv(
            tmp,
            "10.0.0.1,nas,80,200,GoAhead-Webs,,Login,http://10.0.0.1\n",       # embedded, 20
            "10.0.0.1,nas,5000,200,nginx,,QNAP Turbo NAS,http://10.0.0.1:5000\n",  # NAS, 30
        )
        assert load_service_hints(path)["10.0.0.1"] == (30, "NAS")


def test_service_hint_raises_the_score_and_names_the_device():
    action = FakeAction("SSHBruteforce", port=22)
    plain, _ = score_host_action(action, _row(ip="10.0.0.1"))
    hinted, reason = score_host_action(action, _row(ip="10.0.0.1"), None,
                                       {"10.0.0.1": (28, "camera")})
    assert hinted == plain + 28 and "camera" in reason


def test_missing_fingerprint_file_is_not_an_error():
    assert load_service_hints("/nonexistent/http_fingerprints.csv") == {}


# --- adaptive idle interval ---------------------------------------------------------------
def test_idle_backs_off_as_scans_stay_fruitless_but_is_capped():
    assert plan_idle_seconds(180, 1) == 180
    assert plan_idle_seconds(180, 2) == 360
    assert plan_idle_seconds(180, 9) == 720, "capped at 4x so a new device is still noticed"


def test_idle_wakes_early_when_a_retry_window_expires_first():
    assert plan_idle_seconds(180, 1, next_retry_wait=45) == 45
    # ...but never busy-loops on a nearly-expired window.
    assert plan_idle_seconds(180, 1, next_retry_wait=2) == 30


def test_idle_ignores_a_retry_window_that_lands_after_the_interval():
    assert plan_idle_seconds(180, 1, next_retry_wait=600) == 180


def test_planner_reports_when_the_soonest_blocked_action_unblocks():
    """The number the adaptive interval consumes: a host action inside its failed backoff."""
    import time
    fresh = time.strftime("failed_%Y%m%d_%H%M%S")
    ssh = FakeAction("SSHBruteforce", port=22)
    planner = Planner(standalone_every=99, failed_retry_delay=600)
    assert planner.collect([ssh], [], [_row(ports="22", SSHBruteforce=fresh)]) == []
    assert 0 < planner.next_retry_wait <= 600


def test_permanent_blocks_do_not_count_as_a_wait():
    """A success with retry_success_actions off never becomes runnable — sleeping for it would be
    sleeping forever, so it must not shorten (or lengthen) the idle interval."""
    ssh = FakeAction("SSHBruteforce", port=22)
    planner = Planner(standalone_every=99, retry_success_actions=False)
    planner.collect([ssh], [], [_row(ports="22", SSHBruteforce=SUCCESS)])
    assert planner.next_retry_wait == 0

    # A closed port is structural, not temporal — same rule.
    planner.collect([ssh], [], [_row(ports="80")])
    assert planner.next_retry_wait == 0


def test_host_gate_reports_eligibility_and_wait_together():
    ssh = FakeAction("SSHBruteforce", port=22)
    gates = dict(success_retry_delay=900, failed_retry_delay=600, retry_success_actions=False)
    assert host_gate(ssh, _row(ports="22"), **gates) == (True, 0)
    assert host_gate(ssh, _row(ports="80"), **gates) == (False, 0)


def test_standalone_score_rises_when_idle():
    ble = FakeAction("BLEScan", port=0)
    row = _standalone_row(BLEScan=SUCCESS)
    assert (score_standalone(ble, row, idle_boost=40)[0]
            > score_standalone(ble, row, idle_boost=0)[0])


# --- deterministic local learning ---------------------------------------------------------
def test_smart_score_prefers_measured_fast_reliable_work():
    """Enough local evidence can overturn a static prior without any model or cloud service."""
    telemetry = ActionTelemetry()
    fast = FakeAction("HTTPFingerprint", port=80)
    slow = FakeAction("SSHBruteforce", port=22)
    for index in range(8):
        telemetry.record(
            fast.action_name, f"fast-{index}",
            ActionOutcome(OutcomeCode.SUCCESS, duration_s=4))
        telemetry.record(
            slow.action_name, f"slow-{index}",
            ActionOutcome(OutcomeCode.SUCCESS if index == 0 else OutcomeCode.FAILED,
                          duration_s=100))

    fast_score, fast_reason = score_host_action(
        fast, _row(ports="80"), telemetry=telemetry, smart_enabled=True)
    slow_score, _ = score_host_action(
        slow, _row(ports="22"), telemetry=telemetry, smart_enabled=True)
    assert fast_score > slow_score
    assert "smart:p=" in fast_reason and "t=4s" in fast_reason


def test_cold_start_uses_a_small_deterministic_utility_prior():
    action = FakeAction("SSHBruteforce", port=22)
    row = _row(ports="22")
    legacy = score_host_action(action, row)[0]
    smart, reason = score_host_action(
        action, row, telemetry=ActionTelemetry(), smart_enabled=True)
    assert smart != legacy and "smart:prior" in reason


def test_cold_start_still_collects_unlocked_loot_first():
    steal = FakeAction("StealFilesSSH", port=22, parent="SSHBruteforce")
    fingerprint = FakeAction("HTTPFingerprint", port=80)
    telemetry = ActionTelemetry()
    steal_score, _ = score_host_action(
        steal, _row(ports="22", SSHBruteforce=SUCCESS),
        telemetry=telemetry, smart_enabled=True)
    fingerprint_score, _ = score_host_action(
        fingerprint, _row(ports="80"), telemetry=telemetry, smart_enabled=True)
    assert steal_score > fingerprint_score, "ready loot must survive the prior blend"


def test_smart_backoff_blocks_only_the_failed_target():
    telemetry = ActionTelemetry()
    ssh = FakeAction("SSHBruteforce", port=22)
    telemetry.record(
        ssh.action_name, "10.0.0.1",
        ActionOutcome(OutcomeCode.TIMEOUT, duration_s=30))
    planner = Planner(
        telemetry=telemetry, smart_enabled=True,
        standalone_every=99, failed_retry_delay=600)
    data = [
        _row(ip="10.0.0.1", ports="22"),
        _row(ip="10.0.0.2", ports="22"),
    ]
    candidates = planner.collect([ssh], [], data)
    assert [candidate.ip for candidate in candidates] == ["10.0.0.2"]
    assert 0 < planner.next_retry_wait <= 600


def test_config_toggle_restores_legacy_scoring():
    import types
    planner = Planner(telemetry=ActionTelemetry(), smart_enabled=True)
    planner.sync_config(types.SimpleNamespace(
        smart_planner_enabled=False,
        planner_standalone_every=3,
        planner_max_host_actions=4,
    ))
    assert planner.smart_enabled is False


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
