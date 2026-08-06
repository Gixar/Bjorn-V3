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
    is_host_action_eligible,
    is_standalone_eligible,
    load_vuln_ips,
    score_host_action,
    score_standalone,
)


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


def test_standalone_score_rises_when_idle():
    ble = FakeAction("BLEScan", port=0)
    row = _standalone_row(BLEScan=SUCCESS)
    assert (score_standalone(ble, row, idle_boost=40)[0]
            > score_standalone(ble, row, idle_boost=0)[0])


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
