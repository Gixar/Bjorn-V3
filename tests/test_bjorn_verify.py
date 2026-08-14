"""Tests for the pure logic in scripts/bjorn_verify.py.

This is the reason the script was ported from bash. Every bug the shell version had was a *silent
wrong answer* from string handling — a verification script that lies is worse than no script at
all (see the `WiFiScan: success=4` incident in BACKLOG.md). The two historical bugs are pinned
here as regression tests: count_matching on a no-match file, and benchmark_ports on CRLF rows.

No Pi, no network, no subprocesses: only the pure helpers are exercised.
"""
import os
import sys
import csv
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import bjorn_verify as bv  # noqa: E402


def _write(tmp, name, text):
    path = os.path.join(tmp, name)
    with open(path, "w", newline="") as f:
        f.write(text)
    return path


# --- the two bugs that motivated the port ----------------------------------

def test_count_matching_on_a_file_with_no_matches():
    """`grep -c` prints 0 AND exits 1, so `$(grep -c x f || echo 0)` returned "0\\n0" and every
    numeric test on it silently failed. This must be a plain integer 0."""
    with tempfile.TemporaryDirectory() as tmp:
        path = _write(tmp, "quiet.log", "all fine\nnothing wrong\n")
        assert bv.count_matching(path, "ERROR") == 0
        assert bv.count_matching(os.path.join(tmp, "absent.log"), "ERROR") == 0
        assert bv.count_matching(path, "fine") == 1


def test_benchmark_ports_survives_crlf_rows():
    """csv.writer terminates rows with \\r\\n. In the shell version that CR rode into the last
    field and bash's -eq choked, so a passing comparison was reported as 'no comparable row'."""
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "bench.csv")
        with open(path, "w", newline="") as f:
            w = csv.writer(f)  # emits \r\n, exactly like the real benchmark writer
            w.writerow(["Timestamp", "Hosts", "Ports", "nmap_s", "rust_s", "speedup",
                        "nmap_ports", "rust_ports"])
            w.writerow(["2026-08-08", "7", "41", "54.25", "2.01", "26.94", "3", "3"])
        assert bv.benchmark_ports(path) == (3, 3)


def test_benchmark_ports_missing_short_and_unparsable():
    with tempfile.TemporaryDirectory() as tmp:
        assert bv.benchmark_ports(os.path.join(tmp, "nope.csv")) == (None, None)
        assert bv.benchmark_ports(_write(tmp, "hdr.csv", "a,b\n")) == (None, None)
        assert bv.benchmark_ports(_write(tmp, "short.csv", "h\n1,2,3\n")) == (None, None)
        assert bv.benchmark_ports(
            _write(tmp, "bad.csv", "h1,h2,h3,h4,h5,h6,h7,h8\n1,2,3,4,5,6,x,y\n")) == (None, None)


def test_dropped_ports_are_detectable():
    """The verdict this feeds: rustscan finding fewer ports than nmap means the batch size is too
    aggressive. It must be a comparison of numbers, not of strings."""
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "b.csv")
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["t", "h", "p", "n", "r", "s", "np", "rp"])
            w.writerow(["x", "7", "41", "50", "2", "25", "10", "9"])
        nmap_n, rust_n = bv.benchmark_ports(path)
        assert (nmap_n, rust_n) == (10, 9) and rust_n < nmap_n


# --- config truthiness -----------------------------------------------------

def test_truthy_accepts_every_shape_a_config_boolean_arrives_in():
    for value in (True, "true", "True", "1", "yes", " TRUE "):
        assert bv.truthy(value), value
    for value in (False, "false", "False", "0", "", "no", "<absent>", None):
        assert not bv.truthy(value), value


# --- parsers ---------------------------------------------------------------

def test_parse_default_route():
    out = ("default via 192.168.1.1 dev wlan0 proto dhcp metric 600\n"
           "192.168.1.0/24 dev wlan0 proto kernel scope link\n")
    assert bv.parse_default_route(out) == "wlan0"
    assert bv.parse_default_route("192.168.1.0/24 dev wlan0\n") == ""
    assert bv.parse_default_route("") == ""


def test_parse_unit_password():
    unit = ('ExecStart=/usr/bin/bettercap -eval "set api.rest.address 127.0.0.1; '
            'set api.rest.username bjorn; set api.rest.password i2bCRrJNySMvOr3nrNkF2Kz4; '
            'api.rest on"\n')
    assert bv.parse_unit_password(unit) == "i2bCRrJNySMvOr3nrNkF2Kz4"
    assert bv.parse_unit_password("ExecStart=/usr/bin/bettercap\n") == ""


def test_engine_from_log_reads_the_last_line():
    """The toggle being on is not proof rustscan was found — it resolves off-PATH cargo installs
    and falls back to nmap silently. The log line is the only real answer, and the LAST one wins."""
    log = ("Port discovery engine: nmap (8 hosts, 41 ports)\n"
           "some other line\n"
           "Port discovery engine: rustscan (8 hosts, 41 ports)\n")
    assert bv.engine_from_log(log) == "rustscan"
    assert bv.engine_from_log("Port discovery engine: nmap (1 host)\n") == "nmap"
    assert bv.engine_from_log("nothing relevant\n") == ""


def test_pick_monitor_iface_falls_back_like_the_code_it_verifies():
    """On the 2026-08-08 Pi run this skipped the capture AND the Stage A radio test because
    wifi_scan_iface was blank — while Bjorn itself would have used wlan1 quite happily. A verifier
    that is more pessimistic than the code under-reports, which is its own kind of wrong answer."""
    both = {"interfaces": [{"name": "wlan1", "uplink": False}, {"name": "wlan0", "uplink": True}],
            "configured": ""}
    iface, why = bv.pick_monitor_iface(both)
    assert iface == "wlan1" and "unconfigured" in why

    configured = dict(both, configured="wlan1")
    assert bv.pick_monitor_iface(configured) == ("wlan1", "configured")

    # a configured radio that is the uplink, or absent, must NOT silently fall back
    assert bv.pick_monitor_iface(dict(both, configured="wlan0"))[0] == ""
    assert bv.pick_monitor_iface(dict(both, configured="wlan7"))[0] == ""
    # only the uplink present -> nothing usable
    assert bv.pick_monitor_iface({"interfaces": [{"name": "wlan0", "uplink": True}],
                                  "configured": ""})[0] == ""
    assert bv.pick_monitor_iface(None)[0] == ""


def test_an_http_error_body_is_the_answer_not_a_failure():
    """Bjorn's handlers signal a refusal with _err() = HTTP 500 + {"status": "error"}. urllib
    raises on that; curl (the shell version) printed the body regardless. Swallowing it made a
    CORRECT uplink refusal report as 'ACCEPTED wlan0 - check_usable is broken' on the 2026-08-08
    Pi run — the verifier screaming that a working safety guard had failed."""
    import io
    import json as _json
    saved = bv.urllib.request.urlopen

    def refusing(req, timeout=None):
        raise bv.urllib.error.HTTPError(
            req.full_url, 500, "err", {},
            io.BytesIO(_json.dumps({"status": "error", "message": "carries the default route"}).encode()))

    bv.urllib.request.urlopen = refusing
    try:
        answer = bv.Api("127.0.0.1:8000").post("/wifi_monitor_test", {"iface": "wlan0"})
    finally:
        bv.urllib.request.urlopen = saved
    assert answer is not None, "an error body must not be swallowed"
    assert answer.get("status") == "error"


def test_an_unreachable_endpoint_is_none_not_an_empty_answer():
    """None and {} must stay distinguishable: 'could not ask the guard' is a WARN, 'the guard said
    yes' is a catastrophic FAIL, and conflating them invents the catastrophe."""
    saved = bv.urllib.request.urlopen

    def refused(req, timeout=None):
        raise bv.urllib.error.URLError("Connection refused")

    bv.urllib.request.urlopen = refused
    try:
        assert bv.Api("127.0.0.1:8000").post("/wifi_monitor_test", {"iface": "wlan0"}) is None
    finally:
        bv.urllib.request.urlopen = saved


def test_file_group_count_tolerates_both_shapes_and_errors():
    assert bv.file_group_count({"group": "wifi", "files": [{"key": "a"}, {"key": "b"}]}) == 2
    assert bv.file_group_count([{"key": "a"}]) == 1
    assert bv.file_group_count({"status": "error", "message": "unknown group"}) == 0
    assert bv.file_group_count(None) == 0


def test_csv_rows_excludes_the_header():
    with tempfile.TemporaryDirectory() as tmp:
        assert bv.csv_rows(_write(tmp, "a.csv", "h1,h2\n1,2\n3,4\n")) == 2
        assert bv.csv_rows(_write(tmp, "hdr.csv", "h1,h2\n")) == 0
        assert bv.csv_rows(os.path.join(tmp, "gone.csv")) == 0


def test_last_matching_and_file_age():
    with tempfile.TemporaryDirectory() as tmp:
        path = _write(tmp, "o.log", "Planner chose: A (score=1)\nnoise\nPlanner chose: B (score=9)\n")
        assert bv.last_matching(path, "Planner chose").endswith("B (score=9)")
        assert bv.last_matching(path, "nope") == ""
        assert bv.file_age(path) is not None and bv.file_age(path) < 60
        assert bv.file_age(os.path.join(tmp, "gone")) is None
        assert bv.age_str(os.path.join(tmp, "gone")) == "missing"


# --- repo resolution -------------------------------------------------------

def test_resolve_repo_prefers_the_override_and_verifies_candidates():
    """A wrong repo makes every CSV read a path that does not exist, which reads as 'the feature is
    broken' rather than 'you ran it from the wrong place'."""
    assert bv.resolve_repo("/explicit/path") == "/explicit/path"
    # nothing anywhere -> "" rather than a confidently wrong guess
    assert bv.resolve_repo("", "", probe=lambda _p: False) == ""


# --- summary ---------------------------------------------------------------

def test_summarize_counts_every_verdict_including_absent_ones():
    counts = bv.summarize([(bv.PASS, "a", ""), (bv.PASS, "b", ""), (bv.FAIL, "c", "")])
    assert counts == {bv.PASS: 2, bv.FAIL: 1, bv.WARN: 0, bv.SKIP: 0}
    assert bv.summarize([]) == {bv.PASS: 0, bv.FAIL: 0, bv.WARN: 0, bv.SKIP: 0}


# --- source-read checks for the connector bug classes (section 9) ----------

_FIXED_BRUTEFORCE = '''
def run_bruteforce(self, ip, port, row=None):
    if row is not None:
        mac_address = row.get('MAC Address', '')
        hostname = row.get('Hostnames', '')
    else:
        mac_address = 'x'
        hostname = 'y'
    for user, password in candidates:
        self.queue.put((ip, user, password, mac_address, hostname, port))
'''

_BUGGY_BRUTEFORCE = '''
def run_bruteforce(self, ip, port, row=None):
    for user, password in candidates:
        self.queue.put((ip, user, password, mac_address, hostname, port))
    with Progress() as progress:
        if row is not None:
            mac_address = row.get('MAC Address', '')
            hostname = row.get('Hostnames', '')
        else:
            mac_address = 'x'
            hostname = 'y'
'''


def test_used_before_assigned_catches_the_rdp_ordering_bug():
    """The RDP fix, made checkable on a device: mac_address must be assigned before the queue.put()
    that reads it, or run_bruteforce raises UnboundLocalError on every real attack. True = bug."""
    assert bv.used_before_assigned(_BUGGY_BRUTEFORCE, "run_bruteforce", "mac_address") is True
    assert bv.used_before_assigned(_FIXED_BRUTEFORCE, "run_bruteforce", "mac_address") is False
    # never read (the SQL-connector shape) is safe — not a bug, and not unknown
    assert bv.used_before_assigned(
        "def run_bruteforce(self):\n    self.queue.put((ip, user, password, port))\n",
        "run_bruteforce", "mac_address") is False
    # unknown must never read as a false safe: missing function / unparsable -> None
    assert bv.used_before_assigned("def other():\n    pass\n", "run_bruteforce", "mac_address") is None
    assert bv.used_before_assigned("def run_bruteforce(:\n    pass\n", "run_bruteforce",
                                   "mac_address") is None


_GUARDED_WORKER = '''
def worker(self):
    while True:
        item = self.queue.get()
        try:
            self.connect(item)
        finally:
            self.queue.task_done()
'''

_UNGUARDED_WORKER = '''
def worker(self):
    while True:
        item = self.queue.get()
        self.connect(item)
        self.queue.task_done()
'''


def test_call_in_finally_confirms_the_connector_hang_guard():
    """task_done() must sit in a finally so a raising connect can't hang queue.join() forever."""
    assert bv.call_in_finally(_GUARDED_WORKER, "worker", "task_done") is True
    assert bv.call_in_finally(_UNGUARDED_WORKER, "worker", "task_done") is False
    assert bv.call_in_finally("def nope():\n    pass\n", "worker", "task_done") is None
    assert bv.call_in_finally("def worker(:\n    pass\n", "worker", "task_done") is None


def test_the_shipped_connectors_pass_both_source_checks():
    """Not a fixture — the real files. This is the regression that would have caught the RDP bug in
    CI: parse each deployed connector and assert no used-before-assigned + the hang guard holds. All
    six are safe (SQL never reads mac_address; the other five assign it before the queue.put).

    #12: a connector that delegates to base_connector.BaseConnector no longer carries its own
    run_bruteforce/worker — the guarantee lives in the base, checked once below. So for a delegating
    file we verify the base; only a connector still carrying its own scaffolding is parsed directly."""
    repo = Path(__file__).resolve().parent.parent
    actions = repo / "actions"

    base = (repo / "base_connector.py").read_text(encoding="utf-8")
    assert bv.used_before_assigned(base, "run_bruteforce", "mac_address") is False, \
        "base_connector: mac_address read before assigned (the RDP bug class)"
    assert bv.call_in_finally(base, "worker", "task_done") is True, "base_connector: unguarded worker"

    for fn in ("ssh_connector.py", "ftp_connector.py", "smb_connector.py",
               "rdp_connector.py", "telnet_connector.py", "sql_connector.py"):
        src = (actions / fn).read_text(encoding="utf-8")
        if "from base_connector import" in src:
            continue  # delegates — guarantee verified on the base above
        assert bv.used_before_assigned(src, "run_bruteforce", "mac_address") is False, \
            f"{fn}: mac_address read before assigned (the RDP bug class)"
        assert bv.call_in_finally(src, "worker", "task_done") is True, f"{fn}: unguarded worker"


def test_execute_body_is_empty_for_a_module_that_has_no_execute():
    """The delegation checks split on 'def execute(' and look for a guarantee inside it. Falling
    back to the whole file for an adapter that has none would find the line somewhere else and
    report a pass for a module that no longer carries the guarantee at all — the failure mode the
    steal-module conversion could have introduced."""
    assert bv.execute_body("class A:\n    def execute(self):\n        self.x = False\n")
    assert bv.execute_body("class A:\n    pass\n") == ""
    assert "self.x = False" not in bv.execute_body("self.x = False\nclass A:\n    pass\n")


def test_previous_verdicts_reads_back_a_saved_summary(tmp_path):
    """The change delta is only worth having if it cannot invent one. Parses the Summary block
    this script writes, and returns nothing at all when there is no earlier report."""
    (tmp_path / "verify_20260101_000000.txt").write_text(
        "Bjorn verification\n"
        "=== 9. Offensive core ===\n"
        "  [PASS] noise that is not in the summary\n"
        "=== Summary ===\n"
        "  PASS  guard refuses the uplink - refusing to use wlan0\n"
        "  FAIL  airodump capture\n"
        "  WARN  could not ask\n", encoding="utf-8")
    found, name = bv.previous_verdicts(str(tmp_path), exclude=None)
    assert found == {"guard refuses the uplink": bv.PASS,
                     "airodump capture": bv.FAIL,
                     "could not ask": bv.WARN}
    assert name == "verify_20260101_000000.txt"
    assert "noise that is not in the summary" not in found

    # The report being written right now must not be its own baseline.
    only = tmp_path / "verify_20260101_000000.txt"
    assert bv.previous_verdicts(str(tmp_path), exclude=str(only)) == ({}, "")
    assert bv.previous_verdicts(str(tmp_path / "nope"), exclude=None) == ({}, "")


if __name__ == "__main__":
    # Fixture-taking tests can't run here — same guard as test_connectors.py. Without it, adding
    # the first tmp_path test turns `python tests/test_bjorn_verify.py` into a TypeError.
    import inspect
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn) and not inspect.signature(fn).parameters:
            fn()
    print("ok (fixture-free subset; run pytest for all)")
