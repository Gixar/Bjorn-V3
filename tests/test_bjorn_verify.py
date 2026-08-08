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


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
