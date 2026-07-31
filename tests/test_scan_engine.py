"""Tests for the RustScan/nmap engine toggle (backlog #12): greppable-output parser and
engine selection/fallback. Runs under pytest and as `python tests/test_scan_engine.py`.
Heavy imports (nmap/netifaces/getmac/rich/PIL) are stubbed via tests/_stubs.py.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _stubs  # noqa: E402
_stubs.install()

from actions.scanning import NetworkScanner  # noqa: E402

parse = NetworkScanner._parse_rustscan_greppable
build_cmd = NetworkScanner._rustscan_cmd


def test_cmd_omits_batch_flag_by_default():
    cmd = build_cmd(["10.0.0.5"], [22, 80], 0)
    assert "-b" not in cmd
    assert cmd[:5] == ["rustscan", "-a", "10.0.0.5", "-p", "22,80"]
    assert "-g" in cmd and "--no-config" in cmd


def test_cmd_adds_batch_flag_when_set():
    cmd = build_cmd(["10.0.0.5", "10.0.0.6"], [22], 300)
    assert cmd[-2:] == ["-b", "300"]
    assert cmd[2] == "10.0.0.5,10.0.0.6"  # -a takes comma-joined hosts


def test_parses_ports_per_host():
    out = "10.0.0.5 -> [22,80,443]\n10.0.0.6 -> [8080]\n"
    assert parse(out, ["10.0.0.5", "10.0.0.6"]) == {
        "10.0.0.5": [22, 80, 443],
        "10.0.0.6": [8080],
    }


def test_host_with_no_open_ports_present_and_empty():
    # every requested host appears, even if RustScan printed nothing for it
    assert parse("10.0.0.5 -> [22]\n", ["10.0.0.5", "10.0.0.9"]) == {
        "10.0.0.5": [22],
        "10.0.0.9": [],
    }


def test_ignores_noise_and_unrequested_hosts():
    out = "Starting rustscan...\n192.168.1.1 -> [53]\ngarbage line\n"
    # 192.168.1.1 wasn't in ip_list -> ignored; noise lines skipped
    assert parse(out, ["10.0.0.5"]) == {"10.0.0.5": []}


def test_selected_engine_falls_back_when_binary_missing(monkeypatch=None):
    scanner = NetworkScanner.__new__(NetworkScanner)  # skip __init__ (needs real SharedData)
    scanner.logger = _stubs._FakeLogger()
    scanner.shared_data = type("S", (), {"use_rustscan": True})()

    import actions.scanning as s
    orig = s.shutil.which
    s.shutil.which = lambda _name: None  # pretend rustscan isn't installed
    try:
        assert scanner.selected_engine() == "nmap"
        scanner.shared_data.use_rustscan = False
        assert scanner.selected_engine() == "nmap"
        scanner.shared_data.use_rustscan = True
        s.shutil.which = lambda _name: "/usr/bin/rustscan"
        assert scanner.selected_engine() == "rustscan"
    finally:
        s.shutil.which = orig


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
