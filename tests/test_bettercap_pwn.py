"""Tests for the Handshake Hunter: admission guard (C1) and radio/process lifecycle (C2).

Two properties carry the whole feature:

1. **It refuses to run on a single radio.** offline_mode.py warns that nmcli cannot associate an
   interface still in monitor mode and that it fails *quietly*, so a hunter holding the only usable
   radio does not merely fail to reconnect — Bjorn stays offline forever and never delivers the
   handshakes it just captured.
2. **It always gives the radio back.** Including when bettercap will not die, and when it never
   started. `stop()` reports on the radio, not the process, because a radio left in monitor mode is
   what takes Bjorn off the air.

No radio, no daemon and no Pi: the guard is pure logic over injected state, and the lifecycle runs
against a fake process and a faked `iw`.
"""
import os
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _stubs  # noqa: E402
_stubs.install()

import bettercap_pwn as pwn  # noqa: E402

TWO_RADIOS = ["wlan1", "wlan0"]


def cfg(**over):
    base = dict(bettercap_pwn_enabled=True, bettercap_enabled=False, bettercap_pwn_iface="")
    base.update(over)
    return SimpleNamespace(**base)


def call(shared=None, wireless=TWO_RADIOS, uplink="wlan0", holder="", binary=True):
    return pwn.can_start(shared or cfg(), wireless=wireless, uplink=uplink,
                         holder=holder, binary=binary)


# --- the refusal this module exists for -----------------------------------

def test_refuses_to_start_with_a_single_radio():
    """With one radio there is no arrangement where hunting and staying reachable both work: the
    hunter would hold the only path back online and Bjorn could never deliver its loot."""
    ok, reason, iface = call(wireless=["wlan0"], uplink="wlan0")
    assert not ok and iface == ""
    assert "second one" in reason and "back online" in reason

    # ...and offline, where there is no uplink at all, the answer must be the same. This is the
    # case a naive "is it the uplink?" check would wave through.
    ok, reason, _ = call(wireless=["wlan0"], uplink="")
    assert not ok and "only 1 wireless radio" in reason


def test_starts_with_a_dongle_alongside_the_uplink():
    ok, reason, iface = call()
    assert ok and iface == "wlan1" and "ready" in reason


def test_offline_with_two_radios_still_starts():
    """No default route means nothing is the uplink, so both radios are eligible — the second one
    remains free to reconnect, which is the whole reason MIN_RADIOS is 2."""
    ok, _reason, iface = call(uplink="")
    assert ok and iface in TWO_RADIOS


# --- the other refusals ----------------------------------------------------

def test_disabled_is_a_refusal_not_an_error():
    ok, reason, _ = call(cfg(bettercap_pwn_enabled=False))
    assert not ok and "off" in reason


def test_managed_mode_bettercap_is_mutually_exclusive():
    """One bettercap profile at a time: managed mode lives on the joined network, monitor mode
    takes a radio out of that world, and both running means each undoes the other's state."""
    ok, reason, _ = call(cfg(bettercap_enabled=True))
    assert not ok and "mutually exclusive" in reason


def test_missing_binary_says_so_plainly():
    ok, reason, _ = call(binary=False)
    assert not ok and "not installed" in reason


def test_a_configured_radio_that_is_the_uplink_is_refused():
    """Never fall back silently when the operator named a radio: naming the uplink is a mistake
    worth reporting, not routing around."""
    ok, reason, iface = call(cfg(bettercap_pwn_iface="wlan0"))
    assert not ok and iface == ""
    assert "wlan0" in reason


def test_a_configured_radio_that_is_absent_is_refused():
    ok, reason, _ = call(cfg(bettercap_pwn_iface="wlan7"))
    assert not ok and "wlan7" in reason


def test_a_busy_radio_is_come_back_later_not_a_fault():
    """Same rule as WiFiScan: a held radio is a normal state. The hunter is the long-lived
    consumer, so it has to tolerate finding the radio taken."""
    ok, reason, _ = call(holder="scan")
    assert not ok and "held by scan" in reason


def test_describe_never_raises():
    """A status probe that can fail is useless — it would take the web panel down with it."""
    class Exploding:
        def __getattr__(self, _name):
            raise RuntimeError("boom")

    assert isinstance(pwn.describe(Exploding()), str)
    # Not asserting a particular sentence: describe() reads the live system for the arguments it
    # is not given, so the answer legitimately differs between a Pi and a dev box.
    assert isinstance(pwn.describe(cfg()), str) and pwn.describe(cfg())


# --- C2: radio + process lifecycle -----------------------------------------

class _FakeProc:
    """A bettercap that behaves. `stubborn` ignores terminate() so kill() has to happen."""

    def __init__(self, stubborn=False):
        self.stubborn = stubborn
        self.alive = True
        self.terminated = self.killed = False

    def poll(self):
        return None if self.alive else 0

    def terminate(self):
        self.terminated = True
        if not self.stubborn:
            self.alive = False

    def kill(self):
        self.killed = True
        self.alive = False

    def wait(self, timeout=None):
        if self.alive:
            raise pwn.subprocess.TimeoutExpired("bettercap", timeout)
        return 0


def _hunter(tmp_path, monkeypatch, spawn, mode_box):
    """A Hunter over a faked radio. monkeypatch, not bare assignment: monitor_mode's globals are
    module-level, so an unrestored patch leaks into every later test file in the session."""
    import monitor_mode as mm
    monkeypatch.setattr(mm, "default_route_iface", lambda: "wlan0")
    monkeypatch.setattr(mm, "wireless_ifaces", lambda: TWO_RADIOS)
    monkeypatch.setattr(mm.shutil, "which", lambda name: "/usr/sbin/" + name)
    monkeypatch.setattr(mm, "_run", lambda args, **kw: (
        (0, f"\ttype {mode_box['mode']}\n")
        if args[:2] == ["iw", "dev"] and args[-1] == "info" else (0, "")))
    monkeypatch.setattr(pwn.shutil, "which", lambda _n: "/usr/bin/bettercap")
    shared = cfg()
    shared.handshakes_dir = str(tmp_path)
    return pwn.Hunter(shared, spawn=spawn), mm


def test_start_then_stop_returns_the_radio(tmp_path, monkeypatch):
    """The plan's acceptance for C2: after stop(), the interface is managed and nobody holds it."""
    proc = _FakeProc()
    hunter, mm = _hunter(tmp_path, monkeypatch, lambda cmd: proc, {"mode": "managed"})
    try:
        ok, detail = hunter.start()
        assert ok, detail
        assert hunter.is_running() and mm.holder() == "pwn"

        ok, detail = hunter.stop()
        assert ok, detail
        assert not hunter.is_running()
        assert mm.holder() == "", "the radio lease must be gone"
        assert proc.terminated
    finally:
        mm.release("wlan1", owner="pwn")


def test_stop_reports_failure_when_the_radio_does_not_come_back(tmp_path, monkeypatch):
    """ok reflects the RADIO, not the process. A bettercap that needed killing is untidy; a radio
    left in monitor mode is what takes Bjorn off the air."""
    hunter, mm = _hunter(tmp_path, monkeypatch, lambda cmd: _FakeProc(), {"mode": "monitor"})
    try:
        assert hunter.start()[0]
        ok, detail = hunter.stop()
        assert not ok and "STILL in monitor mode" in detail
        assert mm.holder() == "", "the lock must still be freed, or every future consumer deadlocks"
    finally:
        mm.release("wlan1", owner="pwn")


def test_a_stubborn_bettercap_gets_killed_and_the_radio_still_returns(tmp_path, monkeypatch):
    proc = _FakeProc(stubborn=True)
    hunter, mm = _hunter(tmp_path, monkeypatch, lambda cmd: proc, {"mode": "managed"})
    try:
        assert hunter.start()[0]
        ok, _ = hunter.stop(timeout=0)
        assert proc.terminated and proc.killed
        assert ok and mm.holder() == ""
    finally:
        mm.release("wlan1", owner="pwn")


def test_a_failed_spawn_never_strands_the_radio(tmp_path, monkeypatch):
    """The 2026-08-08 fault, pre-empted: if bettercap cannot exec, the radio must not be left in
    monitor mode by a start() that already took it."""
    def boom(_cmd):
        raise OSError("No such file or directory")

    hunter, mm = _hunter(tmp_path, monkeypatch, boom, {"mode": "managed"})
    ok, detail = hunter.start()
    assert not ok and "could not start" in detail
    assert mm.holder() == "" and not hunter.is_running()


def test_start_is_not_reentrant(tmp_path, monkeypatch):
    hunter, mm = _hunter(tmp_path, monkeypatch, lambda cmd: _FakeProc(), {"mode": "managed"})
    try:
        assert hunter.start()[0]
        ok, detail = hunter.start()
        assert not ok and "already hunting" in detail
    finally:
        hunter.stop()


def test_stop_on_a_hunter_that_never_started_is_harmless():
    hunter = pwn.Hunter(cfg(), spawn=lambda cmd: None)
    ok, detail = hunter.stop()
    assert ok and "was not running" in detail


def test_build_cmd_writes_per_ap_pcaps_into_the_dated_dir():
    cmd = pwn.build_cmd("wlan1", "/data/handshakes/raw/2026-08-08")
    assert cmd[:2] == ["bettercap", "-no-colors"]
    assert cmd[cmd.index("-iface") + 1] == "wlan1"
    eval_arg = cmd[cmd.index("-eval") + 1]
    assert "/data/handshakes/raw/2026-08-08" in eval_arg
    assert "aggregate false" in eval_arg, "per-AP files: one corrupt capture must cost one network"
    assert "wifi.recon on" in eval_arg


def test_handshake_dir_is_dated_and_created(tmp_path):
    from datetime import datetime as dt
    shared = cfg()
    shared.handshakes_dir = str(tmp_path)
    path = pwn.handshake_dir(shared, when=dt(2026, 8, 8))
    assert path.endswith(os.path.join("raw", "2026-08-08"))
    assert os.path.isdir(path)


# --- C3: the loot index ----------------------------------------------------

def test_parse_capture_name_handles_the_shapes_a_filename_might_take():
    """bettercap's per-AP naming is version-specific and unconfirmed, so the parser matches a MAC
    by SHAPE rather than a format. Normalised to upper-case colons, because that is what netkb and
    wifi_aps.csv use — a lower-case dashed MAC would silently join against nothing."""
    assert pwn.parse_capture_name("HomeNet-aa:bb:cc:dd:ee:01.pcap") == ("AA:BB:CC:DD:EE:01", "HomeNet")
    assert pwn.parse_capture_name("aa-bb-cc-dd-ee-02_Cafe.pcapng") == ("AA:BB:CC:DD:EE:02", "Cafe")
    assert pwn.parse_capture_name("/loot/raw/2026-08-08/AA:BB:CC:DD:EE:03.cap") == ("AA:BB:CC:DD:EE:03", "")
    # no MAC in the name: still indexable, keyed by what it does have
    assert pwn.parse_capture_name("mystery.pcap") == ("", "mystery")


def test_a_hex_looking_essid_does_not_swallow_the_mac():
    """Caught by a smoke run, not by the tests above: "Cafe-aa-bb-cc-dd-ee-02" matched starting
    inside the ESSID, because "fe-aa-bb-cc-dd-ee" is itself a valid MAC shape — giving BSSID
    FE:AA:BB:CC:DD:EE and ESSID "Ca-02". Every hex-ish name (cafe, beef, dead, face, ace) hits it,
    and the earlier test missed it because two WRONG bssids are still two DISTINCT bssids."""
    for essid in ("Cafe", "beef", "DeadBeef", "face"):
        bssid, parsed = pwn.parse_capture_name(f"{essid}-aa-bb-cc-dd-ee-02.pcap")
        assert bssid == "AA:BB:CC:DD:EE:02", f"{essid!r} corrupted the BSSID: {bssid}"
        assert parsed == essid


def _capture(tmp_path, relname, content=b"pcap"):
    """Filenames here use DASHED MACs: Windows rejects ':' in a path, while Linux allows it. The
    colon form is covered by parse_capture_name's pure test, which never touches the disk."""
    path = tmp_path / "raw" / "2026-08-08" / relname
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return str(path)


def test_index_is_stable_across_rescans(tmp_path):
    """The plan's acceptance for C3: re-running over the same files adds no duplicate entries, and
    first_seen keeps saying when the handshake actually arrived rather than when it was last
    counted."""
    from datetime import datetime as dt
    shared = cfg()
    shared.handshakes_dir = str(tmp_path)
    _capture(tmp_path, "HomeNet-aa-bb-cc-dd-ee-01.pcap")

    first = pwn.update_index(shared, now=dt(2026, 8, 8, 10, 0, 0))
    assert first["captures"] == 1 and first["unique_bssids"] == 1
    original = pwn.load_index(str(tmp_path))
    stamp = list(original.values())[0]["first_seen"]

    again = pwn.update_index(shared, now=dt(2026, 8, 9, 10, 0, 0))
    assert again["captures"] == 1, "a rescan must not duplicate"
    assert list(pwn.load_index(str(tmp_path)).values())[0]["first_seen"] == stamp


def test_index_counts_unique_aps_not_files(tmp_path):
    """Two captures of one AP is one network owned — which is what the coin award in D2 needs."""
    from datetime import datetime as dt
    shared = cfg()
    shared.handshakes_dir = str(tmp_path)
    _capture(tmp_path, "HomeNet-aa-bb-cc-dd-ee-01.pcap")
    _capture(tmp_path, "HomeNet-aa-bb-cc-dd-ee-01-2.pcap")
    _capture(tmp_path, "Cafe-aa-bb-cc-dd-ee-02.pcap")
    summary = pwn.update_index(shared, now=dt(2026, 8, 8))
    assert summary["captures"] == 3 and summary["unique_bssids"] == 2
    # Assert the actual values, not just the count: two WRONG bssids are also "2 unique", which is
    # how the hex-ESSID bug survived this test until a smoke run printed the index.
    assert {e["bssid"] for e in pwn.load_index(str(tmp_path)).values()} == {
        "AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"}


def test_index_ignores_non_captures_and_survives_an_empty_tree(tmp_path):
    from datetime import datetime as dt
    shared = cfg()
    shared.handshakes_dir = str(tmp_path)
    assert pwn.update_index(shared, now=dt(2026, 8, 8))["captures"] == 0
    _capture(tmp_path, "notes.txt")
    _capture(tmp_path, "real-aa-bb-cc-dd-ee-09.pcap")
    assert pwn.update_index(shared, now=dt(2026, 8, 8))["captures"] == 1


def test_a_corrupt_index_does_not_stop_reindexing(tmp_path):
    """An index.json truncated by a power cut must not make the loot invisible forever."""
    from datetime import datetime as dt
    shared = cfg()
    shared.handshakes_dir = str(tmp_path)
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "index.json").write_text("{not json")
    _capture(tmp_path, "x-aa-bb-cc-dd-ee-05.pcap")
    assert pwn.update_index(shared, now=dt(2026, 8, 8))["captures"] == 1


def test_index_is_not_rewritten_when_nothing_changed(tmp_path):
    """SD wear: this runs after every session, and rewriting an identical file is pure damage."""
    from datetime import datetime as dt
    shared = cfg()
    shared.handshakes_dir = str(tmp_path)
    _capture(tmp_path, "x-aa-bb-cc-dd-ee-06.pcap")
    pwn.update_index(shared, now=dt(2026, 8, 8))
    before = os.path.getmtime(pwn.index_path(str(tmp_path)))
    pwn.update_index(shared, now=dt(2026, 8, 8))
    assert os.path.getmtime(pwn.index_path(str(tmp_path))) == before


def test_stop_indexes_what_the_session_caught(tmp_path, monkeypatch):
    hunter, mm = _hunter(tmp_path, monkeypatch, lambda cmd: _FakeProc(), {"mode": "managed"})
    try:
        assert hunter.start()[0]
        _capture(tmp_path, "Caught-aa-bb-cc-dd-ee-07.pcap")
        ok, detail = hunter.stop()
        assert ok and "1 capture(s) on disk" in detail
    finally:
        mm.release("wlan1", owner="pwn")


if __name__ == "__main__":
    # The C2 lifecycle tests take pytest fixtures (tmp_path/monkeypatch), so this bare runner can
    # only drive the fixture-free ones. Use `pytest tests/test_bettercap_pwn.py` for the full set.
    import inspect
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn) and not inspect.signature(fn).parameters:
            fn()
    print("ok (fixture-free subset; run pytest for all)")
