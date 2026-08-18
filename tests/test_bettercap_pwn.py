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
import csv
import sys
import json
from pathlib import Path
from types import SimpleNamespace
from datetime import datetime, timedelta, timezone

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


def test_bettercap_writes_a_separatorless_mac_and_that_still_parses():
    """The filename the 2026-08-17 walk actually produced. The separated-only pattern matched
    nothing in it, so every capture was indexed with bssid="" — unique_bssids stayed 0 (the trophy
    counter never moved) and plan_session's `owned` set held one empty string, which excludes
    nothing. Normalised to the same colon form as the separated shapes."""
    assert pwn.parse_capture_name("Espanola_e81da862c75c.pcap") == ("E8:1D:A8:62:C7:5C", "Espanola")
    assert pwn.parse_capture_name("e81da862c75c.pcap") == ("E8:1D:A8:62:C7:5C", "")


def test_a_longer_hex_run_is_not_mistaken_for_a_bare_mac():
    """Same lookaround job as the separated form: 12 hex characters are only a MAC when they are a
    whole token, or "deadbeefcafe01" donates its first twelve to a BSSID."""
    assert pwn.parse_capture_name("deadbeefcafe01.pcap") == ("", "deadbeefcafe01")


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


# --- D2/D4: the index feeds coins and the report ---------------------------

def test_index_sets_the_coin_counter_to_unique_aps(tmp_path):
    """Coins count networks owned, not files on disk: two captures of one AP is one network."""
    from datetime import datetime as dt
    shared = cfg()
    shared.handshakes_dir = str(tmp_path)
    shared.handshakenbr = 0
    _capture(tmp_path, "Home-aa-bb-cc-dd-ee-01.pcap")
    _capture(tmp_path, "Home-aa-bb-cc-dd-ee-01-again.pcap")
    _capture(tmp_path, "Cafe-aa-bb-cc-dd-ee-02.pcap")
    pwn.update_index(shared, now=dt(2026, 8, 8))
    assert shared.handshakenbr == 2


def test_telegram_reads_the_index_without_shipping_the_pcaps(tmp_path):
    """The catalogue belongs in a report; the capture files do not. Sending PCAPs through a
    third-party bot is a decision nobody made — they leave over SSH or the zip endpoint."""
    import telegram_client
    from datetime import datetime as dt
    shared = cfg()
    shared.handshakes_dir = str(tmp_path)
    _capture(tmp_path, "Home-aa-bb-cc-dd-ee-01.pcap")
    pwn.update_index(shared, now=dt(2026, 8, 8))

    rows = telegram_client._read_json_values(os.path.join(str(tmp_path), "index.json"), "captures")
    assert len(rows) == 1 and rows[0]["bssid"] == "AA:BB:CC:DD:EE:01"
    assert "pcap" not in json.dumps(rows).lower() or rows[0]["path"].endswith(".pcap")


def test_a_missing_or_corrupt_index_never_breaks_a_report(tmp_path):
    """A report must not fail to send because a catalogue file was half-written."""
    import telegram_client
    assert telegram_client._read_json_values(str(tmp_path / "nope.json"), "captures") == []
    bad = tmp_path / "bad.json"
    bad.write_text("{truncated")
    assert telegram_client._read_json_values(str(bad), "captures") == []


# --- E1: target scoring ----------------------------------------------------

def _ap(bssid, essid="Net", channel="6", privacy="WPA2", power="-45"):
    return {"BSSID": bssid, "ESSID": essid, "Channel": channel,
            "Privacy": privacy, "Power": power}


def test_an_ap_with_clients_outranks_a_stronger_one_without():
    """The dominant signal, and the reason this scorer exists: a WPA handshake happens when a
    client (re)associates. A loud AP nobody is talking to will never produce one passively, so
    signal strength alone would aim the radio at the wrong network."""
    aps = [_ap("AA:BB:CC:00:00:01", "Loud", power="-30"),
           _ap("AA:BB:CC:00:00:02", "Busy", power="-70")]
    clients = [{"BSSID": "AA:BB:CC:00:00:02", "Station": "11:22:33:44:55:66"}]
    ranked = pwn.score_targets(aps, clients)
    assert ranked[0]["essid"] == "Busy"
    assert "has clients" in ranked[0]["reason"]


def test_networks_we_already_hold_are_excluded():
    """A second handshake for a network already captured adds nothing — and would keep the radio
    parked on a channel with no unclaimed value left."""
    aps = [_ap("AA:BB:CC:00:00:01"), _ap("AA:BB:CC:00:00:02")]
    ranked = pwn.score_targets(aps, [], owned_bssids={"AA:BB:CC:00:00:01"})
    assert [t["bssid"] for t in ranked] == ["AA:BB:CC:00:00:02"]


def test_open_networks_are_excluded_because_there_is_no_handshake_to_catch():
    aps = [_ap("AA:BB:CC:00:00:01", "Cafe-Free", privacy="OPN"),
           _ap("AA:BB:CC:00:00:02", "Home", privacy="WPA2")]
    ranked = pwn.score_targets(aps, [])
    assert [t["essid"] for t in ranked] == ["Home"]


def test_weak_aps_are_excluded_by_min_rssi():
    aps = [_ap("AA:BB:CC:00:00:01", "Far", power="-88"),
           _ap("AA:BB:CC:00:00:02", "Near", power="-40")]
    assert [t["essid"] for t in pwn.score_targets(aps, [], min_rssi=-80)] == ["Near"]
    assert len(pwn.score_targets(aps, [], min_rssi=-100)) == 2


def test_unreadable_fields_do_not_drop_a_target():
    """airodump writes blanks and odd spacing. A target should be judged on what parsed, not
    discarded because one column was unreadable."""
    aps = [_ap("AA:BB:CC:00:00:01", "Odd", channel="", power="")]
    ranked = pwn.score_targets(aps, [])
    assert len(ranked) == 1 and ranked[0]["channel"] == 0


def test_pick_channel_sums_value_rather_than_taking_the_single_best():
    """The radio hears one channel at a time for the whole session: three mediocre targets on
    channel 6 are worth more than one good one on channel 11."""
    aps = [_ap("AA:BB:CC:00:00:01", channel="11", power="-35"),
           _ap("AA:BB:CC:00:00:02", channel="6", power="-60"),
           _ap("AA:BB:CC:00:00:03", channel="6", power="-60"),
           _ap("AA:BB:CC:00:00:04", channel="6", power="-60")]
    channel, why = pwn.pick_channel(pwn.score_targets(aps, []))
    assert channel == 6 and "3 target(s)" in why


def test_no_targets_means_keep_hopping():
    """Being blind everywhere beats being parked on a channel with nothing on it."""
    channel, why = pwn.pick_channel([])
    assert channel == 0 and "hopping" in why


# --- E1a: the survey is read back through the spreadsheet guard ------------

def _survey(tmp_path, rows):
    """Write wifi_aps.csv exactly the way wifi_scan does — through sanitize_row — so the read side
    is tested against the bytes that are really on disk, not against a hand-built ideal."""
    from csv_safe import sanitize_row
    cols = ["BSSID", "ESSID", "Channel", "Privacy", "Cipher", "Auth", "Power", "Beacons",
            "FirstSeen", "LastSeen"]
    path = tmp_path / "wifi_aps.csv"
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for row in rows:
            w.writerow(sanitize_row([row.get(c, "") for c in cols]))
    return str(path)


def test_signal_survives_the_round_trip_through_the_csv_guard(tmp_path):
    """The 2026-08-17 outage end to end, and the test that was missing: dBm is always negative, so
    sanitize_row always guards it, and reading it back without unsanitize gives "'-52" — which
    int() rejects. Both places that parse Power then hit their except branch, so min_rssi excluded
    nothing and every AP scored 0 for proximity. Asserted through _read_csv_rows rather than on
    the helper, because the helper was never the part that was wrong."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    path = _survey(tmp_path, [
        dict(_ap("AA:BB:CC:00:00:02", "Nearby", "6", power="-52"), LastSeen=now),
        dict(_ap("AA:BB:CC:00:00:03", "Faint", "6", power="-88"), LastSeen=now),
    ])
    assert open(path).read().splitlines()[1].split(",")[6] == "'-52"   # guard still on disk

    ranked = pwn.score_targets(pwn._read_csv_rows(path), [])
    assert [t["essid"] for t in ranked] == ["Nearby"], "min_rssi excluded nothing"
    assert "-52dBm" in ranked[0]["reason"], "proximity contributed nothing to the score"
    assert ranked[0]["score"] > pwn.WPA_BONUS, "score is WPA alone, with no signal component"


# --- E1b: the survey is a permanent record, the radio is not ---------------

def _aged(bssid, minutes_ago, essid="Net", channel="6", power="-45"):
    """An AP row carrying a LastSeen, in airodump's own format: local wall-clock, space separator
    and no timezone. That naive-local shape is the one _age_seconds has to get right."""
    seen = datetime.now() - timedelta(minutes=minutes_ago)
    row = _ap(bssid, essid, channel, power=power)
    row["LastSeen"] = seen.strftime("%Y-%m-%d %H:%M:%S")
    return row


def test_an_ap_not_heard_recently_is_not_a_target():
    """The 2026-08-17 walk in one assertion. wifi_aps.csv never forgets, so after ten hours it held
    370 APs from streets already left behind; pick_channel summed all of them and pinned the radio
    to one 5 GHz channel for 9h53m. A radio can only hear what is in front of it now."""
    aps = [_aged("AA:BB:CC:00:00:01", minutes_ago=180, essid="Ghost"),
           _aged("AA:BB:CC:00:00:02", minutes_ago=1, essid="Here")]
    assert [t["essid"] for t in pwn.score_targets(aps, [])] == ["Here"]


def test_a_stale_client_does_not_grant_the_clients_bonus():
    """'has clients' is worth 45 of a 55-point target, so a stale client table alone is enough to
    aim the radio wrong. An association seen three hours ago will not re-associate now."""
    aps = [_aged("AA:BB:CC:00:00:01", minutes_ago=1)]
    old = {"BSSID": "AA:BB:CC:00:00:01", "Station": "11:22:33:44:55:66",
           "LastSeen": (datetime.now() - timedelta(hours=3)).strftime("%Y-%m-%d %H:%M:%S")}
    assert "has clients" not in pwn.score_targets(aps, [old])[0]["reason"]
    fresh = dict(old, LastSeen=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    assert "has clients" in pwn.score_targets(aps, [fresh])[0]["reason"]


def test_a_naive_timestamp_is_read_as_local_not_utc():
    """airodump writes local time with no offset. Treating that as UTC would age every fresh row by
    the local offset — two hours here in summer — and silently empty the target list."""
    stamp = (datetime.now() - timedelta(seconds=30)).strftime("%Y-%m-%d %H:%M:%S")
    assert 0 <= pwn._age_seconds(stamp) < 120


def test_an_aware_utc_timestamp_is_read_correctly_too():
    """The other format in the file: wifi_scan._merge falls back to an aware UTC isoformat when
    airodump left LastSeen blank, so both shapes coexist in one column."""
    stamp = (datetime.now(timezone.utc) - timedelta(seconds=30)).isoformat()
    assert 0 <= pwn._age_seconds(stamp) < 120


def test_an_unreadable_timestamp_keeps_the_target():
    """Same tolerance Power and Channel already get: airodump writes blanks and odd spacing, and a
    target should be judged on what parsed rather than dropped for one bad column."""
    assert pwn._age_seconds("") is None
    aps = [_ap("AA:BB:CC:00:00:01", "NoStamp")]          # no LastSeen key at all
    assert len(pwn.score_targets(aps, [])) == 1


def test_max_age_zero_disables_the_cut():
    """The escape hatch: a stationary Bjorn watching one street wants the whole table."""
    aps = [_aged("AA:BB:CC:00:00:01", minutes_ago=600)]
    assert len(pwn.score_targets(aps, [], max_age=0)) == 1


def test_build_cmd_only_locks_a_channel_when_one_was_chosen():
    """`wifi.recon.channel` is the one bettercap setting name here not confirmed against a running
    daemon, so it is emitted only when it buys something — a wrong name then degrades to hopping
    rather than breaking every hunt."""
    assert "wifi.recon.channel" not in pwn.build_cmd("wlan1", "/out", channel=0)[-1]
    assert "set wifi.recon.channel 6" in pwn.build_cmd("wlan1", "/out", channel=6)[-1]


def _shipped_defaults():
    """The literal defaults in shared.get_default_config, read from source.

    `shared` is a stub in this suite (tests/_stubs.py), so the class cannot be imported to ask it.
    Parsing the dict literal is the same trick the outcome-contract guards use, and it asserts what
    actually ships rather than what a fixture says.
    """
    import ast
    tree = ast.parse((Path(__file__).resolve().parent.parent / "shared.py")
                     .read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "get_default_config":
            for sub in ast.walk(node):
                if isinstance(sub, ast.Dict):
                    return {k.value: v.value for k, v in zip(sub.keys, sub.values)
                            if isinstance(k, ast.Constant) and isinstance(v, ast.Constant)}
    raise AssertionError("get_default_config dict literal not found in shared.py")


def test_hunter_is_on_by_default_and_the_master_switch_is_not():
    """The walk case: no uplink, so the offline cycle is the hunter's whole purpose. It ships on
    (collect-by-default, like BLE and the Wi-Fi survey) — it is passive and self-refuses on a
    single-radio device, which is what makes it safe to default on.

    `bettercap_enabled` must stay OFF, and not only because managed-mode recon is a bigger
    posture: can_start() treats the two as mutually exclusive, so switching the master switch on
    *disables* the hunter. Defaulting both to True would have shipped a hunter that never runs."""
    defaults = _shipped_defaults()
    assert defaults["bettercap_pwn_enabled"] is True
    assert defaults["bettercap_enabled"] is False, "the master switch blocks the hunter"

    ok, reason, _ = pwn.can_start(
        SimpleNamespace(bettercap_pwn_enabled=defaults["bettercap_pwn_enabled"],
                        bettercap_enabled=defaults["bettercap_enabled"],
                        bettercap_pwn_iface=defaults["bettercap_pwn_iface"]),
        wireless=["wlan0", "wlan1"], uplink="", holder="", binary=True)
    assert ok, f"the shipped defaults must let the hunter start offline: {reason}"
