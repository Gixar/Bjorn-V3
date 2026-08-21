"""Tests for Wi-Fi recon (backlog Wave 4): the airodump-ng CSV parser and the monitor-mode
guard. No radio, no subprocesses — the parsers are pure and the guard is driven with injected
fakes. Heavy imports stubbed via _stubs.
"""
import itertools
import os
import sys
import shutil
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _stubs  # noqa: E402
_stubs.install()

import monitor_mode  # noqa: E402
import actions.wifi_scan as wifi_scan_mod  # noqa: E402
from actions.wifi_scan import WiFiScan  # noqa: E402

parse = WiFiScan.parse_airodump_csv

# A real airodump-ng dump: AP table, blank line, then the client table.
SAMPLE = """BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key

AA:BB:CC:DD:EE:01, 2026-08-04 10:00:00, 2026-08-04 10:01:00,   6,  195, WPA2, CCMP, PSK, -45,      120,        3,   0.  0.  0.  0,   6, HomeNet,
AA:BB:CC:DD:EE:02, 2026-08-04 10:00:05, 2026-08-04 10:01:00,  11,  130, OPN,      ,    , -78,       40,        0,   0.  0.  0.  0,   9, GuestWiFi,

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs

11:22:33:44:55:66, 2026-08-04 10:00:10, 2026-08-04 10:01:00,  -60,       25, AA:BB:CC:DD:EE:01, HomeNet
77:88:99:AA:BB:CC, 2026-08-04 10:00:20, 2026-08-04 10:00:50,  -71,        4, (not associated) , Cafe, Airport
"""


def test_parses_both_tables():
    aps, clients = parse(SAMPLE)
    assert len(aps) == 2 and len(clients) == 2


def test_ap_fields_and_stripping():
    aps, _ = parse(SAMPLE)
    ap = aps[0]
    assert ap["BSSID"] == "AA:BB:CC:DD:EE:01"
    assert ap["ESSID"] == "HomeNet"       # padding spaces stripped
    assert ap["Channel"] == "6"
    assert ap["Privacy"] == "WPA2" and ap["Cipher"] == "CCMP" and ap["Auth"] == "PSK"
    assert ap["Power"] == "-45" and ap["Beacons"] == "120"


def test_open_network_keeps_blank_cipher():
    aps, _ = parse(SAMPLE)
    assert aps[1]["Privacy"] == "OPN" and aps[1]["Cipher"] == ""


def test_client_fields_and_multiple_probed_essids():
    _, clients = parse(SAMPLE)
    assert clients[0]["Station"] == "11:22:33:44:55:66"
    assert clients[0]["BSSID"] == "AA:BB:CC:DD:EE:01"
    assert clients[0]["Packets"] == "25"
    # probed ESSIDs are themselves comma-separated and must survive the split
    assert clients[1]["ProbedESSIDs"] == "Cafe, Airport"


def test_headers_and_blank_lines_are_not_rows():
    aps, clients = parse(SAMPLE)
    assert all(a["BSSID"] != "BSSID" for a in aps)
    assert all(c["Station"] != "Station MAC" for c in clients)


def test_truncated_trailing_row_is_skipped():
    """airodump flushes every second, so the last row can be mid-write when we kill it."""
    aps, clients = parse(SAMPLE + "DD:EE:FF:00:11:2")
    assert len(aps) == 2 and len(clients) == 2


def test_empty_and_ap_only_input():
    assert parse("") == ([], [])
    ap_only = SAMPLE.split("Station MAC")[0]
    aps, clients = parse(ap_only)
    assert len(aps) == 2 and clients == []


# --- monitor-mode guard ---------------------------------------------------------------------
def test_parse_default_route_iface():
    out = "default via 192.168.1.1 dev wlan0 proto dhcp src 192.168.1.50 metric 600\n"
    assert monitor_mode.parse_default_route_iface(out) == "wlan0"
    assert monitor_mode.parse_default_route_iface("") == ""


def test_parse_wireless_ifaces():
    out = "phy#1\n\tInterface wlan1\n\t\tifindex 4\nphy#0\n\tInterface wlan0\n\t\tifindex 3\n"
    assert monitor_mode.parse_wireless_ifaces(out) == ["wlan1", "wlan0"]


def test_parse_supports_monitor_reads_only_the_modes_block():
    supported = ("\tSupported interface modes:\n\t\t * IBSS\n\t\t * managed\n\t\t * AP\n"
                 "\t\t * monitor\n\tBand 1:\n")
    assert monitor_mode.parse_supports_monitor(supported) is True
    # 'monitor' appearing outside the modes block must not count as support
    unsupported = ("\tSupported interface modes:\n\t\t * managed\n\t\t * AP\n"
                   "\tsoftware interface modes (can always be added):\n\t\t * monitor\n")
    assert monitor_mode.parse_supports_monitor(unsupported) is False
    assert monitor_mode.parse_supports_monitor("") is False


def _guard_with(uplink, wireless):
    """check_usable() with the system probes faked out — including `iw` presence, so these run on
    a dev box that has no wireless tooling."""
    saved = (monitor_mode.default_route_iface, monitor_mode.wireless_ifaces,
             monitor_mode.shutil.which)
    monitor_mode.default_route_iface = lambda: uplink
    monitor_mode.wireless_ifaces = lambda: wireless
    monitor_mode.shutil.which = lambda name: "/usr/sbin/" + name
    return saved


def _restore(saved):
    (monitor_mode.default_route_iface, monitor_mode.wireless_ifaces,
     monitor_mode.shutil.which) = saved


def _fake_iw(dev_out, phy_out, rc=0):
    """Fake both `iw` calls _monitor_support() makes: `iw dev X info`, then `iw phy phyN info`.

    Indentation in the fixtures below is spaces, not the tabs `iw` really emits: parse_supports_
    monitor() strips it, and what is under test is the modes list, not the whitespace."""
    return lambda args, timeout=15: (rc, phy_out if args[1] == "phy" else dev_out)


_DEV_INFO = """Interface wlan0
        wiphy 0
"""
# The onboard Pi radio, verbatim in shape: managed and AP, no monitor anywhere.
_PHY_NO_MONITOR = """Supported interface modes:
         * managed
         * AP
Band 1:
"""


def test_a_radio_whose_phy_has_no_monitor_mode_is_refused_by_the_guard():
    """Observed on a Pi Zero 2W field run, 2026-08-20: with the dongle busy hunting, WiFiScan fell
    back to wlan0, `iw dev wlan0 set type monitor` returned "Operation not supported (-95)", the
    action was marked 'failed' and backed off for 10 minutes — four times, on a radio that can
    never work. The guard now refuses it by capability, before anything touches the interface."""
    saved_guard = _guard_with("", ["wlan0"])
    saved_run = monitor_mode._run
    monitor_mode._run = _fake_iw(_DEV_INFO, _PHY_NO_MONITOR)
    try:
        assert monitor_mode.supports_monitor("wlan0") is False
        assert monitor_mode.monitor_capable("wlan0") is False
        problem = monitor_mode.check_usable("wlan0")
    finally:
        monitor_mode._run = saved_run
        _restore(saved_guard)
    assert problem and "monitor mode" in problem


def test_a_probe_that_could_not_run_is_unknown_not_a_no():
    """The two questions diverge here, which is why both exist. `iw` missing or erroring is not
    evidence about the hardware: a filter that drops a radio on a hiccup silently stops scanning
    on a device that works — worse than the -95 the filter was added to prevent. The web 'test'
    button still answers no, because it asked for proof."""
    saved = monitor_mode._run
    monitor_mode._run = _fake_iw("", "", rc=1)
    try:
        assert monitor_mode.supports_monitor("wlan1") is False
        assert monitor_mode.monitor_capable("wlan1") is True
    finally:
        monitor_mode._run = saved


def test_guard_reports_missing_iw_clearly():
    saved = _guard_with("wlan0", ["wlan1"])
    monitor_mode.shutil.which = lambda name: None
    try:
        assert "iw" in monitor_mode.check_usable("wlan1")
    finally:
        _restore(saved)


def test_guard_refuses_the_uplink_interface():
    """The whole point of the module: never monitor-mode the radio carrying Bjorn's own traffic."""
    saved = _guard_with("wlan0", ["wlan0", "wlan1"])
    try:
        problem = monitor_mode.check_usable("wlan0")
    finally:
        _restore(saved)
    assert problem and "default route" in problem


def test_guard_refuses_by_route_not_by_name():
    """If the dongle enumerated as wlan0 and the onboard radio is the uplink, a name-based check
    would happily destroy connectivity. The guard keys on the routing table instead."""
    saved = _guard_with("wlan1", ["wlan0", "wlan1"])
    try:
        assert monitor_mode.check_usable("wlan1")      # the uplink is refused...
        assert monitor_mode.check_usable("wlan0") == ""  # ...and wlan0 is fine here
    finally:
        _restore(saved)


def test_build_cmd_defaults_add_no_band_or_channel_flags():
    """airodump's own default is 2.4GHz hopping — don't pass flags that restate it."""
    cmd = WiFiScan.build_cmd("/usr/sbin/airodump-ng", "wlan1", "/tmp/scan")
    assert cmd[:2] == ["/usr/sbin/airodump-ng", "wlan1"]
    assert "--band" not in cmd and "-c" not in cmd
    assert "--write-interval" in cmd  # the CSV must stay flushed; we stop the process by timeout


def test_build_cmd_band_and_channel():
    assert "--band" in WiFiScan.build_cmd("a", "wlan1", "/tmp/s", band="abg")
    cmd = WiFiScan.build_cmd("a", "wlan1", "/tmp/s", band="abg", channel=6)
    # A locked channel and a band sweep are mutually exclusive — the channel wins, alone.
    assert cmd[cmd.index("-c") + 1] == "6" and "--band" not in cmd


def test_radio_lock_refuses_a_second_capture():
    """The scheduled scan and the web 'Scan now' button are two consumers of one radio: the second
    must be refused, not queued, and the lock must survive release() for the next caller."""
    saved = _guard_with("wlan0", ["wlan0", "wlan1"])
    saved_run = monitor_mode._run
    monitor_mode._run = lambda *a, **k: (0, "")  # every ip/iw/nmcli call "succeeds"
    try:
        ok, _, _ = monitor_mode.acquire("wlan1")
        assert ok, "first acquire must win the radio"

        ok2, detail, reason = monitor_mode.acquire("wlan1")
        assert not ok2 and reason == monitor_mode.BUSY, "second acquire must be refused as busy"
        assert "scan" in detail, "the refusal must name who holds the radio"

        monitor_mode.release("wlan1")
        ok3, _, _ = monitor_mode.acquire("wlan1")
        assert ok3, "the radio must be acquirable again after release"
        monitor_mode.release("wlan1")
    finally:
        monitor_mode._run = saved_run
        _restore(saved)


def test_monitor_is_live_waits_for_the_netdev_to_be_retyped():
    """The mode change is asynchronous, and it is not one clean transition: sampled every 10ms on
    the Pi, the netdev oscillates 803 -> 1 -> 803 over ~100ms after `ip link set up`. A capture
    opened during that Ethernet trough dies with 'ARP linktype is set to 1', so monitor mode must
    *hold* for a settle window before the radio is handed over — one matching read is not enough."""
    saved = monitor_mode.arphrd_type

    def feed(*codes):
        """Yield each code in turn, then repeat the last one forever. A settle window polls more
        times than a fixed list has entries, and a fake that runs dry raises StopIteration."""
        seq = itertools.chain(codes, itertools.repeat(codes[-1]))
        return lambda _iface: next(seq)

    try:
        monitor_mode.arphrd_type = feed(1, 1, 803)   # Ethernet, Ethernet, then radiotap
        assert monitor_mode.monitor_is_live("wlan1", timeout=2, poll=0, settle=0.01) is True

        # The flap itself: the opening 803 must not be taken for success, because the type drops
        # back to Ethernet right after it — exactly when airodump would be opening the device.
        monitor_mode.arphrd_type = feed(803, 1)      # blips monitor, then stays Ethernet
        assert monitor_mode.monitor_is_live("wlan1", timeout=0.2, poll=0.01, settle=0.05) is False

        monitor_mode.arphrd_type = feed(803, 1, 803)  # ...and settles on the far side of the flap
        assert monitor_mode.monitor_is_live("wlan1", timeout=2, poll=0.01, settle=0.05) is True

        monitor_mode.arphrd_type = feed(1)           # never flips
        assert monitor_mode.monitor_is_live("wlan1", timeout=0.05, poll=0) is False

        monitor_mode.arphrd_type = feed(0)           # unreadable (not Linux) — don't veto
        assert monitor_mode.monitor_is_live("wlan1", timeout=0, poll=0) is True
    finally:
        monitor_mode.arphrd_type = saved


def test_wait_for_wpa_release_polls_the_control_socket():
    """The signal is wpa_supplicant's per-interface control socket: present while it holds the
    interface, removed by its nl80211 deinit. A box that does not run it has no socket and waits
    for nothing."""
    saved_dir, saved_holds = monitor_mode.WPA_CTRL_DIR, monitor_mode.wpa_holds
    tmp = tempfile.mkdtemp()
    try:
        monitor_mode.WPA_CTRL_DIR = tmp
        assert monitor_mode.wpa_holds("wlan1") is False, "no socket, nobody holding it"
        open(os.path.join(tmp, "wlan1"), "w").close()
        assert monitor_mode.wpa_holds("wlan1") is True

        monitor_mode.wpa_holds = lambda _iface: True            # never lets go
        assert monitor_mode.wait_for_wpa_release("wlan1", timeout=0.05, poll=0.01) is False

        holds = iter([True, True, False])                       # lets go on the third look
        monitor_mode.wpa_holds = lambda _iface: next(holds)
        assert monitor_mode.wait_for_wpa_release("wlan1", timeout=2, poll=0) is True, \
            "it has to keep polling, not look once and give up"
    finally:
        monitor_mode.WPA_CTRL_DIR, monitor_mode.wpa_holds = saved_dir, saved_holds
        shutil.rmtree(tmp, ignore_errors=True)


def test_acquire_waits_for_the_release_before_changing_the_mode():
    """Ordering is the whole fix. `nmcli ... managed no` returns when NetworkManager has let go,
    not when wpa_supplicant has — its deinit lands ~340ms later (measured on the Pi, 2026-08-18)
    and puts the interface back into station mode. A mode change issued in that window is undone,
    which left acquire()s first attempt typed Ethernet for its whole timeout on every cold
    acquisition, making the second attempt look like a retry that fixed something."""
    events = []
    saved = _guard_with("wlan0", ["wlan0", "wlan1"])
    saved_run, saved_live = monitor_mode._run, monitor_mode.monitor_is_live
    saved_holds = monitor_mode.wpa_holds
    monitor_mode._run = lambda args, **k: (events.append(" ".join(args[:4])), (0, ""))[1]
    monitor_mode.monitor_is_live = lambda *a, **k: True
    monitor_mode.wpa_holds = lambda _iface: (events.append("waited for wpa_supplicant"), False)[1]
    try:
        ok, _, _ = monitor_mode.acquire("wlan1")
        assert ok
        monitor_mode.release("wlan1")
        assert "waited for wpa_supplicant" in events, f"acquire() changed the mode without waiting for the release: {events}"
        nmcli = next(i for i, e in enumerate(events) if e.startswith("nmcli device set"))
        wait = events.index("waited for wpa_supplicant")
        mode = next(i for i, e in enumerate(events) if e.startswith("iw dev wlan1 set"))
        assert nmcli < wait < mode, f"the wait belongs between the release and the mode change: {events}"
    finally:
        monitor_mode._run, monitor_mode.monitor_is_live = saved_run, saved_live
        monitor_mode.wpa_holds = saved_holds
        _restore(saved)


def test_acquire_refuses_an_interface_that_never_leaves_ethernet():
    """acquire() used to report success on three exit codes, so a radio that had not actually
    entered monitor mode was handed to airodump/bettercap anyway — an empty capture reported as a
    working one (2026-08-17). It must now fail, and must not keep the lock when it does."""
    saved = _guard_with("wlan0", ["wlan0", "wlan1"])
    saved_run, saved_live = monitor_mode._run, monitor_mode.monitor_is_live
    monitor_mode._run = lambda *a, **k: (0, "")        # every ip/iw/nmcli call "succeeds"
    monitor_mode.monitor_is_live = lambda *a, **k: False   # ...but the netdev stays Ethernet
    try:
        ok, detail, reason = monitor_mode.acquire("wlan1")
        assert not ok and reason == monitor_mode.FAILED
        assert "monitor mode" in detail
        assert monitor_mode.holder() == "", "a failed acquire must not keep the radio"
        # and the radio is still acquirable once the driver behaves
        monitor_mode.monitor_is_live = lambda *a, **k: True
        ok2, _, _ = monitor_mode.acquire("wlan1")
        assert ok2
        monitor_mode.release("wlan1")
    finally:
        monitor_mode._run, monitor_mode.monitor_is_live = saved_run, saved_live
        _restore(saved)


def test_holder_names_the_owner_and_clears_on_release():
    """A turned-away consumer needs to know *who* has the radio: the hunter holds it for a whole
    session, so 'busy' has to be distinguishable from 'your config is wrong'."""
    saved = _guard_with("wlan0", ["wlan0", "wlan1"])
    saved_run = monitor_mode._run
    monitor_mode._run = lambda *a, **k: (0, "")
    try:
        assert monitor_mode.holder() == ""
        ok, _, reason = monitor_mode.acquire("wlan1", owner="pwn")
        assert ok and reason == ""
        assert monitor_mode.holder() == "pwn"
        monitor_mode.release("wlan1", owner="pwn")
        assert monitor_mode.holder() == ""
    finally:
        monitor_mode._run = saved_run
        _restore(saved)


def test_a_non_owner_cannot_release_the_radio():
    """Without this, the scheduled scan could hand back a radio the hunter is mid-capture on — and
    drop its lock doing so, which is the exact interleaving the lock exists to prevent."""
    saved = _guard_with("wlan0", ["wlan0", "wlan1"])
    saved_run = monitor_mode._run
    monitor_mode._run = lambda *a, **k: (0, "")
    try:
        monitor_mode.acquire("wlan1", owner="pwn")
        monitor_mode.release("wlan1", owner="scan")      # not the owner — must be ignored
        assert monitor_mode.holder() == "pwn", "a non-owner must not free the radio"
        ok, _, reason = monitor_mode.acquire("wlan1", owner="scan")
        assert not ok and reason == monitor_mode.BUSY, "the radio must still be held"
        monitor_mode.release("wlan1", owner="pwn")       # the owner can
        assert monitor_mode.holder() == ""
    finally:
        monitor_mode._run = saved_run
        _restore(saved)


def test_unsafe_and_busy_are_different_reasons():
    """The distinction Stage A exists for: WiFiScan skips on busy and reports on unsafe."""
    saved = _guard_with("wlan0", ["wlan0", "wlan1"])
    saved_run = monitor_mode._run
    monitor_mode._run = lambda *a, **k: (0, "")
    try:
        ok, _, reason = monitor_mode.acquire("wlan0")  # the uplink
        assert not ok and reason == monitor_mode.UNSAFE
        assert monitor_mode.holder() == "", "a refused acquire must not take the lock"
    finally:
        monitor_mode._run = saved_run
        _restore(saved)


def test_wifi_scan_skips_rather_than_fails_when_the_radio_is_busy():
    """The behaviour that matters on a Pi: a held radio must leave no netkb mark, no retry backoff
    and no ERROR line — a hunt running for hours would otherwise log one every cycle."""
    import types
    saved = _guard_with("wlan0", ["wlan0", "wlan1"])
    saved_run = monitor_mode._run
    saved_which = wifi_scan_mod.shutil.which
    monitor_mode._run = lambda *a, **k: (0, "")
    wifi_scan_mod.shutil.which = lambda _n: "/usr/sbin/airodump-ng"
    try:
        monitor_mode.acquire("wlan1", owner="pwn")  # the hunter owns the radio
        cfg = types.SimpleNamespace(scan_results_dir=tempfile.mkdtemp(prefix="bjorn_wifi_test_"),
                                    wifi_scan_enabled=True, wifi_scan_iface="wlan1",
                                    wifi_scan_interval=0)
        scanner = WiFiScan(cfg)
        assert scanner.execute() == 'skipped'
        assert scanner._last_scan == 0.0, "a skipped scan must not start the throttle clock"
    finally:
        monitor_mode.release("wlan1", owner="pwn")
        wifi_scan_mod.shutil.which = saved_which
        monitor_mode._run = saved_run
        _restore(saved)


def test_release_reports_failure_instead_of_claiming_success():
    """2026-08-08 on-Pi: wlan1 was left in monitor mode while release() logged 'returned to managed
    mode'. It ran three commands ignoring every return code and reported success unconditionally —
    a status line that cannot fail tells you nothing (cf. `WiFiScan: success=4`)."""
    saved = _guard_with("wlan0", ["wlan0", "wlan1"])
    saved_run = monitor_mode._run
    mode = {"value": "monitor"}   # the radio never comes back

    def fake_run(args, **kwargs):
        if args[:2] == ["iw", "dev"] and args[-1] == "info":
            return 0, f"\ttype {mode['value']}\n"
        return 0, ""

    monitor_mode._run = fake_run
    try:
        monitor_mode.acquire("wlan1")
        assert monitor_mode.release("wlan1") is False, "a stranded radio must not report success"
        assert monitor_mode.holder() == "", "the lock must be freed even when the radio is stuck"

        mode["value"] = "managed"  # and a radio that does come back reports True
        monitor_mode.acquire("wlan1")
        assert monitor_mode.release("wlan1") is True
    finally:
        monitor_mode._run = saved_run
        _restore(saved)


def test_capture_surfaces_airodump_stderr_instead_of_swallowing_it():
    """2026-08-08 on-Pi: 'airodump capture — no fresh AP rows' FAILed with nothing in the log to
    explain it. airodump-ng only returns before its timeout when it has failed, and it says why on
    stderr — which the old `capture_output=True` collected into a pipe and dropped on the floor."""
    import types
    import subprocess as sp
    logged = []
    saved_run, saved_warn = wifi_scan_mod.subprocess.run, wifi_scan_mod.logger.warning
    wifi_scan_mod.logger.warning = lambda msg, *a, **k: logged.append(str(msg))
    cfg = types.SimpleNamespace(scan_results_dir=tempfile.mkdtemp(prefix="bjorn_wifi_test_"))

    def dead_airodump(cmd, **kwargs):
        assert kwargs.get("stdout") is sp.DEVNULL, "the ncurses screen must not be buffered"
        return types.SimpleNamespace(
            returncode=1, stdout=None,
            stderr="ioctl(SIOCSIWMODE) failed: Device or resource busy\n")

    def timed_out(cmd, **kwargs):
        raise sp.TimeoutExpired(cmd, 30)

    try:
        wifi_scan_mod.subprocess.run = dead_airodump
        assert WiFiScan(cfg)._capture("/usr/sbin/airodump-ng", "wlan1", 30) == ([], [])
        assert any("Device or resource busy" in m for m in logged), logged

        # The healthy path: the timeout IS the stop signal, so it must never report an early exit.
        logged.clear()
        wifi_scan_mod.subprocess.run = timed_out
        assert WiFiScan(cfg)._capture("/usr/sbin/airodump-ng", "wlan1", 30) == ([], [])
        assert not any("exited on its own" in m for m in logged), logged
    finally:
        wifi_scan_mod.subprocess.run = saved_run
        wifi_scan_mod.logger.warning = saved_warn


def test_parse_iface_mode():
    assert monitor_mode.parse_iface_mode("\tifindex 4\n\ttype monitor\n") == "monitor"
    assert monitor_mode.parse_iface_mode("\ttype managed\n") == "managed"
    assert monitor_mode.parse_iface_mode("no type line here\n") == ""


def test_guard_rejects_blank_and_unknown_interfaces():
    saved = _guard_with("wlan0", ["wlan0"])
    try:
        assert "wifi_scan_iface" in monitor_mode.check_usable("")
        assert "not a wireless interface" in monitor_mode.check_usable("eth9")
    finally:
        _restore(saved)


def test_wifi_scan_fails_when_the_radio_is_not_restored():
    """#5(3) side-effect verification: a capture that runs but leaves the radio in monitor mode is
    NOT a success. Success is earned by the radio being back on the air — read from release()'s
    verified True/False — not by airodump having run. This is the `WiFiScan: success=4` class: a
    status line that cannot fail tells you nothing."""
    import types
    from action_outcome import OutcomeCode
    saved = (wifi_scan_mod.shutil.which, wifi_scan_mod.offline_mode.is_online,
             wifi_scan_mod.offline_mode.scan_iface, wifi_scan_mod.monitor_mode.acquire,
             wifi_scan_mod.monitor_mode.release)
    cfg = types.SimpleNamespace(scan_results_dir=tempfile.mkdtemp(prefix="bjorn_wifi_test_"),
                                wifi_scan_enabled=True, wifi_scan_iface="wlan1",
                                wifi_scan_interval=0)
    wifi_scan_mod.shutil.which = lambda _n: "/usr/sbin/airodump-ng"
    wifi_scan_mod.offline_mode.is_online = lambda: True
    wifi_scan_mod.offline_mode.scan_iface = lambda _sd: "wlan1"
    wifi_scan_mod.monitor_mode.acquire = lambda *a, **k: (True, "", "")
    scanner = WiFiScan(cfg)
    scanner._capture = lambda *a, **k: ([{"BSSID": "AA:BB:CC:DD:EE:01", "ESSID": "X"}], [])
    try:
        wifi_scan_mod.monitor_mode.release = lambda *a, **k: False   # radio never comes back
        outcome = scanner.execute()
        assert outcome.code is OutcomeCode.ERROR, "a stranded radio must not read as success"
        assert not outcome.succeeded

        scanner._last_scan = 0.0  # clear the throttle for a second run
        wifi_scan_mod.monitor_mode.release = lambda *a, **k: True    # verified back in managed
        outcome = scanner.execute()
        assert outcome.succeeded and outcome.evidence_count == 1, "a restored radio + a capture is a win"
    finally:
        (wifi_scan_mod.shutil.which, wifi_scan_mod.offline_mode.is_online,
         wifi_scan_mod.offline_mode.scan_iface, wifi_scan_mod.monitor_mode.acquire,
         wifi_scan_mod.monitor_mode.release) = saved


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
