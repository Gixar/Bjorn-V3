"""Tests for Wi-Fi recon (backlog Wave 4): the airodump-ng CSV parser and the monitor-mode
guard. No radio, no subprocesses — the parsers are pure and the guard is driven with injected
fakes. Heavy imports stubbed via _stubs.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _stubs  # noqa: E402
_stubs.install()

import monitor_mode  # noqa: E402
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
    out = "default via 192.168.1.1 dev wlan0 proto dhcp src 192.168.1.35 metric 600\n"
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


def test_guard_rejects_blank_and_unknown_interfaces():
    saved = _guard_with("wlan0", ["wlan0"])
    try:
        assert "wifi_scan_iface" in monitor_mode.check_usable("")
        assert "not a wireless interface" in monitor_mode.check_usable("eth9")
    finally:
        _restore(saved)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
