"""Tests for offline behaviour: radio selection when there is no uplink, nmcli parsing, and the
join policy. All pure functions — no radio, no nmcli, no subprocesses.

The one that matters is pick_scan_iface: it is the function that decides whether Bjorn is allowed
to put a radio into monitor mode, and the failure it must never have is borrowing the interface
carrying the uplink (that kills the web UI, reporting and scanning from inside the process that
would have to report it).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _stubs  # noqa: E402
_stubs.install()

import offline_mode  # noqa: E402

pick = offline_mode.pick_scan_iface


def test_configured_dongle_is_used_when_present():
    assert pick("wlan1", ["wlan0", "wlan1"], "wlan0") == "wlan1"


def test_never_returns_the_uplink_even_if_configured():
    # The saved config naming the uplink must not override the uplink itself.
    assert pick("wlan0", ["wlan0", "wlan1"], "wlan0") == "wlan1"


def test_online_with_no_dongle_returns_nothing():
    # A single radio carrying the uplink: no capture is worth cutting the branch we sit on.
    assert pick("", ["wlan0"], "wlan0") == ""
    # Config names a dongle that is not plugged in, and the only radio present is the uplink.
    assert pick("wlan1", ["wlan0"], "wlan0") == ""


def test_blank_config_uses_the_only_non_uplink_radio():
    # Enabling the scan but leaving the interface blank means "use the spare radio", not "do
    # nothing" — there is exactly one candidate and it is not the uplink.
    assert pick("", ["wlan0", "wlan1"], "wlan0") == "wlan1"


def test_offline_falls_back_to_the_onboard_radio():
    # No uplink -> nothing to lose -> the onboard radio becomes fair game.
    assert pick("", ["wlan0"], "") == "wlan0"
    assert pick("wlan1", ["wlan0"], "") == "wlan0"


def test_offline_still_prefers_the_dongle():
    assert pick("wlan1", ["wlan0", "wlan1"], "") == "wlan1"


def test_fallback_skips_a_radio_that_cannot_do_monitor_mode():
    """Offline, the onboard radio becomes *eligible* (nothing is the uplink) — but on a Pi Zero
    2W its phy has no monitor mode at all, so picking it produced `iw ... set type monitor failed:
    Operation not supported (-95)`, a 'failed' stamp and a 10-minute backoff on a scan that could
    have run on the next cycle. Observed four times in one field run, every time the dongle was
    busy hunting."""
    only_the_dongle = lambda name: name == "wlan1"
    assert pick("", ["wlan0", "wlan1"], "", capable=only_the_dongle) == "wlan1"
    # Dongle unplugged and the onboard radio cannot capture: nothing to scan with. "" routes the
    # caller to its quiet skip, not to an error it will retry forever.
    assert pick("", ["wlan0"], "", capable=only_the_dongle) == ""


def test_a_named_radio_is_still_returned_even_if_it_cannot_capture():
    """Capability gates the *fallback*, not the operator's explicit choice: check_usable() is what
    explains why a named radio is wrong. Filtering it out here would make WiFiScan report a dongle
    that is plugged in as "not present (moved USB port?)" — a wrong answer to a real mistake."""
    assert pick("wlan0", ["wlan0", "wlan1"], "", capable=lambda name: False) == "wlan0"


def test_no_radios_at_all():
    assert pick("wlan1", [], "") == ""


def test_uplink_candidate_avoids_the_capture_radio():
    assert offline_mode.uplink_candidate(["wlan0", "wlan1"], "wlan1") == "wlan0"
    # Single radio: it has to do both jobs, sequentially.
    assert offline_mode.uplink_candidate(["wlan0"], "wlan0") == "wlan0"
    assert offline_mode.uplink_candidate([], "wlan1") == ""


def test_reconnect_uses_the_radio_not_reserved_for_capture():
    """The two offline jobs must land on different radios, and they have to do so with the config
    left blank — that is how the device actually ships.

    reconnect_best used to pass the raw `wifi_scan_iface` string to uplink_candidate, so a blank
    key matched no interface and the first one `iw dev` listed was chosen to reconnect. On this Pi
    that list is ["wlan1", "wlan0"] — the dongle first — so the capture radio and the reconnect
    radio were the same one, and the onboard chip holding the saved profiles was never tried.
    """
    import types

    saved = (offline_mode.monitor_mode.wireless_ifaces,
             offline_mode.monitor_mode.default_route_iface, offline_mode.reconnect)
    tried = []
    # Dongle first, exactly as `iw dev` reports it on the device.
    offline_mode.monitor_mode.wireless_ifaces = lambda: ["wlan1", "wlan0"]
    offline_mode.monitor_mode.default_route_iface = lambda: ""       # offline: no uplink
    offline_mode.reconnect = lambda iface, allow_open=False: (tried.append(iface), (False, ""))[1]
    try:
        offline_mode.reconnect_best(types.SimpleNamespace(wifi_scan_iface=""))
        assert tried == ["wlan0"], f"reconnect must not use the capture radio, got {tried}"
        # Capture radio named explicitly: the other one still carries the uplink attempt.
        tried.clear()
        offline_mode.reconnect_best(types.SimpleNamespace(wifi_scan_iface="wlan1"))
        assert tried == ["wlan0"]
        # Single radio: it does both jobs, sequentially — never "no interface".
        offline_mode.monitor_mode.wireless_ifaces = lambda: ["wlan0"]
        tried.clear()
        offline_mode.reconnect_best(types.SimpleNamespace(wifi_scan_iface=""))
        assert tried == ["wlan0"]
    finally:
        (offline_mode.monitor_mode.wireless_ifaces,
         offline_mode.monitor_mode.default_route_iface, offline_mode.reconnect) = saved


NMCLI_WIFI = r"""*:HomeNet:78:WPA2
:Cafe\:Free:52:
:Neighbour:41:WPA1 WPA2
::22:WPA2
:Weak Open:15:
"""


def test_parse_nmcli_wifi():
    nets = offline_mode.parse_nmcli_wifi(NMCLI_WIFI)
    # The hidden network (empty SSID) is dropped — there is nothing to connect to by name.
    assert [n["ssid"] for n in nets] == ["HomeNet", "Cafe:Free", "Neighbour", "Weak Open"]
    assert nets[0]["in_use"] is True
    assert nets[0]["signal"] == 78
    # An escaped colon inside an SSID must survive as part of the name, not split the record.
    assert nets[1]["ssid"] == "Cafe:Free"
    assert nets[1]["open"] is True
    assert nets[2]["open"] is False


def test_choose_prefers_saved_over_stronger_open():
    nets = offline_mode.parse_nmcli_wifi(NMCLI_WIFI)
    chosen = offline_mode.choose_network(nets, saved={"Neighbour"}, allow_open=True)
    # Cafe:Free is open and stronger (52 > 41), but an authorized network is never the riskier pick.
    assert chosen["ssid"] == "Neighbour"


def test_open_networks_are_ignored_unless_allowed():
    nets = offline_mode.parse_nmcli_wifi(NMCLI_WIFI)
    assert offline_mode.choose_network(nets, saved=set(), allow_open=False) is None
    chosen = offline_mode.choose_network(nets, saved=set(), allow_open=True)
    assert chosen["ssid"] == "Cafe:Free"   # strongest open one


def test_reconnect_refuses_a_radio_still_in_monitor_mode(monkeypatch):
    # nmcli cannot associate an interface in monitor mode and fails quietly, which would read as
    # "auto-join is broken" rather than "auto-join ran before the capture released the radio".
    monkeypatch.setattr(offline_mode.shutil, "which", lambda _n: "/usr/bin/nmcli")
    monkeypatch.setattr(offline_mode, "_iface_mode", lambda _i: "monitor")
    ok, detail = offline_mode.reconnect("wlan0")
    assert ok is False
    assert "monitor" in detail


def demo():
    """Runnable without pytest: python tests/test_offline_mode.py"""
    test_configured_dongle_is_used_when_present()
    test_never_returns_the_uplink_even_if_configured()
    test_online_with_no_dongle_returns_nothing()
    test_blank_config_uses_the_only_non_uplink_radio()
    test_offline_falls_back_to_the_onboard_radio()
    test_offline_still_prefers_the_dongle()
    test_no_radios_at_all()
    test_uplink_candidate_avoids_the_capture_radio()
    test_reconnect_uses_the_radio_not_reserved_for_capture()
    test_parse_nmcli_wifi()
    test_choose_prefers_saved_over_stronger_open()
    test_open_networks_are_ignored_unless_allowed()
    print("offline_mode: all checks passed")


if __name__ == "__main__":
    demo()
