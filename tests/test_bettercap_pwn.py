"""Tests for the Handshake Hunter's admission guard (docs/BETTERCAP_PLAN.md step C1).

The refusal that matters is the single-radio one. offline_mode.py warns that nmcli cannot associate
an interface still in monitor mode and that it fails *quietly*, so a hunter holding the only usable
radio does not merely fail to reconnect — Bjorn stays offline forever and never delivers the
handshakes it just captured. Everything here is pure decision logic over injected state, so no
radio, no daemon and no Pi is involved.
"""
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


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
