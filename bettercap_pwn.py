# bettercap_pwn.py
# The Handshake Hunter's admission guard (docs/BETTERCAP_PLAN.md Stage C, step C1).
#
# This file is deliberately ONLY the guard. Starting the daemon, taking the radio and watching the
# capture directory are C2/C3 — a start() that did nothing but return success would be the fourth
# instance of this codebase's recurring defect: a status generated rather than measured (see
# `WiFiScan: success=4`, the skipped-scan-reported-as-success, and release() claiming a radio came
# back when it had not).
#
# WHY THE GUARD COMES FIRST. The hunter holds a radio in monitor mode for a whole session, and
# offline_mode.py already warns that nmcli cannot associate an interface still in monitor mode —
# it fails *quietly*. So a hunter running on the only usable radio does not merely fail to
# reconnect: Bjorn stays offline forever and never delivers the handshakes it just captured. The
# refusal below is the thing that prevents that, which is why it lands before any code that could
# trigger it.
#
# Pure decision logic over injected state, so every refusal is testable without a radio.
import shutil
import logging

import monitor_mode
import offline_mode
from logger import Logger

logger = Logger(name="bettercap_pwn.py", level=logging.INFO)

# Below this many wireless interfaces the hunter never runs. Not a tunable: with a single radio
# there is no arrangement in which hunting and staying reachable are both possible, so exposing it
# as a knob would only offer a way to strand the device.
MIN_RADIOS = 2


def can_start(shared_data, wireless=None, uplink=None, holder=None, binary=None):
    """May the hunter start right now? Returns (ok, reason, iface).

    Every argument after `shared_data` is injectable so the decision can be tested without
    hardware; left as None they are read from the live system. The reason string is written to be
    shown verbatim in the web panel — "it didn't start" with no explanation is the thing that makes
    an opt-in feature look broken.
    """
    wireless = monitor_mode.wireless_ifaces() if wireless is None else wireless
    uplink = monitor_mode.default_route_iface() if uplink is None else uplink
    holder = monitor_mode.holder() if holder is None else holder
    binary = (shutil.which("bettercap") is not None) if binary is None else binary

    if not getattr(shared_data, "bettercap_pwn_enabled", False):
        return False, "the hunter is off (enable it on the Bettercap page)", ""

    # Mutually exclusive with managed mode: one bettercap profile at a time. Managed mode is
    # attached to the network Bjorn has joined; monitor mode takes a radio out of that world
    # entirely, and running both means one profile silently undoing the other's interface state.
    if getattr(shared_data, "bettercap_enabled", False):
        return False, "managed-mode Bettercap is enabled — the two profiles are mutually exclusive", ""

    if not binary:
        return False, "bettercap is not installed (re-run install_bjorn.sh, or apt install bettercap)", ""

    # THE REFUSAL THIS MODULE EXISTS FOR. Keyed on how many radios exist, not on which one is the
    # uplink: offline there is no uplink at all, and that is exactly when a single-radio device
    # would hand its only way back onto a network to a monitor-mode capture.
    if len(wireless) < MIN_RADIOS:
        return False, (f"only {len(wireless)} wireless radio(s) — the hunter needs a second one. "
                       f"With one radio it would hold the only path back online, and Bjorn could "
                       f"never rejoin a network to deliver what it captured."), ""

    # A radio the operator NAMED is checked here rather than handed to
    # offline_mode.pick_scan_iface, which deliberately falls back to any other non-uplink radio.
    # That fallback is right for the scheduled capture — offline, grab whatever is safe — but wrong
    # here: silently hunting on a different radio than the one configured hides the mistake, and
    # WiFiScan already set the precedent that a *named* radio which cannot be used is a
    # misconfiguration to report (the moved-USB-port case). Blank still means "pick one for me".
    configured = (getattr(shared_data, "bettercap_pwn_iface", "") or "").strip()
    if configured:
        if configured not in wireless:
            return False, f"{configured} is not present (dongle unplugged, or a different name?)", ""
        if configured == uplink:
            return False, (f"{configured} is carrying the uplink — monitor mode there would drop "
                           f"the web UI and reporting. Pick the other radio."), ""
        iface = configured
    else:
        iface = offline_mode.pick_scan_iface("", wireless, uplink)
        if not iface:
            return False, "no non-uplink radio is available", ""

    # A radio someone else is mid-capture on. Non-fatal and worth saying plainly: the hunter is a
    # long-lived consumer, so "come back later" is the honest answer rather than an error.
    if holder:
        return False, f"the radio is currently held by {holder} — try again once it is free", ""

    return True, f"ready to hunt on {iface}", iface


def describe(shared_data):
    """One line for the web panel / logs. Never raises — a status probe that can fail is useless."""
    try:
        ok, reason, iface = can_start(shared_data)
    except Exception as e:                      # noqa: BLE001 - a status call must not take a page down
        logger.error(f"Hunter status check failed: {e}")
        return f"status unavailable: {e}"
    return reason if not ok else f"ready ({iface})"
