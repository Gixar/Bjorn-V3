# monitor_mode.py
# Monitor-mode lifecycle for the second Wi-Fi radio (backlog Wave 4 / airodump-ng AP recon).
#
# THE RULE THIS FILE EXISTS TO ENFORCE: monitor mode and managed mode are mutually exclusive on the
# same radio, so putting Bjorn's *own* uplink into monitor mode instantly kills the web UI, Telegram
# delivery and IP scanning — from inside the very process that would have to report the failure.
# Every acquisition therefore goes through acquire() here, which refuses any interface carrying the
# default route. The guard keys on the routing table, not on the name "wlan0": interface names are
# not stable across USB dongles and reboots, and a name check would silently pass the day the
# dongle enumerates first.
#
# Deliberately NOT using `airmon-ng start`: the ubiquitous companion advice is
# `airmon-ng check kill`, which kills NetworkManager and wpa_supplicant — exactly Bjorn's uplink.
# Plain `iw` sets the same mode without touching any other interface.
#
# Kept dependency-free and separate from shared.py so the parsing/guard logic is unit-testable
# without constructing SharedData (which pulls in PIL / the e-Paper stack).
import shutil
import logging
import threading
import subprocess
from logger import Logger

logger = Logger(name="monitor_mode.py", level=logging.INFO)

# One radio, one capture. The scheduled WiFiScan and the web "Scan now" button are two independent
# consumers now, and they run on different threads: without this, a manual scan started mid-cycle
# would put the interface down underneath a running airodump and both captures would return
# nothing. Non-blocking on purpose — the second caller is told to come back, not queued behind a
# 30s+ capture holding an HTTP request open.
_radio_lock = threading.Lock()

# Who holds it. A bare lock answers "is it taken?"; that was enough while both consumers were
# 30-second captures, but the Bettercap hunter holds the radio for hours (docs/BETTERCAP_PLAN.md
# Stage A), and a consumer turned away needs to know *by whom* — to log something useful, and to
# tell "someone else is working" apart from "your config is wrong". Written while the lock is held,
# cleared before it is dropped, so a plain read is a consistent snapshot.
_radio_owner = ""

# acquire() reasons. The split callers actually consume is busy-vs-not: a held radio is a normal
# state to skip on, everything else is a real problem to report. "unsafe" and "failed" are kept
# apart because one means "this interface must never be used" and the other "this attempt broke".
BUSY, UNSAFE, FAILED = "busy", "unsafe", "failed"


def holder():
    """Which consumer holds the radio ("scan", "pwn", ...), or "" when it is free."""
    return _radio_owner


def _run(args, timeout=15):
    """Run a command, return (rc, stdout+stderr). rc=-1 when the binary is missing."""
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (subprocess.SubprocessError, OSError) as e:
        return -1, str(e)


def parse_default_route_iface(ip_route_output):
    """Interface name from `ip route show default` output, or "" if there is no default route.
    Pure/testable. Example line: 'default via 192.168.1.1 dev wlan0 proto dhcp metric 600'."""
    for line in ip_route_output.splitlines():
        parts = line.split()
        if parts[:1] == ["default"] and "dev" in parts:
            return parts[parts.index("dev") + 1]
    return ""


def default_route_iface():
    """The interface currently carrying Bjorn's uplink. "" when offline."""
    rc, out = _run(["ip", "route", "show", "default"])
    return parse_default_route_iface(out) if rc == 0 else ""


def parse_wireless_ifaces(iw_dev_output):
    """Wireless interface names from `iw dev` output. Pure/testable."""
    names = []
    for line in iw_dev_output.splitlines():
        stripped = line.strip()
        if stripped.startswith("Interface "):
            names.append(stripped.split(None, 1)[1])
    return names


def wireless_ifaces():
    """Wireless interfaces present on the box (for the web dropdown). [] if `iw` is missing."""
    rc, out = _run(["iw", "dev"])
    return parse_wireless_ifaces(out) if rc == 0 else []


def parse_supports_monitor(iw_info_output):
    """True when 'monitor' appears in the phy's supported interface modes. Pure/testable.
    `iw phy <phy> info` lists modes indented under a 'Supported interface modes:' heading; the
    word also appears elsewhere in the dump (e.g. software modes), so we only read that block."""
    in_modes = False
    for line in iw_info_output.splitlines():
        stripped = line.strip()
        if stripped.startswith("Supported interface modes:"):
            in_modes = True
            continue
        if in_modes:
            if stripped.startswith("*"):
                if stripped.lstrip("* ").strip() == "monitor":
                    return True
                continue
            break  # dedented out of the modes block
    return False


def supports_monitor(iface):
    """Whether this interface's phy can do monitor mode (drives the web 'test' button)."""
    rc, out = _run(["iw", "dev", iface, "info"])
    if rc != 0:
        return False
    phy = ""
    for line in out.splitlines():
        if "wiphy" in line:
            phy = "phy" + line.split()[-1]
            break
    if not phy:
        return False
    rc, info = _run(["iw", "phy", phy, "info"], timeout=20)
    return parse_supports_monitor(info) if rc == 0 else False


def check_usable(iface):
    """Why `iface` must not be put into monitor mode, or "" when it is safe. Pure guard logic
    lives in parse_* above; this is the one place that decides. Callers must treat a non-empty
    return as fatal for the scan — never as a warning to push past."""
    if not iface:
        return "no monitor interface configured (wifi_scan_iface)"
    # `iw` first: wireless_ifaces() is built from it, so without it every interface would look
    # non-wireless and the user would chase the wrong problem.
    if not shutil.which("iw"):
        return "`iw` not found (install iw)"
    uplink = default_route_iface()
    if iface == uplink:
        return (f"refusing to use {iface}: it carries Bjorn's default route. Monitor mode would "
                f"drop the web UI, reporting and IP scanning. Use a second radio (USB dongle).")
    if iface not in wireless_ifaces():
        return f"{iface} is not a wireless interface on this device"
    return ""


def acquire(iface, owner="scan"):
    """Put `iface` into monitor mode for `owner`. Returns (ok, detail, reason), where reason is
    "" on success or one of BUSY / UNSAFE / FAILED. Refuses the uplink interface.

    The reason exists so a caller can tell a *busy* radio (someone else is legitimately working —
    come back later, say nothing alarming) from an *unsafe* one (this interface must never be used;
    the operator has to fix something). Collapsing both into "it didn't work" is what made a
    dongle-less Pi log an error every cycle.

    NetworkManager is told to stop managing the interface first, otherwise it races us back to
    managed mode mid-capture. Only this interface is touched — the uplink keeps its manager.

    Holds the radio until release(); a second caller is refused rather than queued."""
    global _radio_owner
    problem = check_usable(iface)
    if problem:
        return False, problem, UNSAFE
    if not _radio_lock.acquire(blocking=False):
        return False, f"the radio is in use by {holder() or 'another consumer'}", BUSY
    _radio_owner = owner
    if shutil.which("nmcli"):
        _run(["nmcli", "device", "set", iface, "managed", "no"])
    for args in (["ip", "link", "set", iface, "down"],
                 ["iw", "dev", iface, "set", "type", "monitor"],
                 ["ip", "link", "set", iface, "up"]):
        rc, out = _run(args)
        if rc != 0:
            release(iface, owner)  # don't strand the radio half-configured
            return False, f"{' '.join(args)} failed: {out.strip()[:200]}", FAILED
    logger.info(f"{iface} is in monitor mode (held by {owner}).")
    return True, "monitor mode enabled", ""


def release(iface, owner="scan"):
    """Return `iface` to managed mode, hand it back to NetworkManager, and free the radio lock.
    Best-effort: this runs in a finally-block after a capture, so it never raises. Always the
    counterpart of a successful acquire() — releasing the lock last means the radio is fully back
    in managed mode before the next caller can take it.

    Only the owner may release. Without that check, a consumer that never acquired could hand back
    a radio another one is mid-capture on — and would drop that one's lock in the process, which is
    the exact interleaving the lock was added to prevent."""
    global _radio_owner
    if not iface:
        return
    if _radio_owner and _radio_owner != owner:
        logger.warning(f"{owner} tried to release {iface}, but {_radio_owner} holds it — ignoring.")
        return
    try:
        for args in (["ip", "link", "set", iface, "down"],
                     ["iw", "dev", iface, "set", "type", "managed"],
                     ["ip", "link", "set", iface, "up"]):
            _run(args)
        if shutil.which("nmcli"):
            _run(["nmcli", "device", "set", iface, "managed", "yes"])
        logger.info(f"{iface} returned to managed mode.")
    finally:
        _radio_owner = ""  # cleared before the lock drops, so holder() never names a stale owner
        if _radio_lock.locked():
            _radio_lock.release()
