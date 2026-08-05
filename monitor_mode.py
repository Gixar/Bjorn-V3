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
import subprocess
from logger import Logger

logger = Logger(name="monitor_mode.py", level=logging.INFO)


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


def acquire(iface):
    """Put `iface` into monitor mode. Returns (ok, detail). Refuses the uplink interface.

    NetworkManager is told to stop managing the interface first, otherwise it races us back to
    managed mode mid-capture. Only this interface is touched — the uplink keeps its manager."""
    problem = check_usable(iface)
    if problem:
        return False, problem
    if shutil.which("nmcli"):
        _run(["nmcli", "device", "set", iface, "managed", "no"])
    for args in (["ip", "link", "set", iface, "down"],
                 ["iw", "dev", iface, "set", "type", "monitor"],
                 ["ip", "link", "set", iface, "up"]):
        rc, out = _run(args)
        if rc != 0:
            release(iface)  # don't strand the radio half-configured
            return False, f"{' '.join(args)} failed: {out.strip()[:200]}"
    logger.info(f"{iface} is in monitor mode.")
    return True, "monitor mode enabled"


def release(iface):
    """Return `iface` to managed mode and hand it back to NetworkManager. Best-effort: this runs
    in a finally-block after a capture, so it never raises."""
    if not iface:
        return
    for args in (["ip", "link", "set", iface, "down"],
                 ["iw", "dev", iface, "set", "type", "managed"],
                 ["ip", "link", "set", iface, "up"]):
        _run(args)
    if shutil.which("nmcli"):
        _run(["nmcli", "device", "set", iface, "managed", "yes"])
    logger.info(f"{iface} returned to managed mode.")


# ponytail: no lock — WiFiScan is the only consumer today. When a second one lands (bettercap
# monitor mode, deauth, evil twin), the mutex goes here around acquire/release, not at the call
# sites; that is the whole reason acquisition is funnelled through this module.
