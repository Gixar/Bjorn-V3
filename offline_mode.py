# offline_mode.py
# What Bjorn does when it has no uplink.
#
# Until now the orchestrator had no idea whether it was connected to anything: with no network it
# kept sweeping an empty netkb on a Pi Zero forever, producing nothing. Offline is not a fault
# state — it is the state Bjorn is *carried around* in, and it is the one where 802.11/BLE recon is
# the only work that still pays. So when the default route disappears we stop the IP sweep, run the
# wireless recon that needs no target, and try to get back on a network.
#
# Two rules this module exists to keep:
#   1. Never take the uplink down to do recon. Enforced upstream by monitor_mode.check_usable(),
#      which refuses the default-route interface. That guard is also why the onboard radio becomes
#      *eligible* while offline (no default route -> not the uplink) — pick_scan_iface() only ever
#      returns a fallback when there is genuinely nothing to lose, and prefers the dongle always.
#   2. Recon first, reconnect second. A capture leaves the radio in monitor mode; reconnecting on a
#      radio still in monitor mode silently fails. The orchestrator calls these in that order, and
#      WiFiScan releases in a finally-block, so the radio is always back in managed mode first.
#
# Parsing and choosing are pure functions (testable without a radio); only reconnect() shells out.
import time
import shutil
import logging
import subprocess

import monitor_mode
from logger import Logger

logger = Logger(name="offline_mode.py", level=logging.INFO)


def _run(args, timeout=30):
    """Run a command, return (rc, stdout). rc=-1 when the binary is missing or the call blows up."""
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "")
    except (subprocess.SubprocessError, OSError) as e:
        return -1, str(e)


def is_online():
    """True when a default route exists. Deliberately 'has an uplink', not 'has Wi-Fi': a USB or
    wired route is just as good for reporting, and neither should trigger offline recon."""
    return bool(monitor_mode.default_route_iface())


def pick_scan_iface(configured, wireless, uplink):
    """Which radio may be used for a monitor-mode capture, or "" when none may. Pure/testable.

    Order: the configured radio if it is present and is not the uplink, else any other radio that
    is not the uplink, else nothing.

    The safety property is carried entirely by `name != uplink`, and that is the whole trick: the
    onboard radio becomes eligible when offline not through a special case, but because with no
    default route nothing is the uplink. An earlier version also refused to fall back whenever an
    uplink existed — which added a state (online, dongle present, config blank or pointing at the
    uplink -> scan nothing) without adding any safety the line below doesn't already give."""
    if configured and configured in wireless and configured != uplink:
        return configured
    for name in wireless:
        if name != uplink:
            return name
    return ""


def scan_iface(shared_data):
    """The radio WiFiScan should use right now. The single resolution point for both callers (the
    scheduled action and the web 'Scan now' button) — two copies of this would drift, and the one
    that drifted would be the one that borrows the uplink."""
    configured = (getattr(shared_data, "wifi_scan_iface", "") or "").strip()
    return pick_scan_iface(configured, monitor_mode.wireless_ifaces(),
                           monitor_mode.default_route_iface())


def uplink_candidate(wireless, scan_iface):
    """Which radio should try to carry the uplink. Pure/testable.

    The dongle is reserved for capture when there is more than one radio, so the onboard chip is
    the one that reconnects. With a single radio it does both jobs — sequentially, never at once."""
    for name in wireless:
        if name != scan_iface:
            return name
    return wireless[0] if wireless else ""


def reconnect_best(shared_data):
    """Pick the uplink radio from config + what is present, then try to join. (ok, detail)."""
    iface = uplink_candidate(monitor_mode.wireless_ifaces(),
                             (getattr(shared_data, "wifi_scan_iface", "") or "").strip())
    return reconnect(iface, allow_open=getattr(shared_data, "wifi_autojoin_open", False))


def _split_escaped(line, sep=":"):
    """Split one `nmcli -t` record. nmcli escapes the separator inside values as '\\:' (SSIDs may
    contain colons), so a plain split() would shred those names into extra fields."""
    out, cur, esc = [], "", False
    for ch in line:
        if esc:
            cur += ch
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == sep:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    out.append(cur)
    return out


def parse_nmcli_wifi(out):
    """Parse `nmcli -t -f IN-USE,SSID,SIGNAL,SECURITY device wifi list` into dicts. Pure/testable.

    Hidden networks come back with an empty SSID and are dropped — there is nothing to connect to
    by name. `security` is empty for an open network, which is the whole signal this module needs."""
    nets = []
    for line in out.splitlines():
        if not line.strip():
            continue
        cells = _split_escaped(line.strip())
        if len(cells) < 4:
            continue
        in_use, ssid, signal, security = cells[0], cells[1], cells[2], ":".join(cells[3:])
        if not ssid:
            continue
        try:
            signal = int(signal)
        except ValueError:
            signal = 0
        nets.append({
            "ssid": ssid,
            "signal": signal,
            "security": security.strip(),
            "open": security.strip() == "",
            "in_use": in_use.strip() == "*",
        })
    return nets


def choose_network(networks, saved, allow_open):
    """Pick what to join: the strongest *saved* network in range, else — only if explicitly
    allowed — the strongest open one. Pure/testable.

    Saved always wins over a stronger open AP: a network the operator has already authorized is
    never the riskier choice, and joining someone's open AP is a posture decision, not a
    connectivity optimisation."""
    visible = sorted(networks, key=lambda n: n["signal"], reverse=True)
    for net in visible:
        if net["ssid"] in saved:
            return net
    if allow_open:
        for net in visible:
            if net["open"]:
                return net
    return None


def saved_ssids():
    """SSIDs Bjorn already has a Wi-Fi profile for (including any injected by WpaSecImport).
    nmcli names wireless profiles after the SSID, which is what `connection up id` matches."""
    rc, out = _run(["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"])
    if rc != 0:
        return set()
    names = set()
    for line in out.splitlines():
        cells = _split_escaped(line.strip())
        if len(cells) >= 2 and "wireless" in cells[-1]:
            names.add(cells[0])
    return names


def reconnect(iface, allow_open=False, settle=12):
    """Try to regain an uplink on `iface`. Returns (ok, detail).

    Called only when offline, and only after any capture has released the radio — nmcli cannot
    associate an interface that is still in monitor mode, and the failure is silent, so the
    ordering is the caller's contract, checked here as a guard rather than assumed."""
    if not shutil.which("nmcli"):
        return False, "nmcli not found"
    if not iface:
        return False, "no wireless interface"

    mode = _iface_mode(iface)
    if mode and mode != "managed":
        return False, f"{iface} is in {mode} mode — release it before reconnecting"

    _run(["nmcli", "device", "set", iface, "managed", "yes"])
    _run(["nmcli", "device", "wifi", "rescan", "ifname", iface], timeout=45)  # fails if too soon; harmless
    rc, out = _run(["nmcli", "-t", "-f", "IN-USE,SSID,SIGNAL,SECURITY", "device", "wifi", "list",
                    "ifname", iface])
    if rc != 0:
        return False, "could not list networks"

    networks = parse_nmcli_wifi(out)
    target = choose_network(networks, saved_ssids(), allow_open)
    if not target:
        return False, f"nothing joinable in range ({len(networks)} AP(s) seen)"

    if target["ssid"] in saved_ssids():
        rc, out = _run(["nmcli", "connection", "up", "id", target["ssid"], "ifname", iface],
                       timeout=60)
        how = "saved profile"
    else:
        rc, out = _run(["nmcli", "device", "wifi", "connect", target["ssid"], "ifname", iface],
                       timeout=60)
        how = "open network"

    if rc != 0:
        return False, f"{target['ssid']}: connect failed"

    # nmcli returns as soon as the profile activates; the default route lands a moment later, and
    # "connected but no route" is not online for any purpose Bjorn has.
    deadline = time.time() + settle
    while time.time() < deadline:
        if is_online():
            return True, f"joined {target['ssid']} ({how}, signal {target['signal']})"
        time.sleep(1)
    return False, f"{target['ssid']}: associated but no default route after {settle}s"


def _iface_mode(iface):
    """Current 802.11 mode of an interface ("managed" / "monitor"), or "" if unknown."""
    rc, out = _run(["iw", "dev", iface, "info"])
    if rc != 0:
        return ""
    for line in out.splitlines():
        parts = line.split()
        if parts[:1] == ["type"]:
            return parts[1] if len(parts) > 1 else ""
    return ""
