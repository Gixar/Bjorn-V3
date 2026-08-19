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
import time
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


# ARPHRD codes as they appear in /sys/class/net/<iface>/type. 1 is Ethernet — the mode change has
# not reached the netdev — and the 80x family is what a capture needs. This is the exact value
# airodump-ng reads before it will start ("ARP linktype is set to 1 (Ethernet) ... Make sure RFMON
# is enabled"), which is why monitor mode is confirmed here rather than inferred from `iw`: `iw`
# reports the nl80211 interface type, which is already set while the netdev is still typed
# Ethernet, so it answers a slightly different question than the one that makes captures fail.
ARPHRD_80211 = (801, 802, 803)


def arphrd_type(iface):
    """The interface's ARPHRD code from sysfs, or 0 when it cannot be read (not Linux, or the
    interface vanished). Same source scanning.py reads operstate from."""
    try:
        with open(f"/sys/class/net/{iface}/type") as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return 0


def monitor_is_live(iface, timeout=3.0, poll=0.05, settle=0.4):
    """Wait until monitor mode has actually reached the netdev *and stayed there*. True when it has.

    `iw dev X set type monitor` returns before the driver has re-typed the interface, and the retype
    is not one clean transition: sampling /sys/class/net/wlan1/type every 10ms across six
    acquisitions on the Pi (2026-08-18) caught it oscillating 803 -> 1 -> 803 over roughly 100ms
    after `ip link set up`, with the Ethernet trough 30-50ms wide, on two of the six.

    Reading the right value once is therefore not enough — the first read can land on the opening
    803 blip, and a capture spawned on the strength of it opens the device during the trough and
    dies with 'ARP linktype is set to 1'. That is the intermittent failure 60001bc narrowed but did
    not close: observed 2026-08-17 on wlan1, and again 2026-08-18 07:51:45 *with* that fix
    deployed, where the retry five seconds later captured 4 APs on the same radio.

    So monitor mode has to *hold* for `settle` before the radio is handed over, and any read of
    Ethernet starts that clock again. `timeout` still bounds the whole wait, so a radio that never
    settles fails exactly as it did before.

    An unreadable type counts as usable, the same call release() makes for an unreadable mode: a
    missing sysfs must not veto a capture on a box where the check simply does not apply.
    """
    deadline = time.monotonic() + timeout
    held_since = None
    while True:
        code = arphrd_type(iface)
        if code == 0:
            return True
        if code in ARPHRD_80211:
            now = time.monotonic()
            if held_since is None:
                held_since = now
            elif now - held_since >= settle:
                return True
        else:
            held_since = None  # flipped back to Ethernet — the settle window starts over
        if time.monotonic() >= deadline:
            return False
        time.sleep(poll)


def parse_iface_mode(iw_info_output):
    """802.11 mode ("managed" / "monitor") from `iw dev <if> info`, or "". Pure/testable."""
    for line in iw_info_output.splitlines():
        parts = line.split()
        if parts[:1] == ["type"]:
            return parts[1] if len(parts) > 1 else ""
    return ""


def current_mode(iface):
    """The interface's current 802.11 mode, or "" when it cannot be read."""
    rc, out = _run(["iw", "dev", iface, "info"])
    return parse_iface_mode(out) if rc == 0 else ""


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
    # Verify, then retry once, then refuse — the same discipline release() already applies coming
    # back the other way. Three commands returning 0 is not the radio being in monitor mode, and
    # the difference is not academic: the caller spawns a capture the moment this returns True.
    for attempt in (1, 2):
        for args in (["ip", "link", "set", iface, "down"],
                     ["iw", "dev", iface, "set", "type", "monitor"],
                     ["ip", "link", "set", iface, "up"]):
            rc, out = _run(args)
            if rc != 0:
                release(iface, owner)  # don't strand the radio half-configured
                return False, f"{' '.join(args)} failed: {out.strip()[:200]}", FAILED
        if monitor_is_live(iface):
            logger.info(f"{iface} is in monitor mode (held by {owner}).")
            return True, "monitor mode enabled", ""
        if attempt == 1:
            logger.warning(f"{iface} is up but still typed Ethernet; redoing the mode change.")
    release(iface, owner)
    return False, (f"{iface} would not enter monitor mode (still ARPHRD {arphrd_type(iface)}) — a "
                   f"capture there fails with 'ARP linktype is set to 1'"), FAILED


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
    restored = False
    try:
        # Verify, then retry once, then shout. This used to run the three commands ignoring every
        # return code and log "returned to managed mode" unconditionally — so on 2026-08-08 a radio
        # left in monitor mode was reported as restored, and the only reason anyone noticed was the
        # verification script checking `iw dev` itself. Same class as the run report claiming
        # `WiFiScan: success=4` for an action that had never captured anything: a status line that
        # cannot fail tells you nothing. `iw set type` commonly fails with EBUSY for a moment after
        # a capture, which is exactly the case a single blind attempt loses.
        for attempt in (1, 2):
            for args in (["ip", "link", "set", iface, "down"],
                         ["iw", "dev", iface, "set", "type", "managed"],
                         ["ip", "link", "set", iface, "up"]):
                _run(args)
            if current_mode(iface) in ("managed", ""):
                restored = True
                break
            if attempt == 1:
                logger.warning(f"{iface} is still in monitor mode after release; retrying.")
                time.sleep(2)

        if shutil.which("nmcli"):
            _run(["nmcli", "device", "set", iface, "managed", "yes"])

        if restored:
            logger.info(f"{iface} returned to managed mode.")
        else:
            # Loud on purpose: the radio is off the network until someone fixes it, and the next
            # acquire() will happily re-monitor an interface that never came back.
            logger.error(f"{iface} is STILL in monitor mode after two release attempts — it is out "
                         f"of service until restored. Recover with: "
                         f"sudo iw dev {iface} set type managed && "
                         f"sudo nmcli device set {iface} managed yes")
    finally:
        _radio_owner = ""  # cleared before the lock drops, so holder() never names a stale owner
        if _radio_lock.locked():
            _radio_lock.release()
    # The lock is freed either way: a radio stuck in monitor mode must not also deadlock every
    # future consumer. acquire() re-runs `iw set type monitor` anyway, so the next capture can
    # still succeed on an interface that never came back.
    return restored
