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
import os
import shutil
import logging
import subprocess
from datetime import datetime

import monitor_mode
import offline_mode
from logger import Logger

logger = Logger(name="bettercap_pwn.py", level=logging.INFO)

# The owner label this module takes the radio under. Distinct from WiFiScan's "scan" so a blocked
# consumer can say who is holding it, and so release() refuses a cross-owner hand-back.
RADIO_OWNER = "pwn"

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


def handshake_dir(shared_data, when=None):
    """Where this session's captures land: <output>/handshakes/raw/YYYY-MM-DD/. Created on demand.

    Dated because a flat directory of PCAPs is unusable after a week of carrying the thing around,
    and because "what did I catch on Tuesday" is the question people actually ask of this loot.
    """
    base = getattr(shared_data, "handshakes_dir", None) or os.path.join("data", "output", "handshakes")
    path = os.path.join(base, "raw", (when or datetime.now()).strftime("%Y-%m-%d"))
    os.makedirs(path, exist_ok=True)
    return path


def build_cmd(iface, outdir, binary="bettercap"):
    """The bettercap argv for a hunting session. Pure/testable.

    `-eval` rather than a caplet file: the handshake path contains today's date, and a caplet is a
    static file with no clean way to take one. Passing the same statements on the command line
    removes the file, the templating and the question of where it was installed.

    `wifi.handshakes.aggregate false` writes one PCAP per AP instead of a single growing file —
    per-AP is what hashcat wants, and it means a corrupt capture costs one network, not all of them.
    """
    eval_stmts = "; ".join([
        f"set wifi.handshakes.file {outdir}",
        "set wifi.handshakes.aggregate false",
        "wifi.recon on",
    ])
    return [binary, "-no-colors", "-iface", iface, "-eval", eval_stmts]


class Hunter:
    """Owns the radio and the bettercap process for one hunting session.

    The two lifetimes are deliberately identical. bettercap here is NOT the systemd unit that
    Stage B provisions — that one is the long-lived managed-mode daemon, and it must not be
    reconfigured underneath its own poller. The hunter's process lives exactly as long as its radio
    lease, which is what makes "stop() puts the radio back" a statement about one object rather
    than a coordination problem between systemd and a lock.
    """

    def __init__(self, shared_data, spawn=None):
        self.shared_data = shared_data
        self._spawn = spawn or (lambda cmd: subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        self.proc = None
        self.iface = ""
        self.started_at = None

    def is_running(self):
        return self.proc is not None and self.proc.poll() is None

    def start(self):
        """Begin a session. Returns (ok, detail). Never leaves the radio held on failure."""
        if self.is_running():
            return False, f"already hunting on {self.iface}"

        ok, reason, iface = can_start(self.shared_data)
        if not ok:
            return False, reason

        got, detail, _why = monitor_mode.acquire(iface, owner=RADIO_OWNER)
        if not got:
            return False, detail

        # Everything from here holds the radio, so every failure path must give it back. Without
        # this the first bettercap that fails to exec would strand the radio in monitor mode — the
        # exact fault the 2026-08-08 run found in WiFiScan's release path.
        try:
            outdir = handshake_dir(self.shared_data)
            cmd = build_cmd(iface, outdir)
            self.proc = self._spawn(cmd)
            self.iface = iface
            self.started_at = datetime.now()
            logger.info(f"Hunting on {iface}; handshakes -> {outdir}")
            return True, f"hunting on {iface}"
        except Exception as e:
            monitor_mode.release(iface, owner=RADIO_OWNER)
            self.proc, self.iface = None, ""
            logger.error(f"Could not start bettercap: {e}")
            return False, f"could not start bettercap: {e}"

    def stop(self, timeout=10):
        """End the session and give the radio back. Returns (ok, detail).

        `ok` reflects the RADIO, not the process: a bettercap that needed killing is untidy, but a
        radio left in monitor mode is what takes Bjorn off the air. release() verifies the mode
        itself now, so this reports what actually happened rather than that it tried.
        """
        iface = self.iface
        try:
            if self.proc is not None and self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    logger.warning("bettercap ignored SIGTERM; killing it.")
                    self.proc.kill()
                    self.proc.wait(timeout=timeout)
        except Exception as e:                  # noqa: BLE001 - the radio still has to come back
            logger.error(f"Error stopping bettercap: {e}")
        finally:
            self.proc = None
            self.iface = ""
            self.started_at = None
            restored = monitor_mode.release(iface, owner=RADIO_OWNER) if iface else True

        if not iface:
            return True, "was not running"
        return (True, f"stopped; {iface} back in managed mode") if restored \
            else (False, f"stopped, but {iface} is STILL in monitor mode — see monitor_mode log")

    def status(self):
        """Measured, not remembered: `is_running` polls the process rather than trusting a flag
        set at start time. A status that cannot report its own failure is the defect this codebase
        keeps rediscovering."""
        running = self.is_running()
        return {
            "running": running,
            "iface": self.iface if running else "",
            "since": self.started_at.isoformat(timespec="seconds") if running and self.started_at else "",
            "holder": monitor_mode.holder(),
        }


def describe(shared_data):
    """One line for the web panel / logs. Never raises — a status probe that can fail is useless."""
    try:
        ok, reason, iface = can_start(shared_data)
    except Exception as e:                      # noqa: BLE001 - a status call must not take a page down
        logger.error(f"Hunter status check failed: {e}")
        return f"status unavailable: {e}"
    return reason if not ok else f"ready ({iface})"
