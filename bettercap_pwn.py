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
import re
import csv
import json
import shutil
import logging
import tempfile
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


def build_cmd(iface, outdir, binary="bettercap", channel=0):
    """The bettercap argv for a hunting session. Pure/testable.

    `-eval` rather than a caplet file: the handshake path contains today's date, and a caplet is a
    static file with no clean way to take one. Passing the same statements on the command line
    removes the file, the templating and the question of where it was installed.

    `wifi.handshakes.aggregate false` writes one PCAP per AP instead of a single growing file —
    per-AP is what hashcat wants, and it means a corrupt capture costs one network, not all of them.

    `channel` (0 = hop) parks the radio where the survey says the unclaimed targets are.
    NOTE: `wifi.recon.channel` is the one bettercap setting name here that has not been confirmed
    against a running daemon. It is emitted only when a channel was actually chosen, so an install
    where the name is wrong degrades to hopping rather than failing to hunt.
    """
    statements = [
        f"set wifi.handshakes.file {outdir}",
        "set wifi.handshakes.aggregate false",
    ]
    if channel:
        statements.append(f"set wifi.recon.channel {int(channel)}")
    statements.append("wifi.recon on")
    return [binary, "-no-colors", "-iface", iface, "-eval", "; ".join(statements)]


# ---------------------------------------------------------------------------
# The loot index (step C3)
# ---------------------------------------------------------------------------
# Capture files are matched by *shape*, not by a filename format anyone has confirmed. bettercap's
# naming for per-AP handshake files is version-specific and undocumented, and the failure mode of
# guessing wrong is an index that stays empty while PCAPs pile up on disk. So: any MAC-shaped token
# in the name is the BSSID, whatever is left is the ESSID, and a file with neither still gets
# indexed under its own name. Wrong-but-tolerant beats right-in-theory here — and when a real
# filename is in hand, this regex is the one place to correct.
CAPTURE_SUFFIXES = (".pcap", ".pcapng", ".cap")
# The lookarounds are load-bearing, not decoration. Without them "Cafe-aa-bb-cc-dd-ee-02" matches
# starting inside the ESSID — "fe-aa-bb-cc-dd-ee" is a perfectly good MAC shape — and yields the
# BSSID FE:AA:BB:CC:DD:EE with an ESSID of "Ca-02". Any hex-looking ESSID (cafe, beef, dead, ace)
# hits this. Requiring a non-hex character on both sides forces the match onto a whole token.
_MAC_IN_NAME = re.compile(r"(?<![0-9a-f])([0-9a-f]{2}(?:[:-][0-9a-f]{2}){5})(?![0-9a-f])", re.I)


def parse_capture_name(filename):
    """(bssid, essid) from a capture filename. Pure/testable. Either may be "".

    The BSSID is normalised to upper-case colon form so it matches netkb and the Wi-Fi survey CSVs,
    which is the whole point of extracting it — a lower-case dashed MAC would silently fail to join
    against anything else Bjorn knows.
    """
    stem = os.path.splitext(os.path.basename(filename))[0]
    match = _MAC_IN_NAME.search(stem)
    if not match:
        return "", stem.strip(" _-")
    bssid = match.group(1).replace("-", ":").upper()
    essid = (stem[:match.start()] + stem[match.end():]).strip(" _-")
    return bssid, essid


def find_captures(base_dir):
    """Every capture file under <base>/raw/, newest last. Returns [(path, mtime)]."""
    root = os.path.join(base_dir, "raw")
    found = []
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            if name.lower().endswith(CAPTURE_SUFFIXES):
                path = os.path.join(dirpath, name)
                try:
                    found.append((path, os.path.getmtime(path)))
                except OSError:
                    continue
    return sorted(found, key=lambda item: item[1])


def build_index(base_dir, previous=None, now=None):
    """Merge what is on disk into the previous index. Pure apart from reading the directory.

    Keyed by path, because the path is the only identity a capture file actually has: bettercap may
    reopen the same AP's file across sessions, and re-indexing must not invent a second entry for
    it. `first_seen` is preserved from the previous index for exactly that reason — it is the field
    that tells you when you caught something, and recomputing it every scan would make every
    handshake look like it arrived today.
    """
    previous = previous or {}
    stamp = (now or datetime.now()).isoformat(timespec="seconds")
    entries = {}
    for path, mtime in find_captures(base_dir):
        bssid, essid = parse_capture_name(path)
        prior = previous.get(path, {})
        entry = {
            "path": path,
            "bssid": bssid,
            "essid": essid or prior.get("essid", ""),
            "bytes": _size(path),
            "first_seen": prior.get("first_seen") or stamp,
            "last_seen": datetime.fromtimestamp(mtime).isoformat(timespec="seconds"),
        }
        # Preserve upload/completeness state across re-indexes (wpa-sec upload loop).
        for field in ("uploaded", "complete", "hc22000"):
            if prior.get(field):
                entry[field] = prior[field]
        entries[path] = entry
    return entries


def _size(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def index_path(base_dir):
    return os.path.join(base_dir, "index.json")


def load_index(base_dir):
    try:
        with open(index_path(base_dir)) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}
    entries = data.get("captures") if isinstance(data, dict) else None
    return entries if isinstance(entries, dict) else {}


def update_index(shared_data, now=None):
    """Rescan the loot directory and persist index.json. Returns the summary dict.

    Written only when something changed — this runs after every hunting session on a device whose
    storage is an SD card, and rewriting an identical file is pure wear. Same discipline as
    stats_engine._atomic_write, including the temp-file-and-rename so a crash mid-write cannot
    leave a truncated index behind.
    """
    base = getattr(shared_data, "handshakes_dir", None) or os.path.join("data", "output", "handshakes")
    previous = load_index(base)
    entries = build_index(base, previous, now)
    summary = {
        "captures": len(entries),
        "unique_bssids": len({e["bssid"] for e in entries.values() if e["bssid"]}),
        "bytes": sum(e["bytes"] for e in entries.values()),
    }
    # Coins count UNIQUE APs, not capture files: two captures of one network is one network owned.
    # stats_engine is a high-water mark, so this only ever pushes the score up.
    try:
        shared_data.handshakenbr = summary["unique_bssids"]
    except AttributeError:
        pass

    if entries != previous:
        _write_index(base, entries, summary)
        logger.info(f"Handshake index: {summary['captures']} capture(s), "
                    f"{summary['unique_bssids']} unique AP(s).")
    return summary


def _write_index(base, entries, summary):
    os.makedirs(base, exist_ok=True)
    payload = {"version": 1, "updated": datetime.now().isoformat(timespec="seconds"),
               **summary, "captures": entries}
    fd, tmp = tempfile.mkstemp(dir=base, prefix=".index-", suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f, indent=2)
        os.replace(tmp, index_path(base))
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# Target scoring (step E1)
# ---------------------------------------------------------------------------
# Scored from wifi_aps.csv / wifi_clients.csv — the airodump survey, which is already verified on
# hardware — and NOT from bettercap's own event stream, whose schema is still unconfirmed. Same
# shape as action_planner: pure functions over dicts, weighted signals, and a reason string that
# reaches the display, so the pick can always be explained.
CLIENTS_BONUS = 45     # dominant signal: a WPA handshake happens when a client (re)associates
WPA_BONUS = 10         # WPA/WPA2 PSK is the crackable case
WEP_BONUS = 4
DEFAULT_MIN_RSSI = -80


def _read_csv_rows(path):
    try:
        with open(path, newline="", errors="replace") as f:
            return list(csv.DictReader(f))
    except OSError:
        return []


def signal_bonus(power):
    """0-30 from dBm. Closer APs are worth more: a handshake needs to be *heard*, and a -85 dBm
    beacon usually means the client side of the exchange is inaudible even when the AP is not."""
    try:
        dbm = int(str(power).strip())
    except (TypeError, ValueError):
        return 0
    return max(0, min(30, (dbm + 90) // 2))


def score_targets(aps, clients, owned_bssids=(), min_rssi=DEFAULT_MIN_RSSI):
    """Rank APs worth hunting. Pure/testable. Returns [{bssid, essid, channel, score, reason}].

    Three exclusions, each because the target cannot pay:
      - **Already captured.** A second handshake for a network we hold adds nothing.
      - **Open networks.** No PSK, so there is no four-way handshake to catch. Nothing to crack.
      - **Too weak.** Below min_rssi the client half of the exchange is usually unhearable.
    """
    owned = {b.upper() for b in owned_bssids if b}
    with_clients = {(row.get("BSSID") or "").upper() for row in clients}
    ranked = []
    for ap in aps:
        bssid = (ap.get("BSSID") or "").strip().upper()
        if not bssid or bssid in owned:
            continue
        privacy = (ap.get("Privacy") or "").upper()
        if "WPA" not in privacy and "WEP" not in privacy:
            continue                                   # OPN / blank: no PSK, no handshake
        try:
            if int(str(ap.get("Power", "0")).strip()) < int(min_rssi):
                continue
        except (TypeError, ValueError):
            pass                                       # unreadable power: judge it on the rest

        reasons = []
        score = signal_bonus(ap.get("Power"))
        if score:
            reasons.append(f"{ap.get('Power')}dBm")
        if bssid in with_clients:
            score += CLIENTS_BONUS
            reasons.append("has clients")
        else:
            reasons.append("no clients seen")
        if "WPA" in privacy:
            score += WPA_BONUS
        elif "WEP" in privacy:
            score += WEP_BONUS
        reasons.append(privacy.split()[0] if privacy.split() else privacy)

        ranked.append({
            "bssid": bssid,
            "essid": (ap.get("ESSID") or "").strip(),
            "channel": _int_or_zero(ap.get("Channel")),
            "score": score,
            "reason": ", ".join(reasons),
        })
    ranked.sort(key=lambda t: t["score"], reverse=True)
    return ranked


def _int_or_zero(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return 0


def pick_channel(ranked):
    """(channel, why). 0 means "keep hopping".

    Parks the radio where the unclaimed value is, summing the scores per channel rather than
    taking the single best AP: three mediocre targets on channel 6 beat one good one on channel 11,
    because the radio can only hear one channel at a time and a session is minutes long. Hopping
    stays the answer when there is nothing to aim at — being blind everywhere beats being parked on
    a channel with nothing on it.
    """
    totals = {}
    for target in ranked:
        if target["channel"]:
            totals[target["channel"]] = totals.get(target["channel"], 0) + target["score"]
    if not totals:
        return 0, "no known targets — hopping"
    channel = max(totals, key=lambda ch: totals[ch])
    count = sum(1 for t in ranked if t["channel"] == channel)
    return channel, f"channel {channel}: {count} target(s), score {totals[channel]}"


def plan_session(shared_data):
    """What this hunting session should aim at. Returns (channel, why, ranked)."""
    scan_dir = getattr(shared_data, "scan_results_dir", "")
    aps = _read_csv_rows(os.path.join(scan_dir, "wifi_aps.csv"))
    clients = _read_csv_rows(os.path.join(scan_dir, "wifi_clients.csv"))
    base = getattr(shared_data, "handshakes_dir", None) or ""
    owned = {e.get("bssid", "") for e in load_index(base).values()}
    min_rssi = getattr(shared_data, "bettercap_pwn_min_rssi", DEFAULT_MIN_RSSI)
    ranked = score_targets(aps, clients, owned, min_rssi)
    channel, why = pick_channel(ranked)
    return channel, why, ranked


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
        self.plan = ""

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
            channel, why, ranked = plan_session(self.shared_data)
            cmd = build_cmd(iface, outdir, channel=channel)
            self.proc = self._spawn(cmd)
            self.iface = iface
            self.started_at = datetime.now()
            self.plan = why
            logger.info(f"Hunting on {iface}; {why}; handshakes -> {outdir}")
            if ranked:
                top = ranked[0]
                logger.info(f"Top target: {top['essid'] or top['bssid']} "
                            f"({top['reason']}, score={top['score']})")
            return True, f"hunting on {iface} — {why}"
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

        # Index what the session caught, now that bettercap has closed its files. Best-effort: a
        # failure here loses a catalogue entry, not the PCAP, and must not turn a clean stop into a
        # reported failure — the return value below is about the radio.
        try:
            summary = update_index(self.shared_data)
        except Exception as e:                  # noqa: BLE001
            logger.error(f"Could not update the handshake index: {e}")
            summary = {}

        caught = f", {summary['captures']} capture(s) on disk" if summary else ""
        return (True, f"stopped; {iface} back in managed mode{caught}") if restored \
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
