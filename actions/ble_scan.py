"""ble_scan.py - BLE recon (backlog Wave 2 #6).

A standalone action, **on by default**: does a timed BLE/Bluetooth discovery via `bluetoothctl` (bluez, already
installed) and records nearby devices to data/output/scan_results/ble_devices.csv, flagging likely
trackers (AirTag/Tile/SmartTag...). Its own file, NOT netkb.csv — wireless (non-IP) entries don't fit
the netkb IP+Ports schema, and a self-contained file avoids destabilizing the core pipeline. No-op
unless `ble_scan_enabled` and `bluetoothctl` is present; throttled by `ble_scan_interval`, or by the
shorter `ble_scan_interval_offline` when there is no uplink and this is the only recon left running.

Tracker detection is two-stage: a cheap name heuristic, then — for devices the name didn't flag —
`bluetoothctl info <mac>`, matching the advertised service UUIDs / manufacturer data against the
known tracker signatures below (the OpenHaystack/AirGuard approach). Devices rename freely; the
advertisement doesn't.
"""
import os
import re
import csv
import time
import shutil
import logging
import subprocess
from datetime import datetime, timezone
from shared import SharedData
from logger import Logger
from csv_safe import sanitize_row
import offline_mode

logger = Logger(name="ble_scan.py", level=logging.INFO)

b_class = "BLEScan"
b_module = "ble_scan"
b_status = "ble_scan"
b_port = 0  # standalone action (BLE is not an IP/port target)
b_parent = None

TRACKER_HINTS = ("airtag", "tile", "smarttag", "smart tag", "chipolo", "find my", "findmy")
_ANSI = re.compile(r"\x1b\[[0-9;]*m")

# 16-bit BLE service UUIDs (as they appear in the 128-bit form bluetoothctl prints) that identify a
# tracker network. Only signatures specific to *finder* networks — Fast Pair (0xFE2C) is deliberately
# absent, plain headphones advertise it too.
TRACKER_UUIDS = {
    "0000fd44": "Apple Find My",
    "0000fd5a": "Samsung SmartTag",
    "0000feed": "Tile",
    "0000feec": "Tile",
}
APPLE_MFR_KEY = "0x004c"
APPLE_OFFLINE_FINDING = "12"  # Apple mfr-data payload type for an offline-finding (Find My) beacon


class BLEScan:
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self._last_scan = 0.0
        self.outfile = os.path.join(shared_data.scan_results_dir, "ble_devices.csv")
        logger.info("BLEScan initialized.")

    def execute(self):
        try:
            if not getattr(self.shared_data, "ble_scan_enabled", False):
                return 'skipped'
            binp = shutil.which("bluetoothctl")
            if not binp:
                logger.info("bluetoothctl not found (install bluez); skipping BLE scan.")
                return 'skipped'
            interval = getattr(self.shared_data, "ble_scan_interval", 300)
            if not offline_mode.is_online():
                # Same reasoning as WiFiScan's offline interval: 5 minutes is a cadence tuned for
                # "don't disturb the real job", and with no uplink there is no real job. BLE needs
                # no dongle, so offline this is often the *only* thing still collecting.
                interval = getattr(self.shared_data, "ble_scan_interval_offline", 60) or interval
            now = time.time()
            if interval and (now - self._last_scan) < interval:
                return 'skipped'  # throttled
            self._last_scan = now

            duration = max(3, int(getattr(self.shared_data, "ble_scan_duration", 10)))
            devices = self._scan(binp, duration)
            if devices is None:
                # No usable Bluetooth controller — the scan could not run, so this is not a
                # success (nor "nothing nearby"). Skip instead of reporting a hollow success
                # every cycle (#5: the WiFiScan: success=4 / status-line-that-cannot-fail class).
                return 'skipped'
            if devices:
                new_trackers = self._record(devices, binp)
                msg = f"BLE scan: {len(devices)} device(s)"
                if new_trackers:
                    msg += f", {new_trackers} flagged as tracker(s)"
                logger.success(msg + ".")
            return 'success'
        except Exception as e:
            logger.error(f"Error in BLE scan: {e}")
            return 'failed'

    def _scan(self, binp, duration):
        """Return [(mac, name)], or None when there is no usable Bluetooth controller.

        None is distinct from [] (scanned, nothing nearby): bluetoothctl `power on` prints
        'No default controller available' on a Pi with no adapter — the scan cannot run, and the
        caller skips rather than reporting success (#5)."""
        power = subprocess.run([binp, "power", "on"], capture_output=True, text=True, timeout=10)
        if "No default controller" in ((power.stdout or "") + (power.stderr or "")):
            logger.info("No Bluetooth controller available; skipping BLE scan.")
            return None
        subprocess.run([binp, "--timeout", str(duration), "scan", "on"],
                       capture_output=True, text=True, timeout=duration + 15)
        proc = subprocess.run([binp, "devices"], capture_output=True, text=True, timeout=15)
        return self._parse_devices(proc.stdout)

    @staticmethod
    def _parse_devices(output):
        """Parse `bluetoothctl devices` lines ('Device AA:BB:.. Name') -> [(mac, name)]. Pure."""
        devices = []
        for raw in output.splitlines():
            line = _ANSI.sub("", raw).strip()
            if line.startswith("Device "):
                parts = line.split(" ", 2)
                if len(parts) >= 2:
                    devices.append((parts[1], parts[2] if len(parts) > 2 else ""))
        return devices

    @staticmethod
    def _is_tracker(name):
        n = (name or "").lower()
        return any(h in n for h in TRACKER_HINTS)

    @staticmethod
    def _tracker_from_info(output):
        """Tracker label from a `bluetoothctl info <mac>` dump, or "" if it looks like an ordinary
        device. Matches a known finder-network service UUID, or Apple manufacturer data whose first
        payload byte is the offline-finding type. Pure/testable."""
        lines = [_ANSI.sub("", raw).strip() for raw in output.splitlines()]
        for line in lines:
            low = line.lower()
            for uuid, label in TRACKER_UUIDS.items():
                if uuid in low:
                    return label
        for i, line in enumerate(lines):
            low = line.lower()
            if not ("manufacturerdata key" in low and APPLE_MFR_KEY in low):
                continue
            # The value follows within the next couple of lines, either inline
            # ("Value: 0x12 0x19 …") or on its own line under a bare "Value:" label.
            for nxt in lines[i + 1:i + 3]:
                if "manufacturerdata value" not in nxt.lower():
                    continue
                payload = nxt.split(":", 1)[-1].strip() or (
                    lines[i + 2].strip() if i + 2 < len(lines) else "")
                tokens = payload.lower().replace("0x", "").split()
                if tokens and tokens[0] == APPLE_OFFLINE_FINDING:
                    return "Apple Find My"
                break
        return ""

    def _device_info(self, binp, mac):
        """Raw `bluetoothctl info <mac>` output; "" if the call fails (device gone, BlueZ busy)."""
        try:
            return subprocess.run([binp, "info", mac], capture_output=True, text=True,
                                  timeout=8).stdout
        except (subprocess.SubprocessError, OSError) as e:
            logger.debug(f"bluetoothctl info {mac} failed: {e}")
            return ""

    def _load(self):
        by_mac = {}
        try:
            with open(self.outfile, newline="") as f:
                for row in csv.DictReader(f):
                    if row.get("MAC"):
                        by_mac[row["MAC"]] = row
        except FileNotFoundError:
            pass
        return by_mac

    def _record(self, devices, binp=None):
        by_mac = self._load()
        now = datetime.now(timezone.utc).isoformat()
        new_trackers = 0
        for mac, name in devices:
            prev = by_mac.get(mac, {})
            name = name or prev.get("Name", "")
            kind = "name match" if self._is_tracker(name) else ""
            if not kind and binp:  # only pay for the extra call when the name says nothing
                kind = self._tracker_from_info(self._device_info(binp, mac))
            if kind and prev.get("Tracker") != "yes":
                new_trackers += 1
            by_mac[mac] = {"MAC": mac, "Name": name, "Tracker": "yes" if kind else "",
                           "TrackerType": kind,
                           "FirstSeen": prev.get("FirstSeen", now), "LastSeen": now}
        self._write(by_mac)
        return new_trackers

    def _write(self, by_mac):
        os.makedirs(os.path.dirname(self.outfile), exist_ok=True)
        cols = ["MAC", "Name", "Tracker", "TrackerType", "FirstSeen", "LastSeen"]
        with open(self.outfile, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(cols)
            for row in by_mac.values():
                w.writerow(sanitize_row([row.get(c, "") for c in cols]))


if __name__ == "__main__":
    BLEScan(SharedData()).execute()
