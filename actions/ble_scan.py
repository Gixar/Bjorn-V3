"""ble_scan.py - BLE recon (backlog Wave 2 #6).

A standalone action (opt-in): does a timed BLE/Bluetooth discovery via `bluetoothctl` (bluez, already
installed) and records nearby devices to data/output/scan_results/ble_devices.csv, flagging likely
trackers (AirTag/Tile/SmartTag...). Its own file, NOT netkb.csv — wireless (non-IP) entries don't fit
the netkb IP+Ports schema, and a self-contained file avoids destabilizing the core pipeline. No-op
unless `ble_scan_enabled` and `bluetoothctl` is present; throttled by `ble_scan_interval`.

ponytail: name-based tracker heuristic only. Robust FindMy detection needs the BLE manufacturer data
(0x004C Apple / service UUIDs) via `bluetoothctl info <mac>` per device — a follow-up if needed.
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

logger = Logger(name="ble_scan.py", level=logging.INFO)

b_class = "BLEScan"
b_module = "ble_scan"
b_status = "ble_scan"
b_port = 0  # standalone action (BLE is not an IP/port target)
b_parent = None

TRACKER_HINTS = ("airtag", "tile", "smarttag", "smart tag", "chipolo", "find my", "findmy")
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


class BLEScan:
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self._last_scan = 0.0
        self.outfile = os.path.join(shared_data.scan_results_dir, "ble_devices.csv")
        logger.info("BLEScan initialized.")

    def execute(self):
        try:
            if not getattr(self.shared_data, "ble_scan_enabled", False):
                return 'success'
            binp = shutil.which("bluetoothctl")
            if not binp:
                logger.info("bluetoothctl not found (install bluez); skipping BLE scan.")
                return 'success'
            interval = getattr(self.shared_data, "ble_scan_interval", 300)
            now = time.time()
            if interval and (now - self._last_scan) < interval:
                return 'success'  # throttled
            self._last_scan = now

            duration = max(3, int(getattr(self.shared_data, "ble_scan_duration", 10)))
            devices = self._scan(binp, duration)
            if devices:
                new_trackers = self._record(devices)
                msg = f"BLE scan: {len(devices)} device(s)"
                if new_trackers:
                    msg += f", {new_trackers} flagged as tracker(s)"
                logger.success(msg + ".")
            return 'success'
        except Exception as e:
            logger.error(f"Error in BLE scan: {e}")
            return 'failed'

    def _scan(self, binp, duration):
        subprocess.run([binp, "power", "on"], capture_output=True, text=True, timeout=10)
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

    def _record(self, devices):
        by_mac = self._load()
        now = datetime.now(timezone.utc).isoformat()
        new_trackers = 0
        for mac, name in devices:
            prev = by_mac.get(mac, {})
            name = name or prev.get("Name", "")
            is_tracker = self._is_tracker(name)
            if is_tracker and prev.get("Tracker") != "yes":
                new_trackers += 1
            by_mac[mac] = {"MAC": mac, "Name": name, "Tracker": "yes" if is_tracker else "",
                           "FirstSeen": prev.get("FirstSeen", now), "LastSeen": now}
        self._write(by_mac)
        return new_trackers

    def _write(self, by_mac):
        os.makedirs(os.path.dirname(self.outfile), exist_ok=True)
        cols = ["MAC", "Name", "Tracker", "FirstSeen", "LastSeen"]
        with open(self.outfile, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(cols)
            for row in by_mac.values():
                w.writerow(sanitize_row([row.get(c, "") for c in cols]))


if __name__ == "__main__":
    BLEScan(SharedData()).execute()
