"""wifi_scan.py - passive Wi-Fi AP/client recon via airodump-ng (backlog Wave 4).

A standalone action (opt-in): puts the *second* radio into monitor mode, runs a timed airodump-ng
capture, and records nearby access points and clients to data/output/scan_results/wifi_aps.csv and
wifi_clients.csv. Own files, NOT netkb.csv — same call as BLEScan: 802.11-layer discoveries have no
IP or ports, so they don't fit the netkb schema.

Why airodump-ng and not bettercap's wifi.recon: airodump writes a plain CSV, which is the same
"external process + parse its output" pattern already used for nmap/nmcli/snmpget/bluetoothctl. A
bettercap-based version needs a daemon, a REST client and auth before it parses anything.

No-op unless `wifi_scan_enabled`, `wifi_scan_iface` is set to a non-uplink radio, and airodump-ng is
installed; throttled by `wifi_scan_interval`. The monitor-mode guard lives in monitor_mode.py — it
refuses the interface carrying the default route, so this can't knock Bjorn off its own network.
"""
import os
import csv
import glob
import time
import shutil
import logging
import tempfile
import subprocess
from datetime import datetime, timezone
from shared import SharedData
from logger import Logger
from csv_safe import sanitize_row
import monitor_mode

logger = Logger(name="wifi_scan.py", level=logging.INFO)

b_class = "WiFiScan"
b_module = "wifi_scan"
b_status = "wifi_scan"
b_port = 0  # standalone action (an AP is not an IP/port target)
b_parent = None

AP_COLS = ["BSSID", "ESSID", "Channel", "Privacy", "Cipher", "Auth", "Power", "Beacons",
           "FirstSeen", "LastSeen"]
CLIENT_COLS = ["Station", "BSSID", "Power", "Packets", "ProbedESSIDs", "FirstSeen", "LastSeen"]


class WiFiScan:
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self._last_scan = 0.0
        self.apfile = os.path.join(shared_data.scan_results_dir, "wifi_aps.csv")
        self.clientfile = os.path.join(shared_data.scan_results_dir, "wifi_clients.csv")
        logger.info("WiFiScan initialized.")

    def execute(self, force=False):
        """Run a capture if due. `force=True` (the web 'Scan now' button) ignores the enabled flag
        and the interval — the user asking for a scan by hand *is* the schedule."""
        try:
            if not force and not getattr(self.shared_data, "wifi_scan_enabled", False):
                return 'success'
            binp = shutil.which("airodump-ng")
            if not binp:
                logger.info("airodump-ng not found (install aircrack-ng); skipping Wi-Fi scan.")
                return 'success'
            interval = getattr(self.shared_data, "wifi_scan_interval", 900)
            now = time.time()
            if not force and interval and (now - self._last_scan) < interval:
                return 'success'  # throttled
            self._last_scan = now

            iface = (getattr(self.shared_data, "wifi_scan_iface", "") or "").strip()
            ok, detail = monitor_mode.acquire(iface)
            if not ok:
                # A refused interface is a configuration error, not a transient failure — say so
                # loudly rather than silently scanning nothing every cycle.
                logger.error(f"Wi-Fi scan skipped: {detail}")
                return 'failed'
            try:
                duration = max(10, int(getattr(self.shared_data, "wifi_scan_duration", 30)))
                aps, clients = self._capture(binp, iface, duration,
                                             getattr(self.shared_data, "wifi_scan_band", "bg"),
                                             getattr(self.shared_data, "wifi_scan_channel", 0))
            finally:
                monitor_mode.release(iface)

            if aps or clients:
                self._record(aps, clients)
                logger.success(f"Wi-Fi scan: {len(aps)} AP(s), {len(clients)} client(s).")
            else:
                logger.info("Wi-Fi scan completed; nothing heard.")
            return 'success'
        except Exception as e:
            logger.error(f"Error in Wi-Fi scan: {e}")
            return 'failed'

    @staticmethod
    def build_cmd(binp, iface, prefix, band="bg", channel=0):
        """airodump-ng command line. Pure/testable.

        `--band` matters on a dual-band adapter: airodump defaults to 2.4 GHz only, so every 5 GHz
        AP is invisible until you ask for it. `-c` locks one channel instead of hopping — far more
        thorough on a known channel, and blind to every other one, so 0 (hop) stays the default."""
        cmd = [binp, iface, "-w", prefix, "--output-format", "csv", "--write-interval", "1"]
        if channel:
            cmd += ["-c", str(int(channel))]  # a locked channel overrides band hopping
        elif band and band != "bg":
            cmd += ["--band", band]
        return cmd

    def _capture(self, binp, iface, duration, band="bg", channel=0):
        """Run airodump-ng for `duration` seconds into a scratch dir and parse its CSV.

        airodump-ng runs until killed, so the timeout IS the stop signal — TimeoutExpired is the
        expected path, not an error. `--write-interval 1` keeps the CSV flushed, so the data is
        already on disk when the process dies."""
        tmpdir = tempfile.mkdtemp(prefix="bjorn_wifi_")
        try:
            cmd = self.build_cmd(binp, iface, os.path.join(tmpdir, "scan"), band, channel)
            try:
                subprocess.run(cmd, capture_output=True, text=True, timeout=duration)
            except subprocess.TimeoutExpired:
                pass  # expected: we stop it by timing it out
            files = sorted(glob.glob(os.path.join(tmpdir, "scan*.csv")))
            if not files:
                logger.warning("airodump-ng produced no CSV (does the radio support monitor mode?)")
                return [], []
            with open(files[-1], newline="", encoding="utf-8", errors="replace") as f:
                return self.parse_airodump_csv(f.read())
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    @staticmethod
    def parse_airodump_csv(text):
        """Parse airodump-ng's CSV into ([ap dicts], [client dicts]). Pure/testable.

        The file is two CSV tables in one: access points, a blank line, then a table that starts
        with a 'Station MAC' header. Rows are comma-separated with padding spaces, so every cell is
        stripped. Short/blank rows are skipped — airodump truncates the row it is mid-write on."""
        ap_rows, client_rows, in_clients = [], [], False
        for raw in text.splitlines():
            line = raw.strip()
            if not line:
                continue
            cells = [c.strip() for c in line.split(",")]
            head = cells[0]
            if head.startswith("Station MAC"):
                in_clients = True
                continue
            if head.startswith("BSSID"):
                continue  # AP header
            if in_clients:
                if len(cells) >= 6 and ":" in head:
                    client_rows.append({
                        "Station": head, "FirstSeen": cells[1], "LastSeen": cells[2],
                        "Power": cells[3], "Packets": cells[4], "BSSID": cells[5],
                        # probed ESSIDs are themselves comma-separated -> re-join the tail
                        "ProbedESSIDs": ", ".join(c for c in cells[6:] if c),
                    })
            elif len(cells) >= 14 and ":" in head:
                ap_rows.append({
                    "BSSID": head, "FirstSeen": cells[1], "LastSeen": cells[2],
                    "Channel": cells[3], "Privacy": cells[5], "Cipher": cells[6],
                    "Auth": cells[7], "Power": cells[8], "Beacons": cells[9],
                    "ESSID": cells[13],
                })
        return ap_rows, client_rows

    @staticmethod
    def _load(path, key):
        by_key = {}
        try:
            with open(path, newline="", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    if row.get(key):
                        by_key[row[key]] = row
        except FileNotFoundError:
            pass
        return by_key

    @staticmethod
    def _merge(existing, fresh, key, cols):
        """Fold this run's rows into what's on disk, keeping the original FirstSeen. A device seen
        again keeps its history; a device not heard this run keeps its last-known row."""
        for row in fresh:
            ident = row.get(key, "")
            if not ident:
                continue
            prev = existing.get(ident, {})
            merged = {c: row.get(c, "") or prev.get(c, "") for c in cols}
            merged[key] = ident
            merged["FirstSeen"] = prev.get("FirstSeen") or row.get("FirstSeen", "")
            merged["LastSeen"] = row.get("LastSeen") or datetime.now(timezone.utc).isoformat()
            existing[ident] = merged
        return existing

    def _record(self, aps, clients):
        self._write(self.apfile, self._merge(self._load(self.apfile, "BSSID"), aps, "BSSID",
                                             AP_COLS), AP_COLS)
        self._write(self.clientfile,
                    self._merge(self._load(self.clientfile, "Station"), clients, "Station",
                                CLIENT_COLS), CLIENT_COLS)

    @staticmethod
    def _write(path, by_key, cols):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(cols)
            for row in by_key.values():
                w.writerow(sanitize_row([row.get(c, "") for c in cols]))


if __name__ == "__main__":
    WiFiScan(SharedData()).execute()
