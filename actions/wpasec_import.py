"""wpasec_import.py - Standalone action (backlog Wave 1 #4).

Pull cracked Wi-Fi credentials from wpa-sec.stanev.org (community WPA handshake cracking) and
inject them into NetworkManager as autoconnect profiles, so Bjorn can roam onto networks it already
has the key for instead of blind-attacking them. Opt-in: no-op unless `wpasec_api_key` is set.
Needs internet + nmcli; throttled to one fetch per `wpasec_interval` seconds.
"""
import os
import re
import csv
import uuid
import time
import logging
import subprocess
import urllib.request
from shared import SharedData
from logger import Logger
from csv_safe import sanitize_row

logger = Logger(name="wpasec_import.py", level=logging.INFO)

b_class = "WpaSecImport"
b_module = "wpasec_import"
b_status = "wpasec_import"
b_port = 0  # standalone action

WPASEC_URL = "https://wpa-sec.stanev.org/?api&dl=1"
NM_DIR = "/etc/NetworkManager/system-connections"


class WpaSecImport:
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self._last_fetch = 0.0
        self.recordfile = os.path.join(shared_data.crackedpwddir, "wifi_wpasec.csv")
        logger.info("WpaSecImport initialized.")

    def execute(self):
        try:
            api_key = (getattr(self.shared_data, "wpasec_api_key", "") or "").strip()
            if not api_key:
                logger.info("wpasec_api_key not set; skipping wpa-sec import.")
                return 'skipped'

            interval = getattr(self.shared_data, "wpasec_interval", 3600)
            now = time.time()
            if interval and (now - self._last_fetch) < interval:
                return 'skipped'  # throttled — don't hammer the service each idle cycle
            self._last_fetch = now

            text = self._fetch(api_key)
            if text is None:
                return 'skipped'  # network error already logged; this is opportunistic

            pairs = self._parse_potfile(text)
            known = self._known_ssids()
            injected = 0
            for ssid, psk in pairs:
                if ssid in known:
                    continue
                if self._inject(ssid, psk):
                    self._record(ssid, psk)
                    known.add(ssid)
                    injected += 1

            if injected:
                subprocess.run(["nmcli", "connection", "reload"], check=False)
                logger.success(f"wpa-sec: injected {injected} new Wi-Fi cred(s) into NetworkManager.")
            else:
                logger.info(f"wpa-sec: {len(pairs)} cracked cred(s) fetched, none new.")
            return 'success'
        except Exception as e:
            logger.error(f"Error in wpa-sec import: {e}")
            return 'failed'

    def _fetch(self, api_key):
        """GET the account's cracked-results potfile. Returns the body text, or None on any network
        error (logged) — the action stays best-effort since Bjorn isn't always online."""
        try:
            req = urllib.request.Request(WPASEC_URL, headers={"Cookie": f"key={api_key}"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except Exception as e:
            logger.warning(f"wpa-sec fetch failed (needs internet): {e}")
            return None

    @staticmethod
    def _parse_potfile(text):
        """Parse wpa-sec download lines 'apmac:stmac:essid:password' into deduped (ssid, password)
        pairs. The MACs are colon-free 12-hex, so split(':', 3) is safe and a ':' in the password is
        preserved. Skip uncracked/empty lines and — a trust boundary, since this is remote data —
        anything with control chars, which could inject extra NM keyfile sections."""
        pairs, seen = [], set()
        for line in text.splitlines():
            parts = line.split(":", 3)
            if len(parts) != 4:
                continue
            ssid, password = parts[2], parts[3]
            if not ssid or not password:
                continue
            if any(bad in ssid or bad in password for bad in ("\n", "\r", "\x00")):
                continue
            key = (ssid, password)
            if key not in seen:
                seen.add(key)
                pairs.append(key)
        return pairs

    @staticmethod
    def _safe_conn_name(ssid):
        return "wpasec-" + re.sub(r'[^A-Za-z0-9_-]', '_', ssid)[:48]

    @staticmethod
    def _nmconnection(ssid, psk):
        """NM keyfile for one cracked network. autoconnect-priority is negative so these never
        outrank Bjorn's own `preconfigured` connection (priority 0) — it only falls back to a
        cracked network when its normal one isn't in range."""
        return f"""[connection]
id={WpaSecImport._safe_conn_name(ssid)}
uuid={uuid.uuid4()}
type=wifi
autoconnect=true
autoconnect-priority=-10

[wifi]
ssid={ssid}
mode=infrastructure

[wifi-security]
key-mgmt=wpa-psk
psk={psk}

[ipv4]
method=auto

[ipv6]
method=auto
"""

    def _inject(self, ssid, psk):
        try:
            path = os.path.join(NM_DIR, self._safe_conn_name(ssid) + ".nmconnection")
            with open(path, "w") as f:
                f.write(self._nmconnection(ssid, psk))
            os.chmod(path, 0o600)  # NM refuses to load a world-readable keyfile
            return True
        except Exception as e:
            logger.warning(f"wpa-sec: could not write NM profile for {ssid!r}: {e}")
            return False

    def _known_ssids(self):
        known = set()
        try:
            with open(self.recordfile, newline='') as f:
                r = csv.reader(f)
                next(r, None)  # header
                for row in r:
                    if row:
                        known.add(row[0])
        except FileNotFoundError:
            pass
        return known

    def _record(self, ssid, psk):
        new_file = not os.path.exists(self.recordfile)
        os.makedirs(os.path.dirname(self.recordfile), exist_ok=True)
        with open(self.recordfile, "a", newline='') as f:
            w = csv.writer(f)
            if new_file:
                w.writerow(["SSID", "Password"])
            w.writerow(sanitize_row([ssid, psk]))


if __name__ == "__main__":
    shared_data = SharedData()
    WpaSecImport(shared_data).execute()
