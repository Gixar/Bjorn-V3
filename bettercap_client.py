# bettercap_client.py
# Thin REST client for bettercap's `api.rest` module (docs/BETTERCAP_PLAN.md Stage B, step B1).
#
# Bettercap runs as its own systemd unit — the same "external process" relationship Bjorn already
# has with nmap/nmcli/airodump-ng — and Bjorn talks to it over HTTP on loopback. This module is a
# *data source*, not an orchestrator action: it has no b_class and never joins actions.json.
#
# Stdlib only (urllib + base64), so no new dependency, and the parsing is pure functions over
# dicts so it is testable without a daemon, a network, or SharedData.
#
# ── THE ONE THING TO CHECK BEFORE TRUSTING THIS ──────────────────────────────────────────────
# Bettercap's event JSON is version-specific and not stably documented. EVENT_TAGS and FIELDS
# below are written from the documented/observed shape, NOT from a capture off the target box —
# step B0 of the plan is to curl /api/events on the Pi and confirm them. That is why every field
# read goes through one table and one `.get()`: a mismatch is a one-line edit here, not a rewrite,
# and an unrecognised event is skipped rather than crashing the poller.
# ─────────────────────────────────────────────────────────────────────────────────────────────
import json
import base64
import logging
import urllib.error
import urllib.parse
import urllib.request

from logger import Logger

logger = Logger(name="bettercap_client.py", level=logging.INFO)

# Event tags that carry an IP-layer host. Wireless-layer tags (wifi.ap.new, wifi.client.*) are
# deliberately absent: they have no IP or ports and do not fit the netkb schema — the same call
# already made for BLEScan and WiFiScan, which keep their own CSVs.
HOST_EVENT_TAGS = ("endpoint.new", "endpoint.lost")

# bettercap field name -> Bjorn's name. One table so B0 is a table edit.
FIELDS = {
    "ipv4": "ip",
    "mac": "mac",
    "hostname": "hostname",
    "vendor": "vendor",
}


def _auth_header(user, password):
    raw = f"{user}:{password}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def parse_hosts(events):
    """IP-layer hosts from a list of bettercap event dicts. Pure/testable.

    Tolerant by design: an event missing a tag, a data block, a MAC or an IPv4 address is skipped,
    not an error. The poller runs for the lifetime of the process against a daemon whose schema may
    shift under it — one unexpected event must not take the thread down.

    MACs are upper-cased. netkb is keyed by MAC and nmap writes them upper-case; bettercap emits
    lower-case, so without this every bettercap host would be a *second* row for a host Bjorn had
    already found, silently doubling the netkb.
    """
    hosts = {}
    for event in events or []:
        if not isinstance(event, dict) or event.get("tag") not in HOST_EVENT_TAGS:
            continue
        data = event.get("data")
        # endpoint.* nests the host under "data"; some builds nest it one deeper under
        # data["endpoint"]. Accept either rather than guessing wrong for a whole release.
        if isinstance(data, dict) and isinstance(data.get("endpoint"), dict):
            data = data["endpoint"]
        if not isinstance(data, dict):
            continue
        host = {ours: (data.get(theirs) or "") for theirs, ours in FIELDS.items()}
        if not host["mac"] or not host["ip"]:
            continue
        host["mac"] = host["mac"].upper()
        host["lost"] = event.get("tag") == "endpoint.lost"
        hosts[host["mac"]] = host  # last event per MAC wins: a lost/new pair collapses correctly
    return list(hosts.values())


class BettercapClient:
    """REST client for one bettercap instance. Construct from config, never from bare literals."""

    def __init__(self, base_url, user, password, timeout=10):
        self.base_url = (base_url or "").rstrip("/")
        self.timeout = timeout
        self._auth = _auth_header(user, password)

    @classmethod
    def from_config(cls, shared_data):
        return cls(getattr(shared_data, "bettercap_api_url", ""),
                   getattr(shared_data, "bettercap_user", ""),
                   getattr(shared_data, "bettercap_password", ""))

    def _request(self, path, payload=None):
        """(ok, parsed-json-or-detail). Never raises: the caller is a long-lived poller, and a
        daemon that is restarting is an expected state, not an exception to propagate."""
        if not self.base_url:
            return False, "bettercap_api_url is not set"
        req = urllib.request.Request(
            self.base_url + path,
            data=json.dumps(payload).encode("utf-8") if payload is not None else None,
            headers={"Authorization": self._auth, "Content-Type": "application/json"},
            method="POST" if payload is not None else "GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
            return True, (json.loads(body) if body.strip() else {})
        except urllib.error.HTTPError as e:
            # 401 is worth naming: bettercap ships weak default credentials, so "unauthorized"
            # usually means the installer-generated password never reached the config.
            detail = "unauthorized (check bettercap_user / bettercap_password)" if e.code == 401 \
                else f"HTTP {e.code}"
            return False, detail
        except (urllib.error.URLError, json.JSONDecodeError, OSError) as e:
            return False, str(e)

    def session(self):
        """Current session state — the reachability probe behind the web panel's status line."""
        return self._request("/api/session")

    def events(self, clear=False):
        """(ok, [event dicts]). `clear=True` asks bettercap to drop what it just handed over, so
        the next poll returns only new events instead of the whole ring buffer again."""
        ok, obj = self._request("/api/events" + ("?clear=true" if clear else ""))
        if not ok:
            return False, obj
        return True, obj if isinstance(obj, list) else []

    def run(self, command):
        """Run one bettercap command (`wifi.recon on`, `net.probe on`, ...)."""
        return self._request("/api/session", payload={"cmd": command})

    def is_reachable(self):
        ok, _ = self.session()
        return ok
