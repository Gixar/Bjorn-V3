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
import time
import base64
import logging
import threading
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


# Localhost HTTP against an idle daemon; the expensive part is never the poll, it is what the
# events turn into. Fixed rather than configurable: nobody has a reason to tune it yet, and the
# Pi Zero load risk is handled by batching into the orchestrator's write, not by polling less.
POLL_INTERVAL = 10


def merge_into_netkb(rows, hosts):
    """Fold bettercap hosts into a list of netkb dict rows, in place. Returns how many were added.

    Pure (no I/O), so the merge rules are testable without a daemon or a CSV.

    Two rules worth stating, because both are about not fighting the scanner:
      - An existing MAC keeps its Ports and every action column. Bettercap knows a host exists; it
        knows nothing about what has been scanned or attacked on it, and must never blank that.
      - `endpoint.lost` does NOT mark a host dead. Bettercap losing sight of a host and the host
        being down are different claims, and the scanner already owns the second one.
    """
    by_mac = {row.get("MAC Address"): row for row in rows}
    added = 0
    for host in hosts:
        mac = host.get("mac")
        if not mac or mac == "STANDALONE":
            continue
        existing = by_mac.get(mac)
        if existing is None:
            rows.append({"MAC Address": mac, "IPs": host.get("ip", ""),
                         "Hostnames": host.get("hostname", ""),
                         "Alive": "0" if host.get("lost") else "1", "Ports": ""})
            added += 1
            continue
        if host.get("ip"):
            existing["IPs"] = host["ip"]
        if host.get("hostname") and not existing.get("Hostnames"):
            existing["Hostnames"] = host["hostname"]
        if not host.get("lost"):
            existing["Alive"] = "1"
    return added


class BettercapPoller:
    """Polls /api/events and buffers the hosts it finds for the orchestrator to write.

    It deliberately does NOT touch netkb.csv. The orchestrator is the single writer (the P3/P5
    discipline: one batched write per cycle, lockless because there is exactly one writer). A
    second writer would not corrupt the file — write_data is atomic — but it would silently lose
    updates whenever the two read-modify-write cycles interleaved.
    """

    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.client = BettercapClient.from_config(shared_data)
        self._buffer = {}
        self._lock = threading.Lock()
        self._schema_reported = False
        self.polls = 0
        self.errors = 0
        # Rate-limit failure logs so a wrong password is not 8,640 silent failures/day
        # and also not 8,640 identical ERROR lines.  First failure logs immediately;
        # subsequent ones back off (30s, 2m, 10m, 30m cap).
        self._last_error = None
        self._next_error_log = 0.0
        self._error_backoff = 30

    def drain(self):
        """Take everything buffered since the last call. Called by the orchestrator."""
        with self._lock:
            hosts, self._buffer = list(self._buffer.values()), {}
        return hosts

    def poll_once(self):
        """One poll. Returns the number of hosts buffered, or -1 when the daemon did not answer.

        Failures are no longer silent: the first error is logged immediately, then with
        exponential backoff so a persistent 401/daemon-down does not flood the log.
        """
        ok, events = self.client.events(clear=True)
        if not ok:
            self.errors += 1
            self._last_error = events  # events is the detail string when ok is False
            now = time.time()
            if now >= self._next_error_log:
                logger.warning(
                    f"Bettercap poll failed ({self.errors} total): {self._last_error}"
                )
                self._next_error_log = now + self._error_backoff
                self._error_backoff = min(self._error_backoff * 2, 1800)  # cap 30 min
            return -1
        # Success resets the backoff so the next outage is reported promptly again.
        if self._error_backoff != 30 or self._last_error is not None:
            if self.errors:
                logger.info(f"Bettercap poll recovered after {self.errors} error(s)")
            self._error_backoff = 30
            self._last_error = None
            self._next_error_log = 0.0
        self.polls += 1
        hosts = parse_hosts(events)
        self._report_schema(events, hosts)
        with self._lock:
            for host in hosts:
                self._buffer[host["mac"]] = host
        return len(hosts)

    def _report_schema(self, events, hosts):
        """Say once what bettercap actually sent.

        This is step B0 turned into something the device does for itself. The event JSON is
        version-specific, and the failure mode of a wrong FIELDS mapping is silence — events
        arriving, zero hosts produced, nothing logged. Naming the tags on the first non-empty poll
        makes a mismatch obvious in the log instead of looking like an idle network.
        """
        if self._schema_reported or not events:
            return
        self._schema_reported = True
        tags = sorted({e.get("tag") for e in events if isinstance(e, dict) and e.get("tag")})
        logger.info(f"bettercap event tags seen: {', '.join(tags) or '(none)'}")
        if not hosts:
            logger.warning(f"{len(events)} bettercap event(s) produced no hosts — if any tag above "
                           f"looks host-shaped, HOST_EVENT_TAGS/FIELDS in bettercap_client.py need "
                           f"updating for this bettercap version.")

    def run(self):
        """Thread body. Exits on shared_data.should_exit; never raises."""
        logger.info(f"Bettercap poller started ({self.client.base_url}).")
        while not getattr(self.shared_data, "should_exit", False):
            try:
                self.poll_once()
            except Exception as e:      # a poller that dies takes the feature with it, silently
                self.errors += 1
                logger.error(f"Bettercap poll failed: {e}")
            for _ in range(POLL_INTERVAL):
                if getattr(self.shared_data, "should_exit", False):
                    break
                time.sleep(1)
        logger.info("Bettercap poller stopped.")


def start_poller(shared_data):
    """Start the poller thread if Bettercap is enabled. Returns the poller, or None."""
    if not getattr(shared_data, "bettercap_enabled", False):
        return None
    poller = BettercapPoller(shared_data)
    threading.Thread(target=poller.run, daemon=True, name="bettercap-poller").start()
    return poller
