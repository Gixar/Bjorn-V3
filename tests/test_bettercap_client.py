"""Tests for the bettercap REST client (docs/BETTERCAP_PLAN.md step B1).

No daemon, no network: parse_hosts() is pure, and the HTTP paths are driven with a fake urlopen.

NOTE: the event fixtures below are written from bettercap's documented/observed shape, not from a
capture off the target Pi — that is step B0. They therefore prove the *parser's* behaviour
(tolerance, MAC normalisation, dedupe), not that the field names are right for the installed
version. When B0 lands, replace SAMPLE_EVENTS with the real dump; if these tests still pass, the
mapping was right, and if they don't, the fix is the FIELDS table.
"""
import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _stubs  # noqa: E402
_stubs.install()

import bettercap_client as bc  # noqa: E402
from bettercap_client import BettercapClient, parse_hosts  # noqa: E402

SAMPLE_EVENTS = [
    {"tag": "endpoint.new", "time": "2026-08-07T10:00:00Z",
     "data": {"ipv4": "192.168.1.10", "mac": "aa:bb:cc:dd:ee:01",
              "hostname": "nas.local", "vendor": "Synology"}},
    {"tag": "sys.log", "data": {"message": "noise that must be ignored"}},
    {"tag": "endpoint.new", "time": "2026-08-07T10:00:01Z",
     "data": {"endpoint": {"ipv4": "192.168.1.11", "mac": "aa:bb:cc:dd:ee:02",
                           "hostname": "", "vendor": "Raspberry Pi"}}},
]


def test_parses_hosts_and_ignores_unrelated_events():
    hosts = {h["mac"]: h for h in parse_hosts(SAMPLE_EVENTS)}
    assert set(hosts) == {"AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"}
    assert hosts["AA:BB:CC:DD:EE:01"]["ip"] == "192.168.1.10"
    assert hosts["AA:BB:CC:DD:EE:01"]["hostname"] == "nas.local"
    # the nested "data.endpoint" shape must parse the same as the flat one
    assert hosts["AA:BB:CC:DD:EE:02"]["vendor"] == "Raspberry Pi"


def test_macs_are_upper_cased_to_match_netkb():
    """netkb is keyed by MAC and nmap writes upper-case; bettercap emits lower-case. Without
    normalising, every bettercap host becomes a second row for a host Bjorn already knows."""
    hosts = parse_hosts([{"tag": "endpoint.new",
                          "data": {"ipv4": "10.0.0.5", "mac": "de:ad:be:ef:00:01"}}])
    assert hosts[0]["mac"] == "DE:AD:BE:EF:00:01"


def test_malformed_events_are_skipped_not_raised():
    """The poller lives for the whole process against a daemon whose schema can shift under it.
    One unexpected event must not take the thread down."""
    junk = [None, "string", {}, {"tag": "endpoint.new"},
            {"tag": "endpoint.new", "data": None},
            {"tag": "endpoint.new", "data": {"mac": "aa:bb:cc:dd:ee:ff"}},   # no IP
            {"tag": "endpoint.new", "data": {"ipv4": "10.0.0.9"}}]           # no MAC
    assert parse_hosts(junk) == []
    assert parse_hosts([]) == [] and parse_hosts(None) == []


def test_last_event_per_mac_wins():
    """A new/lost pair for one host must collapse to one entry carrying the latest state."""
    events = [
        {"tag": "endpoint.new", "data": {"ipv4": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:01"}},
        {"tag": "endpoint.lost", "data": {"ipv4": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:01"}},
    ]
    hosts = parse_hosts(events)
    assert len(hosts) == 1 and hosts[0]["lost"] is True


class _FakeResponse:
    def __init__(self, body):
        self._body = body.encode("utf-8")

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _with_urlopen(fn):
    saved = bc.urllib.request.urlopen
    bc.urllib.request.urlopen = fn
    return saved


def test_events_returns_a_list_and_sends_basic_auth():
    captured = {}

    def fake(req, timeout=None):
        captured["auth"] = req.headers.get("Authorization")
        captured["url"] = req.full_url
        return _FakeResponse(json.dumps(SAMPLE_EVENTS))

    saved = _with_urlopen(fake)
    try:
        ok, events = BettercapClient("http://127.0.0.1:8081/", "bjorn", "pw").events(clear=True)
    finally:
        bc.urllib.request.urlopen = saved
    assert ok and len(events) == 3
    assert captured["auth"].startswith("Basic ")
    assert captured["url"].endswith("/api/events?clear=true")
    assert "//127.0.0.1" in captured["url"], "the trailing slash on base_url must not double up"


def test_unauthorized_is_reported_in_plain_language():
    """bettercap ships weak default credentials, so a 401 nearly always means the generated
    password never reached the config — say that, not 'HTTP 401'."""
    def fake(req, timeout=None):
        raise bc.urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, None)

    saved = _with_urlopen(fake)
    try:
        ok, detail = BettercapClient("http://127.0.0.1:8081", "bjorn", "wrong").session()
    finally:
        bc.urllib.request.urlopen = saved
    assert not ok and "bettercap_password" in detail


def test_a_down_daemon_is_a_false_not_an_exception():
    def fake(req, timeout=None):
        raise bc.urllib.error.URLError("Connection refused")

    saved = _with_urlopen(fake)
    try:
        client = BettercapClient("http://127.0.0.1:8081", "bjorn", "pw")
        assert client.is_reachable() is False
    finally:
        bc.urllib.request.urlopen = saved


def test_no_url_configured_is_handled():
    ok, detail = BettercapClient("", "bjorn", "pw").session()
    assert not ok and "bettercap_api_url" in detail


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
