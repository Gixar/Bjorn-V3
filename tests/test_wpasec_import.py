"""Tests for wpa-sec import (backlog Wave 1 #4): potfile parsing (incl. passwords with ':',
malformed/empty/control-char lines), connection-name sanitization, and the NM keyfile. Pure static
methods — no network, no nmcli. Heavy imports (shared/logger) stubbed via tests/_stubs.py.
"""
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _stubs  # noqa: E402
_stubs.install()

from actions.wpasec_import import WpaSecImport  # noqa: E402

parse = WpaSecImport._parse_potfile


def test_parses_ssid_password():
    out = parse("001122334455:665544332211:HomeWifi:secret123\n")
    assert out == [("HomeWifi", "secret123")]


def test_password_with_colon_preserved():
    # split(':', 3) keeps everything after the 3rd colon as the password
    out = parse("aabbccddeeff:112233445566:CorpNet:p@:ss:word")
    assert out == [("CorpNet", "p@:ss:word")]


def test_skips_malformed_and_empty_password():
    text = "\n".join([
        "not-enough-fields",
        "aa:bb:OnlySsidNoPass:",       # empty password -> skip
        "001122334455:665544332211:Good:pw",
    ])
    assert parse(text) == [("Good", "pw")]


def test_dedupes():
    text = "a:b:Net:pw\na:b:Net:pw\n"
    assert parse(text) == [("Net", "pw")]


def test_rejects_control_chars_injection():
    # a NUL (or CR) in the value could inject extra NM keyfile sections — must be dropped
    assert parse("a:b:Evil:pw\x00[connection]") == []
    assert parse("a:b:Ev\x00il:pw") == []


def test_safe_conn_name_sanitizes():
    assert WpaSecImport._safe_conn_name("My Net/Work!") == "wpasec-My_Net_Work_"


def test_nmconnection_contents():
    conf = WpaSecImport._nmconnection("HomeWifi", "secret123")
    assert "ssid=HomeWifi" in conf
    assert "psk=secret123" in conf
    assert "key-mgmt=wpa-psk" in conf
    assert "autoconnect-priority=-10" in conf  # never outranks Bjorn's own connection


# --- #3 upload half: completeness gate + one-upload-per-BSSID + idempotency -------------------

def _uploader(tmp_path, uploads):
    """A WpaSecImport with __init__ bypassed, wired to a fake tool and a recording uploader.
    `_is_complete` keys off the filename so the dedupe/gate logic is what's under test, not the
    hcxpcapngtool subprocess (a thin wrapper)."""
    obj = WpaSecImport.__new__(WpaSecImport)
    obj.shared_data = SimpleNamespace(handshakes_dir=str(tmp_path))
    obj._is_complete = lambda path: "incomplete" not in os.path.basename(path)
    obj._upload_file = lambda key, path: (uploads.append(os.path.basename(path)) or True)
    return obj


def _write_index(tmp_path, entries):
    for path in entries:
        Path(path).write_bytes(b"x")  # _upload_pending skips entries whose file is gone
    (tmp_path / "index.json").write_text(json.dumps({"captures": entries}))


def test_the_upload_pass_does_not_put_the_empty_captures_back_in_the_count(tmp_path):
    """index.json has two writers. This one rewrites it after every upload pass, so a second
    definition of "a capture" here would restore the inflated count the moment anything uploaded —
    the header-only pcaps bettercap leaves behind when a session hears no EAPOL are 24 bytes and
    are not loot, however many of them are on disk."""
    real = str(tmp_path / "real.pcap")
    empty = str(tmp_path / "empty.pcap")
    entries = {
        real: {"path": real, "bssid": "AA:AA:AA:AA:AA:AA", "bytes": 4096},
        empty: {"path": empty, "bssid": "BB:BB:BB:BB:BB:BB", "bytes": 24},
    }
    _uploader(tmp_path, [])._save_index(entries)

    saved = json.loads((tmp_path / "index.json").read_text())
    assert saved["unique_bssids"] == 1, "an empty capture is not an AP owned"
    assert len(saved["captures"]) == 2, "but it stays listed, or nobody will ever clean it up"


def test_upload_is_one_per_bssid_and_skips_incomplete(tmp_path):
    a1 = str(tmp_path / "apA-1.pcap")
    a2 = str(tmp_path / "apA-2.pcap")          # same BSSID as a1 -> must not upload twice
    b1 = str(tmp_path / "apB.pcap")
    bad = str(tmp_path / "apC-incomplete.pcap")  # no real handshake -> never upload
    entries = {
        a1: {"path": a1, "bssid": "AA:AA:AA:AA:AA:AA"},
        a2: {"path": a2, "bssid": "AA:AA:AA:AA:AA:AA"},
        b1: {"path": b1, "bssid": "BB:BB:BB:BB:BB:BB"},
        bad: {"path": bad, "bssid": "CC:CC:CC:CC:CC:CC"},
    }
    _write_index(tmp_path, entries)

    uploads = []
    n = _uploader(tmp_path, uploads)._upload_pending("KEY")

    assert n == 2, "one upload per unique complete BSSID (AA once, BB once)"
    assert sorted(uploads) == ["apA-1.pcap", "apB.pcap"]
    assert "apC-incomplete.pcap" not in uploads

    # The whole point of persisting `uploaded`: a second pass sends nothing.
    uploads2 = []
    n2 = _uploader(tmp_path, uploads2)._upload_pending("KEY")
    assert n2 == 0 and uploads2 == [], "already-uploaded captures must not re-upload"

    saved = json.loads((tmp_path / "index.json").read_text())["captures"]
    assert saved[a1]["uploaded"] and saved[a2]["uploaded"], "both AA captures marked uploaded"
    assert "uploaded" not in saved[bad], "an incomplete capture is never stamped uploaded"


if __name__ == "__main__":
    import inspect
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn) and not inspect.signature(fn).parameters:
            fn()
    print("ok (fixture-free subset; run pytest for all)")
