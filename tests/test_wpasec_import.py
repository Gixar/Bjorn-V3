"""Tests for wpa-sec import (backlog Wave 1 #4): potfile parsing (incl. passwords with ':',
malformed/empty/control-char lines), connection-name sanitization, and the NM keyfile. Pure static
methods — no network, no nmcli. Heavy imports (shared/logger) stubbed via tests/_stubs.py.
"""
import sys
from pathlib import Path

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


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
