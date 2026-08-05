"""Tests for the report-delivery client (backlog Wave 2/3): API URL, multipart body builder, the
change-detection signature, and the Telegram -> SMTP channel fallback. Pure — no network;
telegram_client is stdlib-only, imported directly.
"""
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import telegram_client as tc  # noqa: E402


def _sd(**kw):
    """A stand-in for SharedData — _deliver only ever getattr()s config values off it."""
    return types.SimpleNamespace(**kw)


def test_api_url():
    assert tc._api_url("123:abc", "sendMessage") == "https://api.telegram.org/bot123:abc/sendMessage"


def test_multipart_encode_contents():
    body, ctype = tc._multipart_encode({"chat_id": "42", "caption": "hi"}, "t.json", b'{"a":1}')
    assert ctype.startswith("multipart/form-data; boundary=")
    boundary = ctype.split("boundary=")[1]
    assert boundary.encode() in body
    assert b'name="chat_id"' in body and b"42" in body
    assert b'name="caption"' in body and b"hi" in body
    assert b'filename="t.json"' in body
    assert b'{"a":1}' in body            # file content present
    assert body.strip().endswith(b"--")  # closing boundary


def test_signature_stable_and_sensitive():
    a = {"hosts": [{"IPs": "10.0.0.1"}], "snmp": []}
    b = {"snmp": [], "hosts": [{"IPs": "10.0.0.1"}]}  # same data, different key order
    assert tc._signature(a) == tc._signature(b)        # order-independent
    c = {"hosts": [{"IPs": "10.0.0.2"}], "snmp": []}
    assert tc._signature(a) != tc._signature(c)         # a change flips the signature


def _patched(**fns):
    """Swap module-level send functions for recording fakes; returns a restore callable."""
    saved = {k: getattr(tc, k) for k in fns}
    for k, v in fns.items():
        setattr(tc, k, v)
    return lambda: [setattr(tc, k, v) for k, v in saved.items()]


def test_deliver_prefers_telegram_and_skips_smtp():
    calls = []
    restore = _patched(
        send_document=lambda *a, **k: (calls.append("tg"), (True, "sent"))[1],
        send_email=lambda *a, **k: (calls.append("smtp"), (True, "sent"))[1])
    try:
        ok, detail = tc._deliver(
            _sd(telegram_bot_token="t", telegram_chat_id="c", smtp_enabled=True),
            "subj", "f.json", b"{}")
    finally:
        restore()
    assert ok and "telegram" in detail
    assert calls == ["tg"]  # SMTP never touched while Telegram works


def test_deliver_falls_back_to_smtp_when_telegram_fails():
    restore = _patched(send_document=lambda *a, **k: (False, "HTTP 403"),
                       send_email=lambda *a, **k: (True, "sent"))
    try:
        ok, detail = tc._deliver(
            _sd(telegram_bot_token="t", telegram_chat_id="c", smtp_enabled=True),
            "subj", "f.json", b"{}")
    finally:
        restore()
    assert ok and "smtp" in detail


def test_deliver_uses_smtp_when_telegram_unconfigured():
    restore = _patched(send_email=lambda *a, **k: (True, "sent"))
    try:
        ok, detail = tc._deliver(_sd(smtp_enabled=True), "subj", "f.json", b"{}")
    finally:
        restore()
    assert ok and "smtp" in detail


def test_deliver_reports_both_channels_when_all_fail():
    restore = _patched(send_document=lambda *a, **k: (False, "HTTP 403"),
                       send_email=lambda *a, **k: (False, "connection refused"))
    try:
        ok, detail = tc._deliver(
            _sd(telegram_bot_token="t", telegram_chat_id="c", smtp_enabled=True),
            "subj", "f.json", b"{}")
    finally:
        restore()
    assert not ok
    assert "HTTP 403" in detail and "connection refused" in detail


def test_deliver_without_any_channel():
    ok, detail = tc._deliver(_sd(smtp_enabled=False), "subj", None, None)
    assert not ok and "telegram" in detail


def test_send_email_requires_host_and_recipient():
    assert tc.send_email(_sd(smtp_host="", smtp_to="a@b.c"), "s", "b")[0] is False
    assert tc.send_email(_sd(smtp_host="mail", smtp_to=""), "s", "b")[0] is False


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
