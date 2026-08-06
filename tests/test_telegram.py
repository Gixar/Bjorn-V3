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


class _FakeSMTP:
    """Minimal stand-in for smtplib.SMTP. `starttls_supported=False` reproduces the relay that
    triggered the cleartext downgrade."""
    def __init__(self, starttls_supported=True):
        self.starttls_supported = starttls_supported
        self.logged_in = False
        self.sent = False

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self, context=None):
        if not self.starttls_supported:
            raise tc.smtplib.SMTPNotSupportedError("STARTTLS extension not supported by server.")
        self.tls_context = context

    def login(self, user, password):
        self.logged_in = True

    def send_message(self, msg):
        self.sent = True


def _with_smtp(fake, attr="SMTP"):
    saved = getattr(tc.smtplib, attr)
    setattr(tc.smtplib, attr, lambda *a, **k: fake)
    return lambda: setattr(tc.smtplib, attr, saved)


def _smtp_config(**kw):
    base = dict(smtp_host="mail.example.com", smtp_to="you@example.com", smtp_port=587,
                smtp_user="bjorn@example.com", smtp_password="hunter2")
    base.update(kw)
    return _sd(**base)


def test_send_email_refuses_cleartext_when_starttls_is_unsupported():
    """The security fix: a server without STARTTLS must abort the send, not continue in the clear.
    The payload can carry every cracked credential, and login() would put the mailbox password on
    the wire too — on exactly the hostile network that made Telegram fail in the first place."""
    fake = _FakeSMTP(starttls_supported=False)
    restore = _with_smtp(fake)
    try:
        ok, detail = tc.send_email(_smtp_config(), "subj", "body", "t.json", b"{}")
    finally:
        restore()
    assert ok is False
    assert "cleartext" in detail and "STARTTLS" in detail
    assert not fake.sent, "the report must not be transmitted"
    assert not fake.logged_in, "the SMTP password must not be sent over an unencrypted socket"


def test_send_email_sends_once_starttls_succeeds():
    fake = _FakeSMTP(starttls_supported=True)
    restore = _with_smtp(fake)
    try:
        ok, _ = tc.send_email(_smtp_config(), "subj", "body", "t.json", b"{}")
    finally:
        restore()
    assert ok and fake.sent and fake.logged_in
    assert fake.tls_context.check_hostname, "STARTTLS must use a verifying context"


def test_send_email_port_465_uses_a_verifying_context():
    """SMTP_SSL's own default context has historically skipped certificate verification, so the
    context is passed explicitly."""
    captured = {}
    saved = tc.smtplib.SMTP_SSL
    fake = _FakeSMTP()

    def _ssl(*a, **k):
        captured.update(k)
        return fake

    tc.smtplib.SMTP_SSL = _ssl
    try:
        ok, _ = tc.send_email(_smtp_config(smtp_port=465), "subj", "body")
    finally:
        tc.smtplib.SMTP_SSL = saved
    assert ok and fake.sent
    assert captured.get("context") is not None and captured["context"].check_hostname


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
