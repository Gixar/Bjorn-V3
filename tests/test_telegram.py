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


# --- the "everything in one file" bundle -----------------------------------

def _bundle_tree(tmp):
    """A miniature data/ tree: some real files, some empty, some header-only."""
    import os
    out = os.path.join(tmp, "output")
    for sub in ("scan_results", "crackedpwd", "data_stolen"):
        os.makedirs(os.path.join(out, sub), exist_ok=True)
    def write(rel, text):
        path = os.path.join(out, rel)
        with open(path, "w", newline="") as f:
            f.write(text)
        return path
    write("scan_results/wifi_aps.csv", "BSSID,ESSID\nAA:BB,Home\n")   # real data
    write("scan_results/snmp_enum.csv", "IP,SysDescr\n")              # header only
    write("scan_results/empty.csv", "")                                # truly empty
    write("crackedpwd/ssh.csv", "IP,User,Password\n10.0.0.1,root,toor\n")
    write("data_stolen/loot.txt", "secrets")
    netkb = os.path.join(tmp, "netkb.csv")
    with open(netkb, "w", newline="") as f:
        f.write("MAC Address,IPs\nAA:BB,10.0.0.1\n")
    live = os.path.join(tmp, "livestatus.csv")
    with open(live, "w", newline="") as f:
        f.write("h\n")                                                 # header only
    return types.SimpleNamespace(datadir=tmp, output_dir=out, netkbfile=netkb,
                                 livestatusfile=live,
                                 crackedpwddir=os.path.join(out, "crackedpwd"),
                                 telegram_include_creds=True)


def test_header_only_and_empty_files_are_left_out():
    """Every module creates its output file up front, so a size check alone would pack a dozen
    empty tables and make the archive look full. A CSV with only a header is a table that never
    got a row, not data you collected."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        sd = _bundle_tree(tmp)
        names = [arc for arc, _ in tc.bundle_sources(sd)]
        assert any(n.endswith("wifi_aps.csv") for n in names)
        assert any(n.endswith("loot.txt") for n in names)
        assert not any("snmp_enum" in n for n in names), "header-only CSV must be skipped"
        assert not any("empty.csv" in n for n in names)
        assert not any(n == "livestatus.csv" for n in names)
        assert "netkb.csv" in names


def test_credentials_obey_the_same_switch_as_the_report():
    """It is one file whether you send it or download it, so 'it's only a local download' is not a
    reason to put cracked passwords in it without being asked."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        sd = _bundle_tree(tmp)
        with_creds = [a for a, _ in tc.bundle_sources(sd, include_creds=True)]
        without = [a for a, _ in tc.bundle_sources(sd, include_creds=False)]
        assert any("ssh.csv" in n for n in with_creds)
        assert not any("ssh.csv" in n for n in without)
        assert any("wifi_aps.csv" in n for n in without), "only creds are withheld"


def test_compile_writes_one_readable_zip_outside_the_output_tree():
    """The archive lives in datadir, not under output_dir — otherwise the next rebuild would pack
    the previous bundle into the new one, and the file would grow every press."""
    import tempfile, zipfile, os
    with tempfile.TemporaryDirectory() as tmp:
        sd = _bundle_tree(tmp)
        ok, detail, summary = tc.compile_bundle(sd)
        assert ok, detail
        path = tc.bundle_path(sd)
        assert os.path.dirname(path) == tmp
        with zipfile.ZipFile(path) as zf:
            assert zf.testzip() is None
            assert sorted(zf.namelist()) == sorted(summary["names"])
            assert zf.read([n for n in zf.namelist() if n.endswith("loot.txt")][0]) == b"secrets"

        # rebuilding must not swallow the previous archive
        ok2, _detail, summary2 = tc.compile_bundle(sd)
        assert ok2 and summary2["names"] == summary["names"]


def test_compiling_nothing_is_an_honest_refusal():
    import tempfile, os
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, "output"))
        sd = types.SimpleNamespace(datadir=tmp, output_dir=os.path.join(tmp, "output"),
                                   netkbfile=os.path.join(tmp, "none.csv"),
                                   livestatusfile=os.path.join(tmp, "none2.csv"),
                                   crackedpwddir=os.path.join(tmp, "output", "crackedpwd"),
                                   telegram_include_creds=True)
        ok, detail, _ = tc.compile_bundle(sd)
        assert not ok and "nothing collected" in detail


def test_sending_before_compiling_says_so():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        sd = types.SimpleNamespace(datadir=tmp)
        ok, detail = tc.send_bundle(sd)
        assert not ok and "Compile first" in detail


def test_an_oversized_bundle_is_refused_before_the_upload():
    """Telegram bots reject documents over 50 MB. Naming the size beats posting a doomed upload
    and relaying whatever Telegram says about it."""
    import tempfile, os
    with tempfile.TemporaryDirectory() as tmp:
        sd = types.SimpleNamespace(datadir=tmp)
        with open(tc.bundle_path(sd), "wb") as f:
            f.write(b"0" * (tc.TELEGRAM_MAX_BYTES + 1))
        ok, detail = tc.send_bundle(sd)
        assert not ok and "download it instead" in detail


def test_a_numeric_chat_id_is_not_a_crash():
    """JSON gives back whatever was written: a chat id of 7961436291 parses as an int, and the old
    `(value or "").strip()` raised AttributeError -> bare HTTP 500 in the browser. Configs written
    by the pre-fix save path are already on disk, so the reader has to cope with them."""
    sd = _sd(telegram_bot_token="123:abc", telegram_chat_id=7961436291)
    assert tc._cfg_text(sd, "telegram_chat_id") == "7961436291"

    sent = {}
    saved = tc.send_message
    tc.send_message = lambda token, chat, text: (sent.update(token=token, chat=chat), (True, "sent"))[1]
    try:
        ok, detail = tc.send_test(sd)          # must not raise
    finally:
        tc.send_message = saved
    assert ok and detail == "sent via telegram"
    assert sent["chat"] == "7961436291", "the id must reach Telegram as text"

    # None and absent stay falsy rather than becoming the string "None"
    assert tc._cfg_text(_sd(telegram_chat_id=None), "telegram_chat_id") == ""
    assert tc._cfg_text(_sd(), "telegram_chat_id") == ""


def test_the_environment_outranks_the_saved_config():
    """The credentials can live in a systemd EnvironmentFile outside the Bjorn tree, so an
    uninstall (which removes /home/bjorn/Bjorn, never /etc/bjorn) does not take them with it — and
    so they are absent from the shared_config.json that /load_config serves. Env wins when set;
    the saved config still works untouched when it is not."""
    import os

    sd = _sd(telegram_bot_token="from-config", telegram_chat_id="111")
    saved = {k: os.environ.get(k) for k in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID")}
    try:
        os.environ["TELEGRAM_BOT_TOKEN"] = "from-env"
        os.environ["TELEGRAM_CHAT_ID"] = " 222 "          # whitespace from a hand-edited env file
        assert tc._cfg_text(sd, "telegram_bot_token") == "from-env"
        assert tc._cfg_text(sd, "telegram_chat_id") == "222"

        # Set-but-empty is not "configured" — an env file with TELEGRAM_CHAT_ID= must not blank
        # out a working config value.
        os.environ["TELEGRAM_CHAT_ID"] = ""
        assert tc._cfg_text(sd, "telegram_chat_id") == "111"

        del os.environ["TELEGRAM_BOT_TOKEN"], os.environ["TELEGRAM_CHAT_ID"]
        assert tc._cfg_text(sd, "telegram_bot_token") == "from-config"
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
