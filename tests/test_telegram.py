"""Tests for the Telegram client (backlog Wave 2): API URL, multipart body builder, and the
change-detection signature. Pure — no network. telegram_client is stdlib-only, imported directly.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import telegram_client as tc  # noqa: E402


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


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
