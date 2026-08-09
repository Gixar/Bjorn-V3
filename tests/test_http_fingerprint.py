"""Tests for HTTP fingerprinting (backlog Wave 2): web-port selection (+TLS flags) and <title>
extraction. Pure static methods — no network. Heavy imports (shared/logger) stubbed via _stubs.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _stubs  # noqa: E402
_stubs.install()

from actions.http_fingerprint import HTTPFingerprint  # noqa: E402

web_ports = HTTPFingerprint._web_ports
title = HTTPFingerprint._extract_title


def test_web_ports_filters_and_flags_tls():
    # only web ports, in WEB_PORTS order, with the TLS flag
    assert web_ports(["22", "8080", "443", "80"]) == [("80", False), ("443", True), ("8080", False)]


def test_web_ports_none_when_no_web_service():
    assert web_ports(["22", "53", "3306"]) == []


def test_extract_title_collapses_whitespace():
    assert title("<html><head><TITLE> My  Router\n Login </TITLE></head>") == "My Router Login"


def test_extract_title_missing_returns_empty():
    assert title("<html>no title element here</html>") == ""


def test_extract_title_truncates_long():
    assert len(title("<title>" + "x" * 300 + "</title>")) == 120


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
