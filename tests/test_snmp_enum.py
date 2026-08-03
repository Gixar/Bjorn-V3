"""Tests for SNMP enumeration (backlog Wave 2): the snmpget argv builder and value cleaning.
Pure static methods — no network, no snmpget. Heavy imports (shared/logger) stubbed via _stubs.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _stubs  # noqa: E402
_stubs.install()

from actions.snmp_enum import SNMPEnum, OID_SYSDESCR  # noqa: E402


def test_snmpget_cmd():
    cmd = SNMPEnum._snmpget_cmd("/usr/bin/snmpget", "public", "10.0.0.5", OID_SYSDESCR)
    assert cmd == ["/usr/bin/snmpget", "-v2c", "-c", "public", "-t", "1", "-r", "0", "-Ovq",
                   "10.0.0.5", OID_SYSDESCR]


def test_clean_value_strips_quotes_and_whitespace():
    assert SNMPEnum._clean_value('  "Linux router 5.4.0"  \n') == "Linux router 5.4.0"
    assert SNMPEnum._clean_value("plain-value") == "plain-value"
    assert SNMPEnum._clean_value("") == ""


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
