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


def test_clean_value_rejects_snmp_non_answers():
    """#5 side-effect verification: snmpget -Ovq exits 0 while printing these for an unserved OID,
    so without filtering, a host that answered but doesn't serve sysDescr would be recorded as a
    found SNMP host with the error phrase as its description — a hollow success. _clean_value must
    treat them as empty (no value → no hit → not recorded), while leaving a real sysDescr intact."""
    for phrase in ("No Such Object available on this agent at this OID",
                   "No Such Instance currently exists at this OID",
                   "No more variables left in this MIB View (It is past the end of the MIB tree)"):
        assert SNMPEnum._clean_value(phrase) == "", f"non-answer not filtered: {phrase!r}"
    # A genuine description that merely contains the word 'object' is still a real value.
    assert SNMPEnum._clean_value("HP LaserJet object store v3") == "HP LaserJet object store v3"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
