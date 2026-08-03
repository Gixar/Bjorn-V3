"""Tests for the CSV formula-injection guard (CWE-1236, csv_safe.py). Pure stdlib module."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from csv_safe import sanitize_cell, sanitize_row  # noqa: E402


def test_formula_triggers_get_apostrophe():
    for bad in ("=cmd|'/c calc'!A0", "+1+1", "-2+3", "@SUM(A1)", "\tTAB", "\rCR"):
        out = sanitize_cell(bad)
        assert out == "'" + bad, out


def test_normal_values_untouched():
    for ok in ("Linux router 5.4", "public", "OpenSSH 7.6p1", "192.168.1.6", "80;443"):
        assert sanitize_cell(ok) == ok


def test_none_and_numbers():
    assert sanitize_cell(None) == ""
    assert sanitize_cell(200) == "200"          # coerced to str, no leading trigger
    assert sanitize_cell("") == ""


def test_sanitize_row_maps_each_cell():
    assert sanitize_row(["=evil", "ok", None, "@x"]) == ["'=evil", "ok", "", "'@x"]


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
