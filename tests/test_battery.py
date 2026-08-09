"""Tests for battery.py — the PiSugar reply parser and no-hardware fallback (PG-3).
Runs under pytest and as `python tests/test_battery.py` (zero install).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from battery import parse_pisugar_battery, read_percent  # noqa: E402


def test_parse_simple():
    assert parse_pisugar_battery("battery: 87.5") == 87.5


def test_parse_multiline():
    assert parse_pisugar_battery("model: PiSugar 3\nbattery: 12") == 12.0


def test_parse_clamps():
    assert parse_pisugar_battery("battery: 250") == 100.0
    assert parse_pisugar_battery("battery: -5") == 0.0


def test_parse_non_numeric_is_none():
    assert parse_pisugar_battery("battery: full") is None


def test_parse_missing_is_none():
    assert parse_pisugar_battery("no battery here") is None
    assert parse_pisugar_battery("") is None
    assert parse_pisugar_battery(None) is None


def test_read_percent_no_hardware_returns_none():
    # No PiSugar server on this box -> both transports fail -> None (graceful no-op, no raise).
    assert read_percent() is None


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
