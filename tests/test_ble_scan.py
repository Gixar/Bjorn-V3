"""Tests for BLE recon (backlog Wave 2 #6): bluetoothctl `devices` parsing (incl. ANSI stripping)
and the tracker heuristic. Pure static methods — no bluetoothctl. Heavy imports stubbed via _stubs.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _stubs  # noqa: E402
_stubs.install()

from actions.ble_scan import BLEScan  # noqa: E402

parse = BLEScan._parse_devices


def test_parses_mac_and_name():
    out = "Device AA:BB:CC:DD:EE:FF Kitchen Speaker\nDevice 11:22:33:44:55:66 11-22-33-44-55-66\n"
    assert parse(out) == [("AA:BB:CC:DD:EE:FF", "Kitchen Speaker"),
                          ("11:22:33:44:55:66", "11-22-33-44-55-66")]


def test_device_without_name():
    assert parse("Device AA:BB:CC:DD:EE:FF\n") == [("AA:BB:CC:DD:EE:FF", "")]


def test_strips_ansi_and_ignores_noise():
    out = "\x1b[0;92m[NEW]\x1b[0m junk line\nDevice A1:B2:C3:D4:E5:F6 \x1b[0;94mMyTile\x1b[0m\n"
    assert parse(out) == [("A1:B2:C3:D4:E5:F6", "MyTile")]


def test_tracker_heuristic():
    assert BLEScan._is_tracker("Someone's AirTag") is True
    assert BLEScan._is_tracker("Tile Mate") is True
    assert BLEScan._is_tracker("Galaxy SmartTag") is True
    assert BLEScan._is_tracker("Kitchen Speaker") is False
    assert BLEScan._is_tracker("") is False


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
