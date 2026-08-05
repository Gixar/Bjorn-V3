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


info = BLEScan._tracker_from_info


def test_tracker_from_service_uuid():
    out = ("Device AA:BB:CC:DD:EE:FF (random)\n"
           "\tAlias: AA-BB-CC-DD-EE-FF\n"
           "\tUUID: Vendor specific           (0000fd44-0000-1000-8000-00805f9b34fb)\n")
    assert info(out) == "Apple Find My"
    assert info(out.replace("0000fd44", "0000feed")) == "Tile"
    assert info(out.replace("0000fd44", "0000fd5a")) == "Samsung SmartTag"


def test_tracker_from_apple_offline_finding_manufacturer_data():
    inline = ("Device AA:BB:CC:DD:EE:FF (random)\n"
              "\tManufacturerData Key: 0x004c\n"
              "\tManufacturerData Value: 0x12 0x19 0x00\n")
    assert info(inline) == "Apple Find My"
    split = ("Device AA:BB:CC:DD:EE:FF (random)\n"
             "\tManufacturerData Key: 0x004c\n"
             "\tManufacturerData Value:\n"
             "  12 19 00 aa bb\n")
    assert info(split) == "Apple Find My"


def test_ordinary_apple_device_is_not_a_tracker():
    # 0x004c with a non-offline-finding payload type (0x10 = nearby/handoff) — a phone, not a tag.
    out = ("Device AA:BB:CC:DD:EE:FF (random)\n"
           "\tManufacturerData Key: 0x004c\n"
           "\tManufacturerData Value: 0x10 0x05 0x0a\n")
    assert info(out) == ""


def test_unremarkable_device_and_ansi_noise():
    assert info("") == ""
    assert info("\tUUID: Battery Service (0000180f-0000-1000-8000-00805f9b34fb)\n") == ""
    assert info("\t\x1b[0;94mUUID\x1b[0m: (0000feec-0000-1000-8000-00805f9b34fb)\n") == "Tile"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
