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


def test_offline_uses_the_shorter_interval():
    """The throttle honours ble_scan_interval_offline when there is no uplink. 5 minutes is a
    cadence tuned for 'don't disturb the real job'; carried around with no uplink there is no real
    job, and BLE is the only recon still collecting."""
    import time
    import tempfile
    from types import SimpleNamespace
    import actions.ble_scan as mod

    cfg = SimpleNamespace(scan_results_dir=tempfile.mkdtemp(prefix="bjorn_ble_test_"),
                          ble_scan_enabled=True, ble_scan_duration=3,
                          ble_scan_interval=300, ble_scan_interval_offline=60)
    scanner = BLEScan(cfg)
    scanner._scan = lambda *a: []          # no bluetoothctl, no devices to record
    real_which, real_online = mod.shutil.which, mod.offline_mode.is_online
    mod.shutil.which = lambda _: "/usr/bin/bluetoothctl"
    try:
        # 120s since the last scan: inside the 300s online floor, past the 60s offline one.
        mod.offline_mode.is_online = lambda: True
        scanner._last_scan = time.time() - 120
        assert scanner.execute() == 'skipped'

        mod.offline_mode.is_online = lambda: False
        scanner._last_scan = time.time() - 120
        assert scanner.execute() == 'success'
    finally:
        mod.shutil.which, mod.offline_mode.is_online = real_which, real_online


def test_no_bluetooth_controller_skips_rather_than_reporting_success():
    """#5 side-effect verification: a bare Pi with no BT adapter must not report a hollow success
    every cycle. bluetoothctl `power on` prints 'No default controller available'; _scan returns
    None on that (distinct from [] = scanned, nothing nearby) and execute() skips — a scan that
    cannot run is not a success (the WiFiScan: success=4 class)."""
    import tempfile
    from types import SimpleNamespace
    import actions.ble_scan as mod

    cfg = SimpleNamespace(scan_results_dir=tempfile.mkdtemp(prefix="bjorn_ble_test_"),
                          ble_scan_enabled=True, ble_scan_duration=3, ble_scan_interval=0)
    scanner = BLEScan(cfg)
    real_which, real_online, real_run = (mod.shutil.which, mod.offline_mode.is_online,
                                         mod.subprocess.run)
    mod.shutil.which = lambda _n: "/usr/bin/bluetoothctl"
    mod.offline_mode.is_online = lambda: True

    def fake_run(cmd, **kwargs):
        out = "No default controller available\n" if cmd[1:3] == ["power", "on"] else ""
        return SimpleNamespace(stdout=out, stderr="", returncode=1)

    mod.subprocess.run = fake_run
    try:
        assert scanner.execute() == 'skipped', "no BT controller must skip, not report success"
    finally:
        (mod.shutil.which, mod.offline_mode.is_online,
         mod.subprocess.run) = real_which, real_online, real_run


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
