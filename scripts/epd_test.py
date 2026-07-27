#!/usr/bin/env python3
"""Standalone e-Paper diagnostic — run ON the Pi, from the repo root:

    sudo python3 scripts/epd_test.py                # test the epd_type in config
    sudo python3 scripts/epd_test.py epd2in13_V3    # test one specific driver
    sudo python3 scripts/epd_test.py --all          # try every known driver (fresh process each)

Reports SPI status, then for each driver: load -> init -> draw a visible test pattern ->
clear, printing exactly which step fails (with traceback). Use it to find the driver that
matches your HAT when the display stays blank.
"""
import glob
import json
import os
import subprocess
import sys
import time
import traceback

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

# Drivers shipped in resources/waveshare_epd/.
CANDIDATES = ["epd2in13", "epd2in13_V2", "epd2in13_V3", "epd2in13_V4", "epd2in7"]


def config_epd_type():
    try:
        with open(os.path.join(REPO_ROOT, "config", "shared_config.json")) as f:
            return json.load(f).get("epd_type")
    except Exception:
        return None


def check_spi():
    devices = glob.glob("/dev/spidev*")
    if devices:
        print(f"[SPI] OK — found {', '.join(devices)}")
    else:
        print("[SPI] NONE FOUND — the most common cause of a blank e-Paper.\n"
              "      Enable it: sudo raspi-config -> Interface Options -> SPI -> Yes\n"
              "      (or add `dtparam=spi=on` to /boot/firmware/config.txt), then reboot.")


def test_one(epd_type):
    print(f"\n=== Testing epd_type={epd_type!r} ===")
    try:
        from PIL import Image, ImageDraw
        from epd_helper import EPDHelper
    except Exception:
        print("Could not import PIL / epd_helper — run this from the repo root on the Pi.")
        traceback.print_exc()
        return False
    try:
        print(f"[1/5] loading driver resources.waveshare_epd.{epd_type} ...")
        helper = EPDHelper(epd_type)
        print("[2/5] init_full_update() ...")
        helper.init_full_update()
        w, h = helper.epd.width, helper.epd.height
        print(f"      panel size: {w}x{h}")
        print("[3/5] drawing test pattern ...")
        img = Image.new("1", (w, h), 255)
        d = ImageDraw.Draw(img)
        d.rectangle((0, 0, w - 1, h - 1), outline=0)
        d.rectangle((0, 0, w - 1, 22), fill=0)
        d.text((4, 6), f"BJORN {epd_type}", fill=255)
        d.text((4, 30), f"{w}x{h}", fill=0)
        d.line((0, 0, w - 1, h - 1), fill=0)
        print("[4/5] display ...")
        buf = helper.epd.getbuffer(img)
        if hasattr(helper.epd, "display"):
            helper.epd.display(buf)
        else:
            helper.epd.displayPartial(buf)
        time.sleep(3)
        print("[5/5] clear ...")
        helper.clear()
        print(f"RESULT: driver '{epd_type}' ran without error.")
        print("        -> If a pattern appeared on the panel, set this as epd_type in "
              "config/shared_config.json.")
        print("        -> If the driver ran but nothing appeared, it's the wrong panel version "
              "or a wiring/SPI issue.")
        return True
    except Exception:
        print(f"RESULT: driver '{epd_type}' FAILED:")
        traceback.print_exc()
        return False


def main():
    args = sys.argv[1:]
    check_spi()
    if args == ["--all"]:
        # Fresh process per driver so GPIO/SPI pins are released between attempts.
        for v in CANDIDATES:
            subprocess.run([sys.executable, os.path.abspath(__file__), v])
        return
    if args:
        test_one(args[0])
    else:
        t = config_epd_type()
        print(f"[config] epd_type = {t!r}")
        test_one(t or "epd2in13_V4")


if __name__ == "__main__":
    main()
