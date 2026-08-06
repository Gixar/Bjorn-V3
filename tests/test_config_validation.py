"""Tests for config loading and validation — fail-fast config checks (PRD §9 step 4 / P1-6),
plus SharedData.load_config()'s default merge.
Runs under pytest and as `python tests/test_config_validation.py` (zero install — the heavy
imports shared.py pulls in are stubbed via _stubs).
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from config_validation import validate_config  # noqa: E402


def _good_config():
    return {
        "manual_mode": False, "websrv": True, "debug_mode": False, "scan_vuln_running": False,
        "startup_delay": 10, "scan_interval": 180, "scan_vuln_interval": 900,
        "failed_retry_delay": 600, "success_retry_delay": 900, "ref_width": 122, "ref_height": 250,
        "epd_type": "epd2in13_V4", "portlist": [22, 80, 443],
        "battery_monitor_enabled": False, "battery_shutdown_percent": 10,
        "vuln_scan_sv": True, "vuln_scan_vulners": True, "vuln_offline_cve": True,
        "bruteforce_threads": 0, "credential_reuse": True, "wpasec_interval": 3600,
        "telegram_enabled": False, "telegram_include_creds": True, "telegram_min_interval": 300,
        "ble_scan_enabled": False, "ble_scan_duration": 10, "ble_scan_interval": 300,
        "smtp_enabled": False, "smtp_port": 587,
        "wifi_scan_enabled": False, "wifi_scan_duration": 30, "wifi_scan_interval": 900,
        "wifi_scan_band": "bg", "wifi_scan_channel": 0,
        "use_rustscan": False, "rustscan_batch_size": 0, "rustscan_full_port": False,
    }


def test_valid_config_passes():
    assert validate_config(_good_config()) is None


def test_mock_epd_type_is_valid():
    cfg = _good_config()
    cfg["epd_type"] = "mock"
    assert validate_config(cfg) is None


def test_auto_epd_type_is_valid():
    cfg = _good_config()
    cfg["epd_type"] = "auto"
    assert validate_config(cfg) is None


def test_missing_key_raises():
    cfg = _good_config()
    del cfg["scan_interval"]
    _assert_raises(cfg, "scan_interval")


def test_wrong_bool_type_raises():
    cfg = _good_config()
    cfg["debug_mode"] = "yes"
    _assert_raises(cfg, "debug_mode")


def test_bool_is_not_accepted_as_int():
    # bool is an int subclass in Python — the validator must reject True where an int is required.
    cfg = _good_config()
    cfg["scan_interval"] = True
    _assert_raises(cfg, "scan_interval")


def test_negative_delay_raises():
    cfg = _good_config()
    cfg["failed_retry_delay"] = -1
    _assert_raises(cfg, "failed_retry_delay")


def test_unknown_epd_type_raises():
    cfg = _good_config()
    cfg["epd_type"] = "epd_does_not_exist"
    _assert_raises(cfg, "epd_type")


def test_all_errors_reported_at_once():
    cfg = _good_config()
    del cfg["websrv"]
    cfg["scan_interval"] = -5
    try:
        validate_config(cfg)
    except ValueError as e:
        assert "websrv" in str(e) and "scan_interval" in str(e)
    else:
        raise AssertionError("expected ValueError")


def _load_config_into(tmpdir, saved):
    """Drive SharedData.load_config() against a saved config file, unbound from __init__
    (which wants an e-Paper panel). Returns (instance, file contents after the load)."""
    import _stubs
    _stubs.install()
    sys.modules.pop("shared", None)  # _stubs installs a fake `shared`; we want the real module
    import shared

    path = Path(tmpdir) / "shared_config.json"
    path.write_text(json.dumps(saved), encoding="utf-8")

    sd = shared.SharedData.__new__(shared.SharedData)
    sd.configdir = str(tmpdir)
    sd.shared_config_json = str(path)
    sd.default_config = sd.get_default_config()
    sd.config = sd.default_config.copy()
    sd.load_config()
    return sd, json.loads(path.read_text(encoding="utf-8"))


def test_load_config_writes_missing_defaults_back_to_the_file():
    """A saved config predating an upgrade must gain the new keys on disk, not just in memory —
    everything that reads the file (the web config form, save_configuration) sees an incomplete
    config otherwise, so a new setting stays invisible in the UI."""
    with tempfile.TemporaryDirectory() as tmp:
        sd, on_disk = _load_config_into(tmp, {"scan_interval": 42})

        assert on_disk["scan_interval"] == 42, "the saved value must win over the default"
        for key in sd.default_config:
            assert key in on_disk, f"default key {key!r} was not written back to the config file"
        # Written in default order, so the form's __title_ section markers still group their keys.
        assert list(on_disk)[:len(sd.default_config)] == list(sd.default_config)


def test_load_config_does_not_rewrite_a_complete_file():
    """No key missing → no write. This runs at every boot; a Pi's SD card doesn't need it."""
    with tempfile.TemporaryDirectory() as tmp:
        import _stubs
        _stubs.install()
        sys.modules.pop("shared", None)
        import shared

        complete = shared.SharedData.get_default_config(None)
        path = Path(tmp) / "shared_config.json"
        path.write_text(json.dumps(complete), encoding="utf-8")
        before = path.stat().st_mtime_ns

        sd = shared.SharedData.__new__(shared.SharedData)
        sd.configdir, sd.shared_config_json = str(tmp), str(path)
        sd.default_config = complete
        sd.config = complete.copy()
        sd.load_config()

        assert path.stat().st_mtime_ns == before, "a complete config file was rewritten anyway"


def test_rejects_unknown_wifi_band():
    cfg = _good_config()
    cfg["wifi_scan_band"] = "5ghz"  # airodump wants a/b/g letters, not a friendly name
    _assert_raises(cfg, "wifi_scan_band")


def test_rejects_out_of_range_channel_but_allows_zero():
    """0 means 'hop every channel'. A typo'd channel captures nothing and looks like dead hardware,
    so it must fail loudly at startup instead."""
    cfg = _good_config()
    cfg["wifi_scan_channel"] = 0
    assert validate_config(cfg) is None
    cfg["wifi_scan_channel"] = 250
    _assert_raises(cfg, "wifi_scan_channel")


def _assert_raises(cfg, expected_substr):
    try:
        validate_config(cfg)
    except ValueError as e:
        assert expected_substr in str(e), f"{expected_substr!r} not in error: {e}"
    else:
        raise AssertionError(f"expected ValueError mentioning {expected_substr!r}")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
