"""Tests for config_validation — fail-fast config checks (PRD §9 step 4 / P1-6).
Runs under pytest and as `python tests/test_config_validation.py` (zero install).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config_validation import validate_config  # noqa: E402


def _good_config():
    return {
        "manual_mode": False, "websrv": True, "debug_mode": False, "scan_vuln_running": False,
        "startup_delay": 10, "scan_interval": 180, "scan_vuln_interval": 900,
        "failed_retry_delay": 600, "success_retry_delay": 900, "ref_width": 122, "ref_height": 250,
        "epd_type": "epd2in13_V4", "portlist": [22, 80, 443],
        "battery_monitor_enabled": False, "battery_shutdown_percent": 10,
        "vuln_scan_sv": True, "vuln_scan_vulners": True, "vuln_offline_cve": True,
        "bruteforce_threads": 0,
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
