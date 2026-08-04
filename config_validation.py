# config_validation.py
# Fail-fast validation for shared_config.json (PRD §9 step 4 / P1-6). Kept dependency-free
# and separate from shared.py so it can be unit-tested without constructing SharedData
# (which pulls in PIL and the e-Paper stack).

# epd_type values with a driver module in resources/waveshare_epd/ (+ the mock backend and
# "auto", which probes the real-panel drivers at startup — see SharedData._auto_detect_epd).
KNOWN_EPD_TYPES = {
    "epd2in13", "epd2in13_V2", "epd2in13_V3", "epd2in13_V4", "epd2in7", "mock", "auto",
}

_BOOL_KEYS = ("manual_mode", "websrv", "debug_mode", "scan_vuln_running",
              "battery_monitor_enabled", "vuln_scan_sv", "vuln_scan_vulners",
              "vuln_offline_cve", "use_rustscan", "rustscan_full_port",
              "credential_reuse", "telegram_enabled", "telegram_include_creds",
              "ble_scan_enabled")
# These must be non-negative integers (JSON bools are excluded — bool is an int subclass).
_NONNEG_INT_KEYS = (
    "startup_delay", "scan_interval", "scan_vuln_interval",
    "failed_retry_delay", "success_retry_delay", "ref_width", "ref_height",
    "battery_shutdown_percent", "bruteforce_threads", "rustscan_batch_size",
    "wpasec_interval", "telegram_min_interval",
    "ble_scan_duration", "ble_scan_interval",
)


def validate_config(config):
    """Check the safety-critical config keys. Returns None on success; raises ValueError
    listing every problem found (so one run surfaces all of them, not just the first)."""
    errors = []

    for key in _BOOL_KEYS:
        if key not in config:
            errors.append(f"missing required key: {key!r}")
        elif not isinstance(config[key], bool):
            errors.append(f"{key!r} must be true/false, got {type(config[key]).__name__}")

    for key in _NONNEG_INT_KEYS:
        if key not in config:
            errors.append(f"missing required key: {key!r}")
        elif isinstance(config[key], bool) or not isinstance(config[key], int):
            errors.append(f"{key!r} must be an integer, got {type(config[key]).__name__}")
        elif config[key] < 0:
            errors.append(f"{key!r} must be >= 0, got {config[key]}")

    epd = config.get("epd_type")
    if epd is None:
        errors.append("missing required key: 'epd_type'")
    elif epd not in KNOWN_EPD_TYPES:
        errors.append(f"'epd_type' {epd!r} is not one of {sorted(KNOWN_EPD_TYPES)}")

    if "portlist" not in config:
        errors.append("missing required key: 'portlist'")
    elif not isinstance(config["portlist"], list):
        errors.append(f"'portlist' must be a list, got {type(config['portlist']).__name__}")

    if errors:
        raise ValueError("Invalid configuration:\n  - " + "\n  - ".join(errors))
