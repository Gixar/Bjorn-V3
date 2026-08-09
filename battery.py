# battery.py
# Optional battery/UPS awareness (PG-3). Reads the charge percentage from a PiSugar power
# manager if one is present, so Bjorn can shut down cleanly before the battery dies (the only
# real "impending power loss" signal — a yanked wall plug gives no warning). Dependency-free
# (stdlib sockets); returns None whenever no battery hardware/server is reachable, so it's a
# safe no-op on a mains-powered Pi. Opt in via `battery_monitor_enabled` in the config.

import socket

# PiSugar's pisugar-server exposes a tiny text protocol on TCP 8423 and a Unix socket.
_PISUGAR_TCP = ("127.0.0.1", 8423)
_PISUGAR_UNIX = "/tmp/pisugar-server.sock"


def parse_pisugar_battery(response):
    """Parse a percentage out of a PiSugar 'get battery' reply like 'battery: 87.5'.
    Returns a float clamped to 0..100, or None if no percentage is present."""
    if not response:
        return None
    for line in str(response).splitlines():
        line = line.strip()
        if line.lower().startswith("battery:"):
            try:
                pct = float(line.split(":", 1)[1].strip())
            except (ValueError, IndexError):
                return None
            return max(0.0, min(100.0, pct))
    return None


def _query(sock, command, timeout=1.0):
    sock.settimeout(timeout)
    sock.sendall((command + "\n").encode())
    return sock.recv(256).decode(errors="replace")


def _pisugar_tcp():
    with socket.create_connection(_PISUGAR_TCP, timeout=1.0) as s:
        return _query(s, "get battery")


def _pisugar_unix():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.settimeout(1.0)
        s.connect(_PISUGAR_UNIX)
        return _query(s, "get battery")
    finally:
        s.close()


def read_percent():
    """Battery charge as a float 0..100, or None if no battery hardware is reachable."""
    for reader in (_pisugar_tcp, _pisugar_unix):
        try:
            pct = parse_pisugar_battery(reader())
            if pct is not None:
                return pct
        except Exception:
            continue  # no server / not this transport — try the next, else report None
    return None


if __name__ == "__main__":
    # ponytail: one runnable check for the parser (the pure, testable part).
    assert parse_pisugar_battery("battery: 87.5") == 87.5
    assert parse_pisugar_battery("model: PiSugar 3\nbattery: 12") == 12.0
    assert parse_pisugar_battery("battery: 250") == 100.0   # clamp
    assert parse_pisugar_battery("battery: -5") == 0.0      # clamp
    assert parse_pisugar_battery("no battery here") is None
    assert parse_pisugar_battery("") is None
    pct = read_percent()
    print(f"parser ok; live read_percent() -> {pct}")
