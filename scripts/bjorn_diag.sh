#!/bin/bash
# bjorn_diag.sh — deep diagnostic report for a Bjorn install (SSH-friendly).
#
# Read-only. Safe to run while Bjorn is up. Works even when the service is down.
# Collects system health, service/process state, network, e-Paper/SPI, tool
# availability, netkb/stats summary, config highlights, log errors, and recent
# orchestrator activity — everything useful to improve or debug the device.
#
# Usage:
#   sudo bash /home/bjorn/Bjorn/scripts/bjorn_diag.sh
#   sudo bash /home/bjorn/Bjorn/scripts/bjorn_diag.sh | tee /tmp/bjorn_diag.txt
#   sudo bash /home/bjorn/Bjorn/scripts/bjorn_diag.sh --save   # writes timestamped file under data/output/
#
# Optional flags:
#   --save          write report to data/output/diag_YYYYMMDD_HHMMSS.txt
#   --short         skip long log tails (faster)
#   --repo PATH     override Bjorn install path
#
# Prefer sudo so journal + install logs + some /proc details are readable.

set -u
# intentionally NOT set -e — greps with no match must not abort the report

SHORT=0
DO_SAVE=0
REPO_OVERRIDE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --short) SHORT=1; shift ;;
        --save)  DO_SAVE=1; shift ;;
        --repo)  REPO_OVERRIDE="${2:-}"; shift 2 ;;
        -h|--help)
            sed -n '2,25p' "$0"
            exit 0
            ;;
        *) echo "Unknown flag: $1 (try --help)"; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")")" && pwd)"
if [ -n "$REPO_OVERRIDE" ]; then
    REPO="$REPO_OVERRIDE"
else
    REPO="$(dirname "$SCRIPT_DIR")"
fi
DATA="$REPO/data"
LOGS="$DATA/logs"
OUT="$DATA/output"
CFG="$REPO/config/shared_config.json"
NETKB="$DATA/netkb.csv"
LIVE="$DATA/livestatus.csv"
STATS="$DATA/stats.json"
HEARTBEAT="/run/bjorn_heartbeat"

# Optional capture to file via --save
REPORT_FILE=""
if [ "$DO_SAVE" -eq 1 ]; then
    mkdir -p "$OUT" 2>/dev/null || true
    REPORT_FILE="$OUT/diag_$(date +%Y%m%d_%H%M%S).txt"
    # shellcheck disable=SC2094
    exec > >(tee "$REPORT_FILE") 2>&1
    TEE_PID=$!
    # The shell can exit before the tee in the process substitution has flushed, silently
    # truncating the tail of the saved file — the part with the recommendations in it.
    trap 'exec 1>&-; [ -n "${TEE_PID:-}" ] && wait "$TEE_PID" 2>/dev/null' EXIT
fi

# Colour only on a terminal. The whole point of this script is output you paste into an issue or
# save with --save; escape codes in a text file are noise, and --save pipes through tee so stdout
# is never a TTY there anyway.
if [ -t 1 ]; then
    C_BOLD=$'\033[1m'; C_WARN=$'\033[33m'; C_BAD=$'\033[31m'; C_OFF=$'\033[0m'
else
    C_BOLD=""; C_WARN=""; C_BAD=""; C_OFF=""
fi

section() { printf '\n%s=== %s ===%s\n' "$C_BOLD" "$1" "$C_OFF"; }
have()    { command -v "$1" >/dev/null 2>&1; }
ok()      { printf '  %-22s %s\n' "$1" "$2"; }
warn()    { printf '  %-22s %s%s%s\n' "$1" "$C_WARN" "$2" "$C_OFF"; }
bad()     { printf '  %-22s %s%s%s\n' "$1" "$C_BAD" "$2" "$C_OFF"; }

echo "Bjorn diagnostic report — $(date -Is 2>/dev/null || date)"
echo "Host: $(hostname 2>/dev/null || echo '?')  |  User: $(id -un 2>/dev/null)  |  Sudo: $([ "$(id -u)" -eq 0 ] && echo yes || echo no)"
echo "Repo: $REPO"

# ===========================================================================
section "1. Version & environment"
# ===========================================================================
ok "version" "$(cat "$REPO/version.txt" 2>/dev/null || echo '?')  (release tag — NOT bumped per commit)"
# The commit is what actually says which code is running. version.txt lags by design, and a report
# reading only "2.5.0-alpha" once described a device many merged commits behind with nothing to
# hint at it. `-c safe.directory` because this runs under sudo against a repo owned by another
# user, which git otherwise refuses to read; it mutates no config.
GIT="git -c safe.directory=$REPO -C $REPO"
if have git && $GIT rev-parse --git-dir >/dev/null 2>&1; then
    dirty=""; [ -n "$($GIT status --porcelain 2>/dev/null)" ] && dirty="  (UNCOMMITTED CHANGES)"
    ok "commit" "$($GIT log -1 --format='%h %cs %s' 2>/dev/null | cut -c1-90)$dirty"
    ok "branch" "$($GIT rev-parse --abbrev-ref HEAD 2>/dev/null)"
    behind="$($GIT rev-list --count HEAD..@{upstream} 2>/dev/null || true)"
    if [ -n "${behind:-}" ] && [ "${behind:-0}" -gt 0 ] 2>/dev/null; then
        warn "upstream" "$behind commit(s) BEHIND — git pull before trusting this report"
    else
        ok "upstream" "up to date (or no tracking branch)"
    fi
else
    warn "commit" "? (not a git checkout)"
fi
ok "python"  "$(python3 --version 2>&1)"
if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    ok "os" "${PRETTY_NAME:-?}"
fi
ok "kernel" "$(uname -r)"
ok "arch"   "$(uname -m)"
ok "uptime" "$(uptime -p 2>/dev/null || uptime)"
ok "boot"   "$(who -b 2>/dev/null | awk '{print $3,$4}' || echo '?')"

# The Pi has no RTC: it boots at the fake-hwclock time and jumps when NTP lands. Anything netkb
# stamped before that sync is dated ahead of everything after it, which used to park actions in a
# retry window until the clock "caught up". A boot date near 1970 is the tell.
if have timedatectl; then
    synced="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo '?')"
    if [ "$synced" = "yes" ]; then
        ok "clock_synced" "yes"
    else
        warn "clock_synced" "$synced - timestamps written before sync are unreliable"
    fi
fi

if [ -f "$REPO/action_planner.py" ]; then
    ok "action_planner" "present (scored work selection)"
else
    warn "action_planner" "missing — this checkout predates the planner; git pull"
fi

# ===========================================================================
section "2. Resources (CPU / memory / disk / thermal)"
# ===========================================================================
if have free; then
    free -h 2>/dev/null | sed 's/^/  /'
else
    ok "meminfo" "$(awk '/MemTotal|MemAvailable|MemFree/{print $1,$2}' /proc/meminfo 2>/dev/null | tr '\n' ' ')"
fi
echo
ok "loadavg" "$(cat /proc/loadavg 2>/dev/null || echo '?')"
if [ -f /sys/class/thermal/thermal_zone0/temp ]; then
    t="$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null || echo 0)"
    # millidegrees on Pi
    if [ "$t" -gt 1000 ] 2>/dev/null; then
        c=$((t / 1000))
    else
        c="$t"
    fi
    if [ "$c" -ge 80 ] 2>/dev/null; then
        bad "cpu_temp_c" "${c}  (hot — throttling risk)"
    elif [ "$c" -ge 70 ] 2>/dev/null; then
        warn "cpu_temp_c" "${c}"
    else
        ok "cpu_temp_c" "${c}"
    fi
fi
# throttled flags (Pi)
if have vcgencmd; then
    ok "throttled" "$(vcgencmd get_throttled 2>/dev/null || echo n/a)"
    ok "arm_freq"  "$(vcgencmd measure_clock arm 2>/dev/null || echo n/a)"
fi
echo
echo "  Disk:"
df -h "$REPO" / /home 2>/dev/null | sed 's/^/  /' || df -h | sed 's/^/  /'
# SD card wear hint: root on mmc
root_src="$(findmnt -n -o SOURCE / 2>/dev/null || true)"
ok "root_device" "${root_src:-?}"

# ===========================================================================
section "3. Service & process"
# ===========================================================================
if have systemctl; then
    en="$(systemctl is-enabled bjorn.service 2>&1 || true)"
    ac="$(systemctl is-active  bjorn.service 2>&1 || true)"
    case "$ac" in
        active) ok "active" "$ac" ;;
        *)      bad "active" "$ac" ;;
    esac
    ok "enabled" "$en"
    echo
    systemctl status bjorn.service --no-pager -l 2>&1 | sed 's/^/  /' | head -20
    echo
    # restart / crash history
    if have journalctl; then
        echo "  Recent starts / stops (journal):"
        journalctl -u bjorn.service --no-pager -n 30 2>/dev/null \
            | grep -Ei 'Started|Stopped|Failed|Main process|heartbeat|watchdog|Restart' \
            | tail -15 | sed 's/^/  /' || echo "  (none)"
    fi
else
    warn "systemctl" "not available"
fi

# Process details
echo
pids="$(pgrep -f '[Bb]jorn\.py' 2>/dev/null || true)"
if [ -n "$pids" ]; then
    for pid in $pids; do
        ok "bjorn_pid" "$pid"
        if [ -r "/proc/$pid/status" ]; then
            rss_kb="$(awk '/VmRSS/{print $2}' "/proc/$pid/status" 2>/dev/null || echo 0)"
            threads="$(awk '/Threads/{print $2}' "/proc/$pid/status" 2>/dev/null || echo '?')"
            ok "rss_mb" "$((rss_kb / 1024))"
            ok "threads" "$threads"
        fi
        if [ -d "/proc/$pid/fd" ]; then
            fd_count="$(ls "/proc/$pid/fd" 2>/dev/null | wc -l)"
            ok "open_fds" "$fd_count"
            # soft limit
            if [ -r "/proc/$pid/limits" ]; then
                soft="$(awk '/Max open files/{print $4}' "/proc/$pid/limits" 2>/dev/null || echo '?')"
                ok "fd_soft_limit" "$soft"
                if [ "$fd_count" -gt 0 ] && [ "$soft" != "?" ] 2>/dev/null; then
                    if [ "$fd_count" -gt $((soft * 8 / 10)) ] 2>/dev/null; then
                        bad "fd_pressure" "open FDs near limit — risk of Errno 24"
                    fi
                fi
            fi
        fi
        # cmdline
        if [ -r "/proc/$pid/cmdline" ]; then
            ok "cmdline" "$(tr '\0' ' ' < "/proc/$pid/cmdline" | head -c 160)"
        fi
    done
else
    bad "bjorn_pid" "not running"
fi

# Watchdog heartbeat (PG-4)
echo
if [ -f "$HEARTBEAT" ]; then
    hb="$(cat "$HEARTBEAT" 2>/dev/null || echo 0)"
    now="$(date +%s)"
    age=$((now - hb)) 2>/dev/null || age="?"
    if [ "$age" != "?" ] && [ "$age" -lt 120 ] 2>/dev/null; then
        ok "heartbeat_age_s" "$age  (fresh)"
    elif [ "$age" != "?" ] && [ "$age" -lt 300 ] 2>/dev/null; then
        warn "heartbeat_age_s" "$age  (stale — main loop may be slow)"
    else
        bad "heartbeat_age_s" "${age}  (very stale or wedged)"
    fi
else
    warn "heartbeat" "no $HEARTBEAT (service never started, or not on Pi)"
fi

# Port 8000
echo
if have ss; then
    ok "listen_8000" "$(ss -ltnp 2>/dev/null | grep -E ':8000\b' || echo 'not listening')"
elif have lsof; then
    ok "listen_8000" "$(lsof -iTCP:8000 -sTCP:LISTEN 2>/dev/null || echo 'not listening')"
else
    ok "listen_8000" "$(grep -r 8000 /proc/net/tcp 2>/dev/null | head -1 || echo '?')"
fi

# ===========================================================================
section "4. Network"
# ===========================================================================
echo "  Interfaces:"
ip -br addr 2>/dev/null | sed 's/^/  /' || ifconfig 2>/dev/null | sed 's/^/  /' | head -40
echo
# Wi-Fi
if have nmcli; then
    ok "wifi_radio" "$(nmcli -t -f WIFI g 2>/dev/null || echo '?')"
    ok "wifi_active" "$(nmcli -t -f ACTIVE,SSID,SIGNAL,DEVICE dev wifi 2>/dev/null | grep '^yes' | head -3 || echo 'none')"
    ok "nm_connectivity" "$(nmcli networking connectivity check 2>/dev/null || echo '?')"
else
    warn "nmcli" "not installed"
fi
# Default route
ok "default_route" "$(ip route show default 2>/dev/null | head -1 || echo none)"
# usb0 gadget
if ip link show usb0 >/dev/null 2>&1; then
    ok "usb0" "$(ip -br addr show usb0 2>/dev/null)"
    ok "usb0_carrier" "$(cat /sys/class/net/usb0/carrier 2>/dev/null || echo '?')"
else
    warn "usb0" "interface not present"
fi
# Own IPs (should be excluded from scans)
echo
echo "  Local IPv4 (scan blacklist candidates):"
ip -4 -br addr 2>/dev/null | sed 's/^/  /' || true

# ===========================================================================
section "5. Display / SPI / I2C"
# ===========================================================================
if ls /dev/spidev* >/dev/null 2>&1; then
    ok "SPI" "OK ($(ls /dev/spidev* 2>/dev/null | tr '\n' ' '))"
else
    bad "SPI" "NOT ENABLED — blank e-Paper is expected"
    echo "         fix: sudo raspi-config nonint do_spi 0 && sudo reboot"
fi
if ls /dev/i2c* >/dev/null 2>&1; then
    ok "I2C" "OK ($(ls /dev/i2c* 2>/dev/null | tr '\n' ' '))"
else
    warn "I2C" "no /dev/i2c* (only needed for some HATs / battery)"
fi
if [ -f "$CFG" ]; then
    epd="$(python3 -c "import json;print(json.load(open('$CFG')).get('epd_type','?'))" 2>/dev/null \
        || grep -o '"epd_type"[[:space:]]*:[[:space:]]*"[^"]*"' "$CFG" 2>/dev/null | head -1)"
    ok "epd_type" "$epd"
fi
# Groups for gpio/spi
if have groups; then
    ok "groups_root" "$(groups root 2>/dev/null || true)"
fi
echo "  Blank panel? Stop service first, then probe:"
echo "    sudo systemctl stop bjorn && sudo python3 $SCRIPT_DIR/epd_test.py --all"

# ===========================================================================
section "6. External tools (what Bjorn can actually run)"
# ===========================================================================
check_bin() {
    local name="$1"
    local path
    path="$(command -v "$name" 2>/dev/null || true)"
    if [ -n "$path" ]; then
        local ver
        ver="$("$name" --version 2>&1 | head -1 | tr -d '\r' | cut -c1-60)"
        ok "$name" "$path  |  $ver"
    else
        # common alt paths for rustscan
        if [ "$name" = rustscan ]; then
            for p in /usr/local/bin/rustscan /usr/bin/rustscan /home/*/.cargo/bin/rustscan /root/.cargo/bin/rustscan; do
                if [ -x "$p" ]; then
                    ok "rustscan" "$p (off PATH)"
                    return
                fi
            done
        fi
        warn "$name" "NOT FOUND"
    fi
}
check_bin nmap
check_bin nmcli
check_bin rustscan
check_bin bluetoothctl
check_bin snmpget
check_bin python3
check_bin systemctl

# nmap scripts db age
if have nmap && [ -d /usr/share/nmap/scripts ]; then
    ok "nmap_scripts" "$(ls /usr/share/nmap/scripts 2>/dev/null | wc -l) scripts"
fi

# ===========================================================================
section "7. Config highlights"
# ===========================================================================
# This report gets pasted into issues, so the config section is an explicit ALLOW-list and every
# value is passed through a redactor. The old fallback here was a grep for '...|telegram|...',
# which happily printed telegram_bot_token; a diagnostic that leaks the secrets it is meant to help
# you debug is worse than one that omits the section. Fallback is now key names only, no values.
if [ -f "$CFG" ]; then
    python3 - "$CFG" <<'PY' 2>/dev/null || { echo "  (python3 unavailable — key names only, values withheld)"; grep -oE '"[a-z_]+"[[:space:]]*:' "$CFG" 2>/dev/null | tr -d '":' | head -60 | sed 's/^/    /'; }
import json, sys
cfg = json.load(open(sys.argv[1]))
SECRET = ("token", "password", "api_key", "secret", "passwd")
def show(k, v):
    if any(p in k.lower() for p in SECRET):
        return "<set>" if v else "<empty>"   # presence is diagnostic, the value never is
    return repr(v)
keys = [
    "manual_mode", "websrv", "debug_mode", "epd_type",
    "scan_interval", "adaptive_scan_interval", "scan_vuln_interval", "scan_vuln_running",
    "failed_retry_delay", "success_retry_delay", "retry_success_actions",
    "use_rustscan", "rustscan_full_port", "rustscan_batch_size", "nmap_scan_aggressivity",
    "bruteforce_threads", "credential_reuse",
    "vuln_scan_sv", "vuln_scan_vulners", "vuln_offline_cve",
    "ble_scan_enabled", "ble_scan_interval",
    "wifi_scan_enabled", "wifi_scan_iface", "wifi_scan_band", "wifi_scan_channel",
    "wifi_scan_interval",
    "telegram_enabled", "telegram_bot_token", "telegram_include_creds",
    "smtp_enabled", "smtp_host", "smtp_password",
    "wpasec_api_key",
    "battery_monitor_enabled",
    "planner_max_host_actions", "planner_standalone_every",
]
for k in keys:
    if k in cfg:
        print(f"  {k:28} {show(k, cfg[k])}")
for k in ("portlist", "mac_scan_blacklist", "ip_scan_blacklist", "snmp_communities"):
    if k in cfg and isinstance(cfg[k], list):
        print(f"  {k:28} {len(cfg[k])} items")
missing = [k for k in ("adaptive_scan_interval", "planner_max_host_actions", "wifi_scan_band")
           if k not in cfg]
if missing:
    print(f"  {'(keys not in config)':28} {', '.join(missing)} - older config, will fill in on next save")
PY
else
    bad "config" "missing $CFG"
fi

# ===========================================================================
section "8. NetKB / live status / stats"
# ===========================================================================
if [ -f "$NETKB" ]; then
    ok "netkb_path" "$NETKB"
    ok "netkb_size" "$(wc -c < "$NETKB" 2>/dev/null) bytes"
    ok "netkb_mtime" "$(date -r "$NETKB" -Is 2>/dev/null || stat -c %y "$NETKB" 2>/dev/null || echo '?')"
    # summarize with python (csv)
    python3 - "$NETKB" <<'PY' 2>/dev/null || true
import csv, sys
from collections import Counter
path = sys.argv[1]
with open(path, newline="", errors="replace") as f:
    rows = list(csv.DictReader(f))
print(f"  rows:                      {len(rows)}")
alive = [r for r in rows if r.get("Alive") == "1"]
print(f"  alive:                     {len(alive)}")
standalone = [r for r in rows if r.get("MAC Address") == "STANDALONE"]
print(f"  standalone_row:            {len(standalone)}")
# action outcome counts
success = fail = 0
action_hits = Counter()
for r in rows:
    for k, v in r.items():
        if k in ("MAC Address", "IPs", "Hostnames", "Ports", "Alive"):
            continue
        vs = str(v or "")
        if "success" in vs:
            success += 1
            action_hits[k] += 1
        elif "failed" in vs:
            fail += 1
print(f"  cell_success_marks:        {success}")
print(f"  cell_failed_marks:         {fail}")
if action_hits:
    print("  top successful actions:")
    for name, n in action_hits.most_common(8):
        print(f"    - {name}: {n}")
# sample alive hosts
print("  alive hosts (up to 8):")
for r in alive[:8]:
    ports = (r.get("Ports") or "")[:40]
    print(f"    {r.get('IPs','?'):16} ports={ports}")
PY
else
    warn "netkb" "not found (no scan yet?) — $NETKB"
fi

echo
if [ -f "$LIVE" ]; then
    ok "livestatus" "$LIVE ($(wc -l < "$LIVE") lines, mtime $(date -r "$LIVE" '+%H:%M:%S' 2>/dev/null || echo '?'))"
    head -5 "$LIVE" 2>/dev/null | sed 's/^/  /'
else
    warn "livestatus" "missing"
fi

echo
if [ -f "$STATS" ]; then
    ok "stats.json" "present"
    python3 -c "import json;d=json.load(open('$STATS'));print('  coins:',d.get('coins'),' level:',d.get('level'),' hwm:',d.get('hwm'))" 2>/dev/null \
        || cat "$STATS" | head -c 400 | sed 's/^/  /'
else
    warn "stats.json" "missing (coins/level not persisted yet)"
fi

# Output dirs sizes
echo
echo "  Output tree sizes:"
for d in scan_results vulnerabilities crackedpwd data_stolen zombies run_reports; do
    p="$OUT/$d"
    if [ -d "$p" ]; then
        n="$(find "$p" -type f 2>/dev/null | wc -l)"
        sz="$(du -sh "$p" 2>/dev/null | awk '{print $1}')"
        ok "$d" "$n files, $sz"
    else
        warn "$d" "dir missing"
    fi
done

# ===========================================================================
section "9. Recent orchestrator / planner activity"
# ===========================================================================
orch_log="$LOGS/orchestrator.py.log"
if [ -f "$orch_log" ]; then
    ok "orch_log" "$orch_log ($(wc -l < "$orch_log") lines)"
    echo "  Last planner / action lines:"
    grep -E 'Planner chose|Executing action|Executing standalone|idling|NetworkScanner|No available|Starting Orchestrator|vulnerability' \
        "$orch_log" 2>/dev/null | tail -25 | sed 's/^/  /' || echo "  (no matching lines)"
else
    # any log mentioning orchestrator
    if [ -d "$LOGS" ]; then
        warn "orch_log" "orchestrator.py.log missing — scanning all logs"
        grep -h 'Planner chose\|Executing action' "$LOGS"/*.log 2>/dev/null | tail -15 | sed 's/^/  /' || echo "  (none)"
    fi
fi

# Latest run report
echo
latest_rr="$(ls -t "$OUT/run_reports"/*.json 2>/dev/null | head -1 || true)"
if [ -n "$latest_rr" ]; then
    ok "latest_run_report" "$latest_rr"
    python3 -c "
import json
d=json.load(open('$latest_rr'))
print('  run_id:', d.get('run_id'))
print('  written_at:', d.get('written_at'))
print('  version:', d.get('version'))
acts=d.get('actions') or {}
print('  actions tracked:', len(acts))
for k,v in list(acts.items())[:10]:
    print(f\"    {k}: success={v.get('success')} failed={v.get('failed')}\")
" 2>/dev/null || head -c 500 "$latest_rr" | sed 's/^/  /'
else
    warn "run_reports" "none yet"
fi

# ===========================================================================
section "10. Log errors (all locations)"
# ===========================================================================
echo "  App logs ($LOGS):"
if [ -d "$LOGS" ] && ls "$LOGS"/*.log >/dev/null 2>&1; then
    # counts per file
    echo "  Error/critical counts by file:"
    for f in "$LOGS"/*.log; do
        # grep -c prints 0 AND exits 1 on no match, so `|| echo 0` used to yield the two-line
        # string "0\n0" and every numeric test on it failed (silently, thanks to 2>/dev/null).
        n="$(grep -cEi 'error|critical|traceback|exception' "$f" 2>/dev/null)" || n=0
        bn="$(basename "$f")"
        if [ "${n:-0}" -gt 0 ] 2>/dev/null; then
            printf '    %-32s %s\n' "$bn" "$n"
        fi
    done
    if [ "$SHORT" -eq 0 ]; then
        echo
        echo "  Last matching lines (max 25):"
        grep -rEi 'error|critical|traceback|exception' "$LOGS"/*.log 2>/dev/null | tail -25 | sed 's/^/  /' \
            || echo "  (no errors logged)"
    fi
else
    echo "  no logs yet"
fi

echo
echo "  Systemd journal (err+):"
if have journalctl; then
    journalctl -u bjorn.service -p err -n 15 --no-pager 2>&1 | sed 's/^/  /' || true
else
    echo "  journalctl not available"
fi

echo
echo "  Install logs:"
latest_install="$(ls -t /var/log/bjorn_install/*.log 2>/dev/null | head -1 || true)"
if [ -n "$latest_install" ]; then
    ok "latest_install" "$latest_install"
    grep -Ei 'error|failed' "$latest_install" 2>/dev/null | tail -10 | sed 's/^/  /' || echo "  (no errors)"
else
    echo "  none under /var/log/bjorn_install/"
fi

# ===========================================================================
section "11. Python packages (key deps)"
# ===========================================================================
python3 - <<'PY' 2>/dev/null || warn "pip" "could not query packages"
import importlib
# Keyed on IMPORT name, not pip name — they differ often enough that guessing produces false
# alarms. This list previously tried `import pysmb` (it is `smb`) and reported a working install as
# NOT IMPORTABLE, which cost more time than the check saved. Same for Pillow -> PIL, get-mac ->
# getmac, python-nmap -> nmap.
DEPS = [("fastapi", "fastapi"), ("uvicorn", "uvicorn"), ("paramiko", "paramiko"),
        ("pysmb", "smb"), ("smbprotocol", "smbprotocol"), ("pymysql", "pymysql"),
        ("Pillow", "PIL"), ("numpy", "numpy"), ("pandas", "pandas"), ("rich", "rich"),
        ("netifaces", "netifaces"), ("get-mac", "getmac"), ("python-nmap", "nmap"),
        ("sqlalchemy", "sqlalchemy"), ("gpiozero", "gpiozero"), ("lgpio", "lgpio")]
for pip_name, import_name in DEPS:
    label = pip_name if pip_name == import_name else f"{pip_name} ({import_name})"
    try:
        mod = importlib.import_module(import_name)
        print(f"  {label:24} {getattr(mod, '__version__', getattr(mod, 'VERSION', 'ok'))}")
    except Exception as e:
        print(f"  {label:24} NOT IMPORTABLE ({type(e).__name__})")
PY

# ===========================================================================
section "12. File map (where things live)"
# ===========================================================================
cat <<MAP
  app logs (per module)       $LOGS/*.log
  web console buffer          $LOGS/temp_log.txt
  run reports (redacted)      $OUT/run_reports/*.json
  scan results                $OUT/scan_results/
  vulnerabilities             $OUT/vulnerabilities/
  cracked credentials         $OUT/crackedpwd/
  stolen data (loot)          $OUT/data_stolen/
  zombies                     $OUT/zombies/
  mock display                $OUT/mock_display.png
  net knowledge base          $NETKB
  live status                 $LIVE
  stats (coins/level)         $STATS
  config                      $CFG
  actions auto-gen            $REPO/config/actions.json
  heartbeat                   $HEARTBEAT
  install logs                /var/log/bjorn_install/*.log
  systemd journal             journalctl -u bjorn.service
  this diag (if --save)       $OUT/diag_*.txt
MAP

# ===========================================================================
section "13. Quick recommendations"
# ===========================================================================
# Heuristic hints based on what we saw
recs=0
if ! ls /dev/spidev* >/dev/null 2>&1; then
    echo "  • Enable SPI (blank e-Paper): sudo raspi-config nonint do_spi 0 && sudo reboot"
    recs=1
fi
if ! pgrep -f '[Bb]jorn\.py' >/dev/null 2>&1; then
    echo "  • Service not running: sudo systemctl start bjorn.service && sudo journalctl -u bjorn -f"
    recs=1
fi
if [ ! -f "$REPO/action_planner.py" ]; then
    echo "  • action_planner.py absent — this checkout predates scored work selection: git pull"
    recs=1
fi
if [ -n "${behind:-}" ] && [ "${behind:-0}" -gt 0 ] 2>/dev/null; then
    echo "  • $behind commit(s) behind upstream — pull before acting on anything above"
    recs=1
fi
if have timedatectl && [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" != "yes" ]; then
    echo "  • System clock not NTP-synced — netkb timestamps (retry windows) are unreliable"
    recs=1
fi
if [ -f "$CFG" ]; then
    if grep -q '"use_rustscan"[[:space:]]*:[[:space:]]*true' "$CFG" 2>/dev/null; then
        if ! command -v rustscan >/dev/null 2>&1 && ! ls /usr/local/bin/rustscan /home/*/.cargo/bin/rustscan 2>/dev/null | grep -q .; then
            echo "  • use_rustscan=true but rustscan binary missing — scans fall back to nmap"
            recs=1
        fi
    fi
    if grep -q '"debug_mode"[[:space:]]*:[[:space:]]*true' "$CFG" 2>/dev/null; then
        echo "  • debug_mode is true — more SD writes; set false on long-running field units"
        recs=1
    fi
fi
# disk space
avail_kb="$(df -Pk "$REPO" 2>/dev/null | awk 'NR==2{print $4}')"
if [ -n "${avail_kb:-}" ] && [ "$avail_kb" -lt 200000 ] 2>/dev/null; then
    echo "  • Low disk space on repo filesystem (<200MB) — clear loot/logs or expand SD"
    recs=1
fi
if [ "$recs" -eq 0 ]; then
    echo "  (no automatic red flags — review sections above for tuning ideas)"
fi

echo
echo "Done. Save this output when asking for help:"
echo "  sudo bash $SCRIPT_DIR/bjorn_diag.sh --save"
echo "  sudo bash $SCRIPT_DIR/bjorn_diag.sh | tee /tmp/bjorn_diag.txt"
if [ -n "$REPORT_FILE" ]; then
    echo
    echo "Report written to: $REPORT_FILE"
fi
echo
