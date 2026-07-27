#!/bin/bash
# bjorn_doctor.sh — one-shot health + log report for a Bjorn install.
#
# The single place to look after an install or when something misbehaves. Read-only: it
# gathers version, hardware/service status, and recent errors from EVERY log location, then
# prints a map of where each log/output file lives. Works even when Bjorn won't start —
# which is exactly when you need it.
#
#   sudo /home/bjorn/Bjorn/scripts/bjorn_doctor.sh            # print the report
#   sudo /home/bjorn/Bjorn/scripts/bjorn_doctor.sh > report.txt   # save it (e.g. to attach)
#
# Run with sudo so it can read the systemd journal and the install logs.

set -u  # (intentionally NOT set -e: grep returning "no match" must not abort the report)

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
REPO="$(dirname "$SCRIPT_DIR")"
DATA="$REPO/data"
LOGS="$DATA/logs"
OUT="$DATA/output"

section() { printf '\n=== %s ===\n' "$1"; }
have()    { command -v "$1" >/dev/null 2>&1; }

section "Bjorn version & environment"
echo "version:  $(cat "$REPO/version.txt" 2>/dev/null || echo '?')"
echo "repo:     $REPO"
echo "python:   $(python3 --version 2>&1)"
if [ -f /etc/os-release ]; then . /etc/os-release; echo "os:       ${PRETTY_NAME:-?}"; fi
echo "arch:     $(uname -m)"

section "Hardware"
if ls /dev/spidev* >/dev/null 2>&1; then
    echo "SPI:      OK ($(ls /dev/spidev* | tr '\n' ' '))"
else
    echo "SPI:      NOT ENABLED  <-- common cause of a blank e-Paper."
    echo "                       enable: sudo raspi-config nonint do_spi 0 && sudo reboot"
fi
echo "epd_type: $(grep -o '"epd_type"[^,]*' "$REPO/config/shared_config.json" 2>/dev/null || echo '?')"

section "Service (bjorn.service)"
if have systemctl; then
    echo "enabled:  $(systemctl is-enabled bjorn.service 2>&1)"
    echo "active:   $(systemctl is-active  bjorn.service 2>&1)"
    systemctl status bjorn.service --no-pager -n 3 2>&1 | sed 's/^/  /' | head -8
else
    echo "systemctl not available (not on the Pi?)"
fi

section "Recent errors in app logs ($LOGS)"
if [ -d "$LOGS" ] && ls "$LOGS"/*.log >/dev/null 2>&1; then
    matches="$(grep -rEi 'error|critical|traceback|exception' "$LOGS"/*.log 2>/dev/null | tail -30)"
    [ -n "$matches" ] && echo "$matches" || echo "  (no errors logged)"
else
    echo "  no logs yet at $LOGS"
fi

section "Recent errors in systemd journal"
if have journalctl; then
    journalctl -u bjorn.service -p err -n 20 --no-pager 2>&1 | sed 's/^/  /' || echo "  (journal unavailable)"
else
    echo "  journalctl not available"
fi

section "Install logs (/var/log/bjorn_install)"
latest_install_log="$(ls -t /var/log/bjorn_install/*.log 2>/dev/null | head -1)"
if [ -n "${latest_install_log:-}" ]; then
    echo "latest: $latest_install_log"
    errs="$(grep -Ei 'error|failed' "$latest_install_log" 2>/dev/null | tail -15)"
    [ -n "$errs" ] && echo "$errs" || echo "  (no errors logged)"
else
    echo "  none found"
fi

section "Where Bjorn leaves files"
cat <<MAP
app logs (per module)     $LOGS/*.log
web console log           $LOGS/temp_log.txt
run reports (redacted)    $OUT/run_reports/*.json
scan results              $OUT/scan_results/
vulnerabilities           $OUT/vulnerabilities/
cracked credentials       $OUT/crackedpwd/
stolen data (loot)        $OUT/data_stolen/
zombies                   $OUT/zombies/
mock display snapshot     $OUT/mock_display.png   (only when epd_type=mock)
net knowledge base        $DATA/netkb.csv
live status               $DATA/livestatus.csv
config                    $REPO/config/shared_config.json
install logs              /var/log/bjorn_install/*.log
systemd journal           journalctl -u bjorn.service
MAP

echo
echo "e-Paper still blank? Probe each driver visually:  sudo python3 $SCRIPT_DIR/epd_test.py --all"
