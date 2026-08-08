#!/bin/bash
# bjorn_verify.sh — on-device verification of the things only hardware can confirm.
#
# Started as a one-shot for the Tier-0 backlog items (docs/BACKLOG.md); it is now the standing
# "did the last batch of changes actually work on the Pi" script, and is tracked in the repo so it
# stops drifting from the code it inspects. Section 8 covers everything since the 2026-08-07 sweep.
#
# NOT read-only, unlike bjorn_diag.sh. This one *acts*: it starts a real airodump capture on the
# monitor radio, runs the nmap-vs-rustscan benchmark, and sends a Telegram/SMTP test message. That
# is the point — every Tier-0 item is "needs the Pi to actually do the thing", not "needs another
# look at the config". Run bjorn_diag.sh first if something is broken; run this to close backlog
# items. Nothing is committed, nothing is reconfigured: the only writes are the ones Bjorn itself
# makes (capture CSVs, benchmark CSV) plus this report.
#
# Requires the bjorn service to be UP — most checks go through the web API on :8000.
#
# Usage:
#   sudo /home/bjorn/Bjorn/scripts/bjorn_verify.sh --save
#   sudo /home/bjorn/Bjorn/scripts/bjorn_verify.sh --quick --no-send   # no capture/benchmark/message
#
# Flags:
#   --quick        skip the slow active checks (Wi-Fi capture ~1min, benchmark up to ~10min)
#   --no-send      skip the Telegram/SMTP test message (it really sends)
#   --save         write the report to data/output/verify_YYYYMMDD_HHMMSS.txt
#   --repo PATH    override the install path
#   --url HOST:PORT  web API address (default 127.0.0.1:8000)
#
# Output is a PASS/FAIL/SKIP list per item, safe to paste back: no config values are printed except
# booleans and interface names, and no credentials or loot are read.

set -u
# intentionally NOT set -e — a failing check is a result, not a reason to abort the run

QUICK=0
NO_SEND=0
DO_SAVE=0
REPO_OVERRIDE=""
HOSTPORT="127.0.0.1:8000"

while [ $# -gt 0 ]; do
    case "$1" in
        --quick)   QUICK=1; shift ;;
        --no-send) NO_SEND=1; shift ;;
        --save)    DO_SAVE=1; shift ;;
        --repo)    REPO_OVERRIDE="${2:-}"; shift 2 ;;
        --url)     HOSTPORT="${2:-}"; shift 2 ;;
        -h|--help) sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown flag: $1 (try --help)"; exit 1 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")")" && pwd)"

# Where the install lives. Deliberately NOT "the directory above this script": this file gets
# scp'd around and run from ~, and a wrong REPO makes every CSV and config read a path that does
# not exist — which reads as "the feature is broken" rather than "you ran it from the wrong
# place". systemd already knows the answer, so ask it first and verify the guess before using it.
resolve_repo() {
    local d
    if [ -n "$REPO_OVERRIDE" ]; then echo "$REPO_OVERRIDE"; return; fi
    for d in "$(systemctl show -p WorkingDirectory --value bjorn.service 2>/dev/null)" \
             "$(dirname "$SCRIPT_DIR")" /home/*/Bjorn /opt/Bjorn "${HOME:-/root}/Bjorn"; do
        [ -n "$d" ] && [ -f "$d/config/shared_config.json" ] && { echo "$d"; return; }
    done
    echo ""
}
REPO="$(resolve_repo)"
if [ -z "$REPO" ]; then
    echo "Could not locate the Bjorn install (looked for config/shared_config.json via the systemd"
    echo "unit, this script's parent dir, /home/*/Bjorn and /opt/Bjorn)."
    echo "Pass it explicitly:  $0 --repo /home/bjorn/Bjorn"
    exit 1
fi
DATA="$REPO/data"
OUT="$DATA/output"
SCAN="$OUT/scan_results"
CRACKED="$OUT/crackedpwd"
VULN="$OUT/vulnerabilities"
CFG="$REPO/config/shared_config.json"

if [ "$DO_SAVE" -eq 1 ]; then
    mkdir -p "$OUT" 2>/dev/null || true
    REPORT_FILE="$OUT/verify_$(date +%Y%m%d_%H%M%S).txt"
    exec > >(tee "$REPORT_FILE") 2>&1
    TEE_PID=$!
    trap 'exec 1>&-; [ -n "${TEE_PID:-}" ] && wait "$TEE_PID" 2>/dev/null' EXIT
fi

if [ -t 1 ]; then
    C_BOLD=$'\033[1m'; C_GOOD=$'\033[32m'; C_WARN=$'\033[33m'; C_BAD=$'\033[31m'; C_OFF=$'\033[0m'
else
    C_BOLD=""; C_GOOD=""; C_WARN=""; C_BAD=""; C_OFF=""
fi

section() { printf '\n%s=== %s ===%s\n' "$C_BOLD" "$1" "$C_OFF"; }
info()    { printf '  %-26s %s\n' "$1" "$2"; }

RESULTS=""
verdict() {  # verdict PASS|FAIL|SKIP|WARN "<id> label" "detail"
    local v="$1" label="$2" detail="${3:-}" c=""
    case "$v" in
        PASS) c="$C_GOOD" ;; FAIL) c="$C_BAD" ;; WARN) c="$C_WARN" ;; *) c="" ;;
    esac
    printf '  %s[%s]%s %s%s\n' "$c" "$v" "$C_OFF" "$label" "${detail:+ — $detail}"
    RESULTS="$RESULTS
$v|$label|$detail"
}

have() { command -v "$1" >/dev/null 2>&1; }

api_get()  { curl -s --max-time 30 "http://$HOSTPORT$1" 2>/dev/null; }
api_post() {
    if [ -n "${2:-}" ]; then
        curl -s --max-time 60 -X POST -H 'Content-Type: application/json' -d "$2" "http://$HOSTPORT$1" 2>/dev/null
    else
        curl -s --max-time 60 -X POST "http://$HOSTPORT$1" 2>/dev/null
    fi
}

# One JSON reader for everything: reads a doc on stdin, prints one top-level key.
jkey() {
    python3 -c 'import sys,json
try: d=json.load(sys.stdin)
except Exception: d={}
v=d.get(sys.argv[1]) if isinstance(d,dict) else None
print("" if v is None else (json.dumps(v) if isinstance(v,(dict,list)) else v))' "$1" 2>/dev/null
}
cfg()  { jkey "$1" < "$CFG"; }
rows() { if [ -f "$1" ]; then awk 'END{print (NR>0)?NR-1:0}' "$1"; else echo 0; fi; }
age()  { if [ -f "$1" ]; then echo $(( $(date +%s) - $(stat -c %Y "$1" 2>/dev/null || echo 0) )); else echo -1; fi; }
agestr() { local a; a="$(age "$1")"; if [ "$a" -lt 0 ]; then echo "missing"; else echo "$((a/60))m ago"; fi; }

echo "Bjorn Tier-0 verification — $(date -Is 2>/dev/null || date)"
echo "Host: $(hostname 2>/dev/null || echo '?')  |  Sudo: $([ "$(id -u)" -eq 0 ] && echo yes || echo no)  |  Repo: $REPO"
echo "Mode: $([ "$QUICK" -eq 1 ] && echo 'quick (no capture/benchmark)' || echo 'full')$([ "$NO_SEND" -eq 1 ] && echo ', no-send' || echo '')"

# ===========================================================================
section "0. Preflight"
# ===========================================================================
info "version.txt" "$(cat "$REPO/version.txt" 2>/dev/null || echo '?')"
# build_info, NOT `git -C "$REPO"`. Two reasons, and the second is why the git call was removed
# rather than guarded: (1) BACKLOG.md records that the deployed tree is not a checkout — the
# installer copies files — so build_info is the only commit stamp that exists on a real device;
# (2) this script is documented to run under sudo, and $REPO is owned by the bjorn user (or, via
# the /home/*/Bjorn glob in resolve_repo, by any local user), so running git there as root reads
# an attacker-controllable .git/config. Modern git refuses that with "dubious ownership", but
# depending on another tool's safety check for our own privilege boundary is not a design.
COMMIT="$(sed -n 's/^source_commit=//p' "$REPO/build_info" 2>/dev/null | cut -c1-60)"
info "commit" "${COMMIT:-? (no .git and no build_info — reinstall to stamp the build)}"
info "service" "$(systemctl is-active bjorn.service 2>/dev/null || echo '?')"

WEB_CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://$HOSTPORT/" 2>/dev/null)"
if [ "$WEB_CODE" = "200" ]; then
    verdict PASS "#155 web server reachable" "GET / → 200 on $HOSTPORT"
else
    verdict FAIL "#155 web server reachable" "GET / → ${WEB_CODE:-no response}; every API check below will fail"
fi
have python3 || { echo "python3 missing — cannot parse API responses"; exit 1; }
have curl    || { echo "curl missing — install curl"; exit 1; }

# ===========================================================================
section "1. Wi-Fi recon end-to-end (Wave 4 — the big one)"
# ===========================================================================
UPLINK_BEFORE="$(ip route show default 2>/dev/null | awk '/^default/{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
IF_JSON="$(api_get /wifi_ifaces)"
MON_IFACE="$(printf '%s' "$IF_JSON" | jkey configured)"
MISSING="$(printf '%s' "$IF_JSON" | jkey configured_missing)"
info "uplink (default route)" "${UPLINK_BEFORE:-none}"
info "wireless interfaces" "$(printf '%s' "$IF_JSON" | jkey interfaces)"
info "configured monitor iface" "${MON_IFACE:-<unset>}"

if [ -z "$MON_IFACE" ]; then
    verdict SKIP "Wi-Fi capture" "wifi_scan_iface is unset — set it on /wifi first"
elif [ "$MISSING" = "true" ] || [ "$MISSING" = "True" ]; then
    verdict FAIL "Wi-Fi radio present" "$MON_IFACE is configured but not present (dongle moved USB port? inner micro-USB is the data one)"
else
    verdict PASS "Wi-Fi radio present" "$MON_IFACE enumerated"

    # Guard regression — must REFUSE the uplink. Read-only (ip route + iw dev), costs nothing.
    if [ -n "$UPLINK_BEFORE" ]; then
        G="$(api_post /wifi_monitor_test "{\"iface\":\"$UPLINK_BEFORE\"}")"
        if [ "$(printf '%s' "$G" | jkey status)" = "error" ]; then
            verdict PASS "guard refuses the uplink" "$UPLINK_BEFORE: $(printf '%s' "$G" | jkey message | cut -c1-60)…"
        else
            verdict FAIL "guard refuses the uplink" "ACCEPTED $UPLINK_BEFORE — do not run a capture, monitor_mode.check_usable is broken"
        fi
    fi

    T="$(api_post /wifi_monitor_test "{\"iface\":\"$MON_IFACE\"}")"
    if [ "$(printf '%s' "$T" | jkey status)" = "success" ]; then
        verdict PASS "monitor mode supported" "$MON_IFACE ($(printf '%s' "$T" | jkey message))"
    else
        verdict FAIL "monitor mode supported" "$(printf '%s' "$T" | jkey message)"
    fi

    if ! have airodump-ng; then
        verdict FAIL "airodump-ng installed" "not on PATH — install aircrack-ng; the action skips silently without it"
    fi

    if [ "$QUICK" -eq 1 ]; then
        verdict SKIP "airodump capture" "--quick"
    elif ! have airodump-ng; then
        verdict SKIP "airodump capture" "no airodump-ng"
    else
        AP_BEFORE="$(rows "$SCAN/wifi_aps.csv")"; CL_BEFORE="$(rows "$SCAN/wifi_clients.csv")"
        S="$(api_post /wifi_scan_now)"
        if [ "$(printf '%s' "$S" | jkey status)" != "success" ]; then
            verdict FAIL "airodump capture" "$(printf '%s' "$S" | jkey message)"
        else
            DUR="$(printf '%s' "$S" | jkey duration)"; DUR="${DUR:-30}"
            echo "  … capturing for ${DUR}s on $MON_IFACE"
            sleep "$((DUR + 10))"
            # The capture is over when airodump is gone, not when the clock says so. Waiting on the
            # process instead of a fixed sleep is what separates "still flushing" from "stranded" —
            # the two produce identical output at a fixed deadline.
            for _ in $(seq 1 18); do
                pgrep -x airodump-ng >/dev/null 2>&1 || break
                sleep 5
            done
            if pgrep -x airodump-ng >/dev/null 2>&1; then
                verdict FAIL "airodump exits on its timeout" "still running $((DUR + 100))s in — subprocess timeout is not stopping it"
                info "airodump procs" "$(pgrep -a airodump-ng | head -3)"
            fi

            AP_AFTER="$(rows "$SCAN/wifi_aps.csv")"; CL_AFTER="$(rows "$SCAN/wifi_clients.csv")"
            info "wifi_aps.csv" "$AP_BEFORE → $AP_AFTER rows ($(agestr "$SCAN/wifi_aps.csv"))"
            info "wifi_clients.csv" "$CL_BEFORE → $CL_AFTER rows ($(agestr "$SCAN/wifi_clients.csv"))"
            if [ "$AP_AFTER" -gt 0 ] && [ "$(age "$SCAN/wifi_aps.csv")" -lt "$((DUR + 200))" ]; then
                verdict PASS "airodump capture" "$AP_AFTER APs / $CL_AFTER clients, file just written"
            else
                verdict FAIL "airodump capture" "no fresh AP rows"
                echo "  --- tail of wifi_scan.py.log ---"
                tail -8 "$DATA/logs/wifi_scan.py.log" 2>/dev/null | sed 's/^/  /' || echo "  (no log)"
            fi

            # release() — the radio must be back in managed mode and back under NetworkManager.
            MODE="$(iw dev "$MON_IFACE" info 2>/dev/null | awk '/type/{print $2; exit}')"
            NMSTATE="$(nmcli -t -f DEVICE,STATE device 2>/dev/null | awk -F: -v i="$MON_IFACE" '$1==i{print $2}')"
            if [ "$MODE" = "managed" ]; then
                verdict PASS "release() restored $MON_IFACE" "type=managed, nmcli state=${NMSTATE:-?}"
            else
                verdict FAIL "release() restored $MON_IFACE" "type=${MODE:-unknown}, nmcli state=${NMSTATE:-?} — radio left stranded"
                echo "  recover with: sudo iw dev $MON_IFACE set type managed && sudo nmcli device set $MON_IFACE managed yes"
            fi
        fi

        # The whole reason the guard exists: the uplink must be untouched afterwards.
        UPLINK_AFTER="$(ip route show default 2>/dev/null | awk '/^default/{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
        WEB_AFTER="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://$HOSTPORT/" 2>/dev/null)"
        if [ "$UPLINK_AFTER" = "$UPLINK_BEFORE" ] && [ "$WEB_AFTER" = "200" ]; then
            verdict PASS "uplink undisturbed" "default route still ${UPLINK_AFTER:-none}, web still 200"
        else
            verdict FAIL "uplink undisturbed" "route ${UPLINK_BEFORE:-none} → ${UPLINK_AFTER:-none}, web $WEB_AFTER"
        fi
    fi
fi

# ===========================================================================
section "2. Scan engine — rustscan batch tuning"
# ===========================================================================
info "use_rustscan" "$(cfg use_rustscan)"
info "rustscan_batch_size" "$(cfg rustscan_batch_size) (0 = auto, 1500 on a Pi Zero)"
info "rustscan binary" "$(command -v rustscan 2>/dev/null || ls /home/*/.cargo/bin/rustscan /root/.cargo/bin/rustscan 2>/dev/null | head -1 || echo 'not on PATH')"

if [ "$QUICK" -eq 1 ]; then
    verdict SKIP "benchmark nmap vs rustscan" "--quick"
else
    B="$(api_post /run_benchmark)"
    if [ "$(printf '%s' "$B" | jkey status)" != "success" ]; then
        verdict FAIL "benchmark nmap vs rustscan" "$(printf '%s' "$B" | jkey message)"
    else
        echo "  … benchmark running (two full discovery passes; polling up to 12min)"
        for _ in $(seq 1 72); do
            sleep 10
            [ "$(api_get /benchmark_results | jkey running)" = "false" ] && break
        done
        # Python's csv.writer terminates rows with \r\n, so every last field carries a CR that
        # bash's -eq chokes on — a real comparison silently became "no comparable row".
        LAST="$(tail -1 "$DATA/scan_engine_benchmark.csv" 2>/dev/null | tr -d '\r')"
        echo "  header: Timestamp,Hosts,Ports,nmap s,rustscan s,speedup,nmap ports,rustscan ports"
        echo "  last:   $LAST"
        NP="$(printf '%s' "$LAST" | awk -F, '{print $7}')"
        RP="$(printf '%s' "$LAST" | awk -F, '{print $8}')"
        if ! [ "${NP:-x}" -eq "${NP:-x}" ] 2>/dev/null || ! [ "${RP:-x}" -eq "${RP:-x}" ] 2>/dev/null; then
            verdict WARN "benchmark nmap vs rustscan" "no comparable row (rustscan skipped? see the CSV)"
        elif [ "$RP" -ge "$NP" ]; then
            verdict PASS "rustscan finds every port nmap does" "nmap=$NP rustscan=$RP at batch $(cfg rustscan_batch_size) — this batch is safe"
        else
            verdict FAIL "rustscan finds every port nmap does" "nmap=$NP rustscan=$RP — DROPPED PORTS: lower rustscan_batch_size on /config and re-run"
        fi
    fi
fi

# ===========================================================================
section "3. usb0 gadget (#68 — plugged-host lease)"
# ===========================================================================
USB_IP="$(ip -4 addr show usb0 2>/dev/null | awk '/inet /{print $2; exit}')"
USB_FLAGS="$(ip link show usb0 2>/dev/null | head -1 | sed 's/.*<\([^>]*\)>.*/\1/')"
info "usb0 address" "${USB_IP:-none}"
info "usb0 flags" "${USB_FLAGS:-interface absent}"
if [ "${USB_IP%%/*}" = "172.20.2.1" ]; then
    verdict PASS "usb0 addressed without carrier" "$USB_IP"
else
    verdict FAIL "usb0 addressed without carrier" "expected 172.20.2.1/24, got ${USB_IP:-nothing}"
fi
LEASES="$(networkctl status usb0 2>/dev/null | grep -iA3 'Offered DHCP leases' | tail -n +2 | tr -s ' ')"
if [ -z "$USB_FLAGS" ]; then
    verdict SKIP "DHCP lease handed to a host" "usb0 does not exist — the gadget never came up (see bjorn_diag.sh section 4)"
elif [ -n "$LEASES" ]; then
    verdict PASS "DHCP lease handed to a host" "$(printf '%s' "$LEASES" | head -2 | tr '\n' ' ')"
elif printf '%s' "$USB_FLAGS" | grep -q NO-CARRIER; then
    verdict SKIP "DHCP lease handed to a host" "nothing plugged in (NO-CARRIER) — plug a laptop in and re-run, then open http://172.20.2.1:8000/"
else
    verdict WARN "DHCP lease handed to a host" "carrier up but no lease offered — check systemd-networkd"
fi

# ===========================================================================
section "4. Display + web UI (#122, #113, #176)"
# ===========================================================================
info "epd_type" "$(cfg epd_type)"
# mktemp, not a fixed /tmp name: root writing to a predictable path in a world-writable directory
# is the classic symlink overwrite — any local user pre-creates /tmp/bjorn_screen.png pointing at
# a file they could not otherwise touch, and this curl clobbers it as root.
SHOT="$(mktemp -t bjorn_screen.XXXXXX 2>/dev/null || echo "")"
if [ -z "$SHOT" ]; then
    PNG="mktemp failed"
else
    PNG="$(curl -s -o "$SHOT" -w '%{http_code}:%{size_download}' --max-time 15 "http://$HOSTPORT/screen.png" 2>/dev/null)"
    rm -f "$SHOT"
fi
info "GET /screen.png" "$PNG"
if [ "${PNG%%:*}" = "200" ] && [ "${PNG##*:}" -gt 1000 ]; then
    verdict PASS "#122 framebuffer renders" "screen.png ${PNG##*:} bytes — compare it against the physical panel for #113"
else
    verdict FAIL "#122 framebuffer renders" "screen.png $PNG"
fi
PORTLIST="$(api_get /load_config | jkey portlist)"
info "portlist (from API)" "$PORTLIST"
case "$PORTLIST" in
    \[*\]) verdict PASS "#176 portlist round-trips as a list" "$PORTLIST — now edit it in the GUI with commas and re-run to confirm the save path" ;;
    "")    verdict WARN "#176 portlist round-trips as a list" "empty or unreadable" ;;
    *)     verdict FAIL "#176 portlist round-trips as a list" "not a JSON array: $PORTLIST" ;;
esac

# ===========================================================================
section "5. Action evidence (needs a real target — passive read of what ran)"
# ===========================================================================
# These items are "confirm it works against a live target". The evidence is the output file:
# enabled + fresh + non-empty means it ran; enabled + stale means it never found anything.
evidence() {  # evidence "<label>" <file> <enabled-yes|no> "<what-it-needs>"
    local label="$1" file="$2" enabled="$3" needs="$4" n age_s
    n="$(rows "$file")"; age_s="$(agestr "$file")"
    info "$(basename "$file")" "$n rows, $age_s"
    if [ "$enabled" = "no" ]; then
        verdict SKIP "$label" "disabled (or key absent from the saved config → default off)"
    elif [ "$n" -gt 0 ]; then
        verdict PASS "$label" "$n rows ($age_s)"
    else
        verdict WARN "$label" "no rows yet — $needs"
    fi
}

BLE_EN="$([ "$(cfg ble_scan_enabled)" = "True" ] || [ "$(cfg ble_scan_enabled)" = "true" ] && echo yes || echo no)"
evidence "BLE recon"          "$SCAN/ble_devices.csv"           "$BLE_EN" "needs a BLE device in range"
evidence "HTTP fingerprint"   "$SCAN/http_fingerprints.csv"     yes       "needs a host with an open web port"
evidence "Web templates"      "$SCAN/web_template_findings.csv" yes       "hits only; empty is a valid result"
evidence "SNMP enumeration"   "$SCAN/snmp_enum.csv"             yes       "needs a host answering UDP/161"
evidence "Credential reuse"   "$CRACKED/known_creds.csv"        yes       "needs a crackable host (weak SSH/FTP/SMB password)"
WPA_EN="$([ -n "$(cfg wpasec_api_key)" ] && echo yes || echo no)"
evidence "wpa-sec import"     "$CRACKED/wifi_wpasec.csv"        "$WPA_EN" "needs wpasec_api_key + internet"

VULN_N="$(ls -1 "$VULN" 2>/dev/null | wc -l | tr -d ' ')"
info "vulnerabilities/" "$VULN_N files"
if [ "$VULN_N" -gt 0 ]; then
    verdict PASS "CVE enrichment" "$VULN_N vuln files — grep one for a CVE line to confirm the signature match"
else
    verdict WARN "CVE enrichment" "no vuln scans yet — needs a host running a known-vulnerable service version"
fi

# ===========================================================================
section "6. Report delivery (Telegram / SMTP)"
# ===========================================================================
TG="$(cfg telegram_enabled)"; SM="$(cfg smtp_enabled)"
info "telegram_enabled" "$TG"
info "smtp_enabled" "$SM"
if [ "$NO_SEND" -eq 1 ]; then
    verdict SKIP "delivery test" "--no-send"
elif [ "$TG" != "True" ] && [ "$TG" != "true" ] && [ "$SM" != "True" ] && [ "$SM" != "true" ]; then
    verdict SKIP "delivery test" "neither channel enabled"
else
    D="$(api_post /telegram_test)"
    if [ "$(printf '%s' "$D" | jkey status)" = "success" ]; then
        verdict PASS "delivery test" "$(printf '%s' "$D" | jkey message) — confirm it arrived in the chat/mailbox"
    else
        verdict FAIL "delivery test" "$(printf '%s' "$D" | jkey message)"
    fi
fi

# ===========================================================================
section "7. Dependency set (P1-2 — the pin refresh is a copy-paste from here)"
# ===========================================================================
# Always the system python3, never a pip found inside $REPO.
#
# This used to prefer "$REPO/venv/bin/pip" and execute it. That is a root shell for anyone who can
# write to the install tree: the script is documented to run under sudo, the tree is chown'd to
# the bjorn user, and resolve_repo's /home/*/Bjorn glob widens that to any local user who creates
# ~/Bjorn/config/shared_config.json. Nothing in a directory this script merely *located* should
# ever be executed by it — reading attacker-controlled files is fine, running them is not.
#
# Cost of the fix: a venv install reports the system package set instead. The comment that used to
# live here already said no-venv is the normal case (the unit runs the system python3), so this
# trades a speculative branch for the removal of a privilege boundary — and if a venv ever does
# appear on the ExecStart line, the "service interpreter" line below is what would reveal it.
info "python3" "$(python3 -V 2>&1)"
info "service interpreter" "$(systemctl show -p ExecStart --value bjorn.service 2>/dev/null | grep -o '/[^ ]*python[0-9.]*' | head -1)"
info "pip source" "system python3 -m pip"
FREEZE="$OUT/pip_freeze_$(date +%Y%m%d).txt"
python3 -m pip freeze > "$FREEZE" 2>/dev/null
NPKG="$(wc -l < "$FREEZE" 2>/dev/null | tr -d ' ')"
if [ "${NPKG:-0}" -gt 0 ]; then
    verdict PASS "pip freeze captured" "$FREEZE ($NPKG packages) — the P1-2 lockfile candidate"
else
    verdict WARN "pip freeze captured" "pip freeze produced nothing (is pip installed for this interpreter?)"
fi

# ===========================================================================
section "8a. Defaults flipped to collect-by-default (c5b2b44)"
# ===========================================================================
# Bjorn is carried in a pocket, so the recon that needs no network is on by default now. A default
# that didn't survive the upgrade is invisible: everything keeps working, it just collects nothing.
truthy() { [ "$1" = "True" ] || [ "$1" = "true" ]; }

for pair in "ble_scan_enabled:BLE recon on by default" \
            "wifi_scan_enabled:Wi-Fi survey on by default" \
            "use_rustscan:RustScan is the default engine"; do
    key="${pair%%:*}"; label="${pair#*:}"
    val="$(cfg "$key")"
    if truthy "$val"; then
        verdict PASS "$label" "$key=$val"
    else
        verdict FAIL "$label" "$key=${val:-<absent>} — a saved config from before the upgrade wins over the new default; fix it on /config"
    fi
done

OFFKEY="$(cfg ble_scan_interval_offline)"
if [ -n "$OFFKEY" ]; then
    verdict PASS "BLE hunts faster offline" "ble_scan_interval_offline=${OFFKEY}s (vs $(cfg ble_scan_interval)s online)"
else
    verdict WARN "BLE hunts faster offline" "key absent from the saved config — the default (60s) still applies in memory"
fi

# The engine actually selected, not the toggle. rustscan resolves off-PATH cargo installs, so the
# toggle being on is not proof it was found.
ENGINE_LINE="$(grep -h 'Port discovery engine' "$DATA/logs/scanning.py.log" 2>/dev/null | tail -1)"
info "engine log line" "${ENGINE_LINE:-<none yet — no scan has run since boot>}"
case "$ENGINE_LINE" in
    *rustscan*) verdict PASS "rustscan is the engine in use" "$(printf '%s' "$ENGINE_LINE" | sed 's/.*Port discovery/Port discovery/')" ;;
    *nmap*)     verdict FAIL "rustscan is the engine in use" "fell back to nmap — the binary was not found; see 'rustscan not installed' in the log" ;;
    *)          verdict WARN "rustscan is the engine in use" "no engine line logged yet; run a scan and re-check" ;;
esac

# ===========================================================================
section "8b. Radio ownership — a busy radio must SKIP, not FAIL (Stage A, e04580a)"
# ===========================================================================
# The regression this guards: with wifi_scan_enabled on by default, a long-lived radio holder (the
# Bettercap hunter, later) made every scheduled scan log an ERROR and take a 10-minute retry
# backoff. Two overlapping captures reproduce the same contention cheaply.
if [ "$QUICK" -eq 1 ]; then
    verdict SKIP "busy radio is a clean skip" "--quick"
elif [ -z "${MON_IFACE:-}" ] || ! have airodump-ng; then
    verdict SKIP "busy radio is a clean skip" "needs a monitor radio + airodump-ng"
else
    WLOG="$DATA/logs/wifi_scan.py.log"
    # grep -c prints 0 AND exits 1 on no-match, so a `|| echo 0` here would append a second
    # line and every numeric test below would silently fail (bjorn_diag.sh had this exact bug).
    ERR_BEFORE="$(grep -c 'ERROR' "$WLOG" 2>/dev/null)"; ERR_BEFORE="${ERR_BEFORE:-0}"
    api_post /wifi_scan_now >/dev/null    # takes the radio
    sleep 5
    api_post /wifi_scan_now >/dev/null    # must be turned away politely
    sleep 5
    ERR_AFTER="$(grep -c 'ERROR' "$WLOG" 2>/dev/null)"; ERR_AFTER="${ERR_AFTER:-0}"
    BUSY_LINE="$(grep -h 'radio is in use' "$WLOG" 2>/dev/null | tail -1)"
    info "wifi_scan errors" "$ERR_BEFORE → $ERR_AFTER"
    if [ -n "$BUSY_LINE" ] && [ "$ERR_AFTER" -eq "$ERR_BEFORE" ]; then
        verdict PASS "busy radio is a clean skip" "second capture declined, no new ERROR"
    elif [ "$ERR_AFTER" -gt "$ERR_BEFORE" ]; then
        verdict FAIL "busy radio is a clean skip" "a contended radio logged an ERROR — Stage A regressed"
        tail -4 "$WLOG" 2>/dev/null | sed 's/^/  /'
    else
        verdict WARN "busy radio is a clean skip" "no contention observed (first capture may have finished first) — re-run without --quick"
    fi
    # Do not leave a capture running into the next section.
    for _ in $(seq 1 18); do pgrep -x airodump-ng >/dev/null 2>&1 || break; sleep 5; done
fi

# ===========================================================================
section "8c. Bettercap plumbing (Stage B — installed, configured, NOT enabled)"
# ===========================================================================
info "bettercap binary" "$(command -v bettercap 2>/dev/null || echo 'not installed (optional)')"
info "bettercap_enabled" "$(cfg bettercap_enabled)"
info "bettercap_api_url" "$(cfg bettercap_api_url)"

BC_PAGE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://$HOSTPORT/bettercap.html" 2>/dev/null)"
BC_STAT="$(api_get /bettercap_status)"
if [ "$BC_PAGE" = "200" ] && [ -n "$BC_STAT" ]; then
    verdict PASS "Bettercap panel reachable" "page 200, status: $(printf '%s' "$BC_STAT" | jkey message)"
else
    verdict FAIL "Bettercap panel reachable" "page $BC_PAGE, status endpoint $([ -n "$BC_STAT" ] && echo answered || echo silent)"
fi

BC_UNIT=/etc/systemd/system/bettercap.service
if [ ! -f "$BC_UNIT" ]; then
    verdict SKIP "bettercap.service provisioned" "no unit — the optional installer step did not run"
else
    BC_ENABLED="$(systemctl is-enabled bettercap.service 2>/dev/null || echo disabled)"
    if [ "$BC_ENABLED" = "enabled" ] && ! truthy "$(cfg bettercap_enabled)"; then
        verdict FAIL "bettercap stays off until asked" "unit is enabled but bettercap_enabled is false — it will start at boot with nothing reading it"
    else
        verdict PASS "bettercap stays off until asked" "unit present, is-enabled=$BC_ENABLED"
    fi

    # The credential check is the point of the installer block. Root-only: the unit is chmod 600.
    if [ "$(id -u)" -ne 0 ]; then
        verdict SKIP "bettercap password is generated + in sync" "needs sudo to read $BC_UNIT"
    else
        UNIT_PW="$(sed -n 's/.*api\.rest\.password \([^;"]*\).*/\1/p' "$BC_UNIT" | head -1 | tr -d ' ')"
        CFG_PW="$(cfg bettercap_password)"
        if [ -z "$UNIT_PW" ]; then
            verdict WARN "bettercap password is generated + in sync" "could not read the password out of the unit"
        elif [ "$UNIT_PW" = "pass" ] || [ "$UNIT_PW" = "bjorn" ]; then
            verdict FAIL "bettercap password is generated + in sync" "unit still carries a guessable password — regenerate it"
        elif [ "$UNIT_PW" != "$CFG_PW" ]; then
            verdict FAIL "bettercap password is generated + in sync" "unit and shared_config.json disagree — the panel will report 'unauthorized'"
        else
            verdict PASS "bettercap password is generated + in sync" "generated (${#UNIT_PW} chars), matches the config"
        fi
    fi
fi

# ===========================================================================
section "8d. The Unreleased wave — offline mode, planner, per-page dumps"
# ===========================================================================
# None of this has ever run on hardware. Each check looks for the *evidence in the logs* that the
# feature ran, not merely that its code is on disk.
PLANNER_LINE="$(grep -h 'Planner chose' "$DATA/logs/orchestrator.py.log" 2>/dev/null | tail -1)"
if [ -n "$PLANNER_LINE" ]; then
    verdict PASS "scored work selection runs" "$(printf '%s' "$PLANNER_LINE" | sed 's/.*Planner chose/Planner chose/' | cut -c1-70)"
else
    verdict WARN "scored work selection runs" "no 'Planner chose' line yet — needs an alive host to have work to rank"
fi

IDLE_LINE="$(grep -h 'idling' "$DATA/logs/orchestrator.py.log" 2>/dev/null | tail -1)"
info "last idle notice" "${IDLE_LINE:-<none>}"
IDLE_COUNT="$(grep -hc 'idling' "$DATA/logs/orchestrator.py.log" 2>/dev/null)"; IDLE_COUNT="${IDLE_COUNT:-0}"
if [ "${IDLE_COUNT:-0}" -lt 200 ]; then
    verdict PASS "idle notice logged once per window" "$IDLE_COUNT idle lines total (the P1 flood wrote 7000+)"
else
    verdict WARN "idle notice logged once per window" "$IDLE_COUNT idle lines — high; check for a per-second regression"
fi

OFF_LOG="$DATA/logs/offline_mode.py.log"
if [ -f "$OFF_LOG" ]; then
    verdict PASS "offline mode has run" "$(agestr "$OFF_LOG"); last: $(tail -1 "$OFF_LOG" 2>/dev/null | cut -c1-70)"
else
    verdict SKIP "offline mode has run" "never triggered — unplug the uplink for a few minutes to exercise it"
fi

# Per-page dumps: every group the pages reference must resolve, or a page shows an empty card.
DUMP_FAIL=""
for g in wifi ble scan web snmp telegram bettercap; do
    n="$(api_get "/module_files/$g" | python3 -c 'import sys,json
try: d=json.load(sys.stdin)
except Exception: print(0); raise SystemExit
f=d.get("files") if isinstance(d,dict) else d
print(len(f) if isinstance(f,list) else 0)' 2>/dev/null)"
    [ "${n:-0}" -gt 0 ] || DUMP_FAIL="$DUMP_FAIL $g"
done
if [ -z "$DUMP_FAIL" ]; then
    verdict PASS "per-page file groups resolve" "wifi ble scan web snmp telegram bettercap"
else
    verdict FAIL "per-page file groups resolve" "empty or erroring:$DUMP_FAIL"
fi

HELP_CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://$HOSTPORT/help.html" 2>/dev/null)"
[ "$HELP_CODE" = "200" ] && verdict PASS "help page served" "GET /help.html → 200" \
                         || verdict FAIL "help page served" "GET /help.html → $HELP_CODE"

CMT_MISS="$(grep -hc 'No comment found for theme' "$DATA/logs/comment.py.log" 2>/dev/null)"; CMT_MISS="${CMT_MISS:-0}"
if [ "${CMT_MISS:-0}" -eq 0 ]; then
    verdict PASS "every action has a comment theme" "no theme-miss warnings"
else
    verdict WARN "every action has a comment theme" "$CMT_MISS theme misses — an action is falling back to IDLE"
fi

# ===========================================================================
section "Summary"
# ===========================================================================
printf '%s' "$RESULTS" | awk -F'|' 'NF>1 {printf "  %-5s %s%s\n", $1, $2, ($3 ? " — " $3 : "")}'
echo
printf '%s' "$RESULTS" | awk -F'|' 'NF>1 {c[$1]++} END {printf "  %d PASS, %d FAIL, %d WARN, %d SKIP\n", c["PASS"], c["FAIL"], c["WARN"], c["SKIP"]}'
[ -n "${REPORT_FILE:-}" ] && echo "  Saved to $REPORT_FILE"
echo
echo "  A FAIL is a backlog item that stays open. A WARN usually means 'needs a target', not a bug."
