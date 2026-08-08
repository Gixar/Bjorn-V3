#!/usr/bin/env python3
"""bjorn_verify.py — on-device verification of the things only hardware can confirm.

Ported from bjorn_verify.sh (git show d31dc12:scripts/bjorn_verify.sh for the original, if you
want to diff two reports). The port exists for one reason: every bug this script has ever had was
a *silent wrong answer* from shell string handling — `grep -c` printing "0" and exiting 1 so
`|| echo 0` yielded "0\\n0" and broke every numeric test; Python's csv.writer emitting \\r\\n so a
trailing CR made `-eq` fail and a passing comparison read as "no comparable row". A script whose
entire job is to not lie about state cannot have that failure mode. Here the parsing is typed, and
the pure parts are unit-tested in tests/test_bjorn_verify.py.

NOT read-only, unlike bjorn_diag.sh. This one *acts*: real airodump capture, real benchmark, real
Telegram/SMTP message. That is the point — these items are "needs the Pi to actually do the thing".
Run bjorn_diag.sh first if something is broken; run this to close backlog items.

Nothing is reconfigured. The only writes are the ones Bjorn itself makes plus this report.

SECURITY: this script runs under sudo, and $REPO is a directory it merely *located* — owned by the
bjorn user, or by any local user via the /home/*/Bjorn glob. It therefore READS from that tree and
never executes anything out of it. Keep it that way (see the 2026-08-08 review: a pip binary and a
git call there were both root shells).

Usage:
  sudo /home/bjorn/Bjorn/scripts/bjorn_verify.py --save
  sudo /home/bjorn/Bjorn/scripts/bjorn_verify.py --quick --no-send
"""
import os
import re
import csv
import sys
import glob
import json
import time
import shutil
import argparse
import subprocess
import urllib.error
import urllib.request
from datetime import datetime

PASS, FAIL, WARN, SKIP = "PASS", "FAIL", "WARN", "SKIP"


# ---------------------------------------------------------------------------
# Pure helpers — no I/O beyond reading a path, no subprocesses. Unit-tested.
# ---------------------------------------------------------------------------
def truthy(value):
    """Config booleans arrive as JSON true, or as the strings Python/shell print. The shell
    version compared against "True" and "true" by hand at every call site and got it wrong once."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "1", "yes")


def count_matching(path, needle):
    """Lines containing `needle`; 0 for a missing file.

    This is the function the port was written for. `grep -c` prints 0 AND exits 1 on no-match, so
    the idiomatic `$(grep -c x f || echo 0)` returns "0\\n0" and every `-eq` on it silently fails.
    """
    try:
        with open(path, errors="replace") as f:
            return sum(1 for line in f if needle in line)
    except OSError:
        return 0


def last_matching(path, needle):
    """Last line containing `needle`, or "" — the `grep | tail -1` idiom."""
    hit = ""
    try:
        with open(path, errors="replace") as f:
            for line in f:
                if needle in line:
                    hit = line.rstrip("\n")
    except OSError:
        pass
    return hit


def csv_rows(path):
    """Data rows (excluding the header) in a CSV, or 0 if it does not exist."""
    try:
        with open(path, newline="", errors="replace") as f:
            return max(0, sum(1 for _ in f) - 1)
    except OSError:
        return 0


def file_age(path):
    """Seconds since mtime, or None when the file is absent."""
    try:
        return int(time.time() - os.path.getmtime(path))
    except OSError:
        return None


def age_str(path):
    age = file_age(path)
    return "missing" if age is None else f"{age // 60}m ago"


def parse_default_route(ip_route_output):
    """Interface carrying the default route, or "". Same shape monitor_mode.py parses; duplicated
    rather than imported because this script must run standalone after being scp'd anywhere."""
    for line in ip_route_output.splitlines():
        parts = line.split()
        if parts[:1] == ["default"] and "dev" in parts:
            return parts[parts.index("dev") + 1]
    return ""


def parse_unit_password(unit_text):
    """api.rest password out of the bettercap unit's ExecStart, or ""."""
    match = re.search(r"api\.rest\.password\s+([^;\"'\s]+)", unit_text)
    return match.group(1) if match else ""


def engine_from_log(log_text):
    """'rustscan' / 'nmap' / '' from the last 'Port discovery engine:' line."""
    engine = ""
    for line in log_text.splitlines():
        if "Port discovery engine" in line:
            engine = "rustscan" if "rustscan" in line else "nmap"
    return engine


def pick_monitor_iface(payload):
    """(iface, why) the capture would actually use, from a /wifi_ifaces response. Pure/testable.

    Mirrors offline_mode.pick_scan_iface: the configured radio if it is present and is not the
    uplink, else ANY other non-uplink radio. Reading only `configured` — as the shell version did —
    made the script more pessimistic than the code it verifies: on a box with wifi_scan_iface blank
    and a dongle plugged in, Bjorn captures happily while the verifier skipped the capture *and*
    the Stage A radio-ownership test, which is the one that most needed running.
    """
    if not isinstance(payload, dict):
        return "", "no /wifi_ifaces response"
    interfaces = payload.get("interfaces") or []
    names = {i.get("name"): bool(i.get("uplink")) for i in interfaces if isinstance(i, dict)}
    configured = (payload.get("configured") or "").strip()
    if configured:
        if configured not in names:
            return "", f"configured radio {configured} is not present"
        if names[configured]:
            return "", f"configured radio {configured} is the uplink"
        return configured, "configured"
    spare = next((n for n, uplink in names.items() if not uplink), "")
    return (spare, "unconfigured — Bjorn falls back to any non-uplink radio") if spare \
        else ("", "no non-uplink radio present")


def file_group_count(payload):
    """Entries in a /module_files/<group> response, tolerating both shapes and an error body."""
    if isinstance(payload, dict):
        payload = payload.get("files")
    return len(payload) if isinstance(payload, list) else 0


def benchmark_ports(csv_path):
    """(nmap_ports, rustscan_ports) from the last benchmark row, or (None, None).

    Read with the csv module on purpose: csv.writer terminates rows with \\r\\n, and in the shell
    version that trailing CR rode into the last field and made a real comparison read as "no
    comparable row". Nothing to strip here — the parser owns the line ending.
    """
    try:
        with open(csv_path, newline="") as f:
            rows = [r for r in csv.reader(f) if r]
    except OSError:
        return None, None
    if len(rows) < 2:
        return None, None
    last = rows[-1]
    if len(last) < 8:
        return None, None
    try:
        return int(last[6]), int(last[7])
    except ValueError:
        return None, None


def summarize(results):
    """{verdict: count} over collected (verdict, label, detail) triples."""
    counts = {PASS: 0, FAIL: 0, WARN: 0, SKIP: 0}
    for verdict, _label, _detail in results:
        counts[verdict] = counts.get(verdict, 0) + 1
    return counts


def resolve_repo(override="", script_dir="", probe=os.path.isfile):
    """Where the install lives. Deliberately NOT "the directory above this script": this file gets
    scp'd around and run from ~, and a wrong repo makes every CSV read a path that does not exist —
    which reads as "the feature is broken" rather than "you ran it from the wrong place". systemd
    knows the answer, so it is asked first and the guess is verified before use."""
    if override:
        return override
    candidates = [_systemd_working_dir()]
    if script_dir:
        candidates.append(os.path.dirname(script_dir))
    candidates += sorted(glob.glob("/home/*/Bjorn")) + ["/opt/Bjorn",
                                                       os.path.join(os.path.expanduser("~"), "Bjorn")]
    for path in candidates:
        if path and probe(os.path.join(path, "config", "shared_config.json")):
            return path
    return ""


# ---------------------------------------------------------------------------
# Thin I/O layer
# ---------------------------------------------------------------------------
def run(args, timeout=20):
    """(rc, stdout+stderr). No shell=True anywhere: argv lists cannot be word-split or injected."""
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (subprocess.SubprocessError, OSError) as e:
        return -1, str(e)


def _systemd_working_dir():
    rc, out = run(["systemctl", "show", "-p", "WorkingDirectory", "--value", "bjorn.service"])
    return out.strip() if rc == 0 else ""


def have(binary):
    return shutil.which(binary) is not None


class Api:
    """Bjorn's own web API. urllib, so curl is not a dependency of verifying Bjorn."""

    def __init__(self, hostport):
        self.base = f"http://{hostport}"

    def _call(self, path, payload=None, timeout=60):
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(
            self.base + path, data=data,
            headers={"Content-Type": "application/json"} if data else {},
            method="POST" if data is not None or payload == {} else "GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
            return json.loads(body) if body.strip() else {}
        except (urllib.error.URLError, OSError, json.JSONDecodeError):
            return None

    def get(self, path, timeout=30):
        return self._call(path, None, timeout)

    def post(self, path, payload=None, timeout=60):
        return self._call(path, payload if payload is not None else {}, timeout)

    def status_code(self, path, timeout=10):
        try:
            with urllib.request.urlopen(self.base + path, timeout=timeout) as resp:
                return resp.status, len(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, 0
        except (urllib.error.URLError, OSError):
            return 0, 0


class Report:
    def __init__(self, save_path=None):
        self.results = []
        self.color = sys.stdout.isatty()
        self._fh = open(save_path, "w", encoding="utf-8") if save_path else None
        self.save_path = save_path

    def line(self, text):
        print(text)
        if self._fh:
            self._fh.write(text + "\n")

    def section(self, title):
        self.line(f"\n{'=== ' + title + ' ==='}")

    def info(self, label, value):
        self.line(f"  {label:<26} {value}")

    def verdict(self, verdict, label, detail=""):
        tint = {PASS: "\033[32m", FAIL: "\033[31m", WARN: "\033[33m"}.get(verdict, "")
        off = "\033[0m" if tint else ""
        if not self.color:
            tint = off = ""
        self.line(f"  {tint}[{verdict}]{off} {label}" + (f" — {detail}" if detail else ""))
        self.results.append((verdict, label, detail))

    def close(self):
        if self._fh:
            self._fh.close()


def _read(path):
    try:
        with open(path, errors="replace") as f:
            return f.read()
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# Checks. One method per section of the report.
# ---------------------------------------------------------------------------
class Verifier:
    def __init__(self, repo, api, report, quick=False, no_send=False):
        self.repo, self.api, self.r = repo, api, report
        self.quick, self.no_send = quick, no_send
        self.data = os.path.join(repo, "data")
        self.logs = os.path.join(self.data, "logs")
        self.out = os.path.join(self.data, "output")
        self.scan = os.path.join(self.out, "scan_results")
        self.cracked = os.path.join(self.out, "crackedpwd")
        self.vuln = os.path.join(self.out, "vulnerabilities")
        with open(os.path.join(repo, "config", "shared_config.json"), errors="replace") as f:
            self.config = json.load(f)
        self.mon_iface = ""
        self.uplink = ""

    def log(self, name):
        return os.path.join(self.logs, name)

    def cfg(self, key, default=""):
        return self.config.get(key, default)

    # -- 0 ------------------------------------------------------------------
    def preflight(self):
        self.r.section("0. Preflight")
        self.r.info("version.txt", _read(os.path.join(self.repo, "version.txt")).strip() or "?")
        # build_info, never `git` in $REPO: that tree is not root-owned and this runs under sudo.
        # It is also the only stamp that resolves on a device, where the tree is a copy of the
        # repo rather than a checkout (BACKLOG.md).
        commit = "?"
        for line in _read(os.path.join(self.repo, "build_info")).splitlines():
            if line.startswith("source_commit="):
                commit = line.split("=", 1)[1].strip()[:60]
        self.r.info("commit", commit if commit != "?" else "? (reinstall to stamp the build)")
        self.r.info("service", run(["systemctl", "is-active", "bjorn.service"])[1].strip() or "?")

        code, _ = self.api.status_code("/")
        if code == 200:
            self.r.verdict(PASS, "#155 web server reachable", "GET / -> 200")
        else:
            self.r.verdict(FAIL, "#155 web server reachable",
                           f"GET / -> {code or 'no response'}; every API check below will fail")

    # -- 1 ------------------------------------------------------------------
    def wifi_recon(self):
        self.r.section("1. Wi-Fi recon end-to-end (Wave 4)")
        self.uplink = parse_default_route(run(["ip", "route", "show", "default"])[1])
        ifaces = self.api.get("/wifi_ifaces") or {}
        self.mon_iface, why = pick_monitor_iface(ifaces)
        self.r.info("uplink (default route)", self.uplink or "none")
        self.r.info("wireless interfaces", json.dumps(ifaces.get("interfaces", [])))
        self.r.info("configured monitor iface", ifaces.get("configured") or "<unset>")
        self.r.info("radio the capture will use", f"{self.mon_iface or 'none'} ({why})")

        if not self.mon_iface:
            if ifaces.get("configured"):
                self.r.verdict(FAIL, "Wi-Fi radio present",
                               f"{why} (dongle moved USB port? the INNER micro-USB is the data one)")
            else:
                self.r.verdict(SKIP, "Wi-Fi capture", why)
            return
        self.r.verdict(PASS, "Wi-Fi radio present", f"{self.mon_iface} enumerated ({why})")

        # Guard regression - must REFUSE the uplink. Read-only, so it costs nothing to check, and
        # a guard bug found here cannot take the uplink with it.
        if self.uplink:
            guard = self.api.post("/wifi_monitor_test", {"iface": self.uplink}) or {}
            if guard.get("status") == "error":
                self.r.verdict(PASS, "guard refuses the uplink", str(guard.get("message"))[:60])
            else:
                self.r.verdict(FAIL, "guard refuses the uplink",
                               f"ACCEPTED {self.uplink} - do NOT run a capture, check_usable is broken")
                return

        test = self.api.post("/wifi_monitor_test", {"iface": self.mon_iface}) or {}
        if test.get("status") == "success":
            self.r.verdict(PASS, "monitor mode supported", self.mon_iface)
        else:
            self.r.verdict(FAIL, "monitor mode supported", str(test.get("message")))

        if not have("airodump-ng"):
            self.r.verdict(FAIL, "airodump-ng installed", "not on PATH - install aircrack-ng")
        elif self.quick:
            self.r.verdict(SKIP, "airodump capture", "--quick")
        else:
            self._capture()

    def _wait_for_airodump(self, tries=18):
        """True once airodump is gone. The capture is over when the process exits, not when the
        clock says so: 'still flushing' and 'stranded' look identical at a fixed deadline."""
        for _ in range(tries):
            if run(["pgrep", "-x", "airodump-ng"])[0] != 0:
                return True
            time.sleep(5)
        return False

    def _capture(self):
        aps = os.path.join(self.scan, "wifi_aps.csv")
        clients = os.path.join(self.scan, "wifi_clients.csv")
        before = (csv_rows(aps), csv_rows(clients))
        started = self.api.post("/wifi_scan_now") or {}
        if started.get("status") != "success":
            self.r.verdict(FAIL, "airodump capture", str(started.get("message")))
            return
        duration = int(started.get("duration") or 30)
        print(f"  ... capturing for {duration}s on {self.mon_iface}")
        time.sleep(duration + 10)
        if not self._wait_for_airodump():
            self.r.verdict(FAIL, "airodump exits on its timeout",
                           f"still running {duration + 100}s in - the subprocess timeout is not "
                           f"stopping it")

        after = (csv_rows(aps), csv_rows(clients))
        self.r.info("wifi_aps.csv", f"{before[0]} -> {after[0]} rows ({age_str(aps)})")
        self.r.info("wifi_clients.csv", f"{before[1]} -> {after[1]} rows ({age_str(clients)})")
        age = file_age(aps)
        if after[0] > 0 and age is not None and age < duration + 200:
            self.r.verdict(PASS, "airodump capture",
                           f"{after[0]} APs / {after[1]} clients, just written")
        else:
            self.r.verdict(FAIL, "airodump capture", "no fresh AP rows")
            for line in _read(self.log("wifi_scan.py.log")).splitlines()[-8:]:
                print("  " + line)

        # release() - the radio must be back in managed mode. rc first: `iw` failing is "could not
        # tell", which must not be reported as "stranded" — a false FAIL on a verification script
        # sends someone hunting a bug that isn't there.
        iw_rc, info = run(["iw", "dev", self.mon_iface, "info"])
        mode = next((l.split()[1] for l in info.splitlines()
                     if l.strip().startswith("type") and len(l.split()) > 1), "unknown")
        if iw_rc != 0:
            self.r.verdict(WARN, f"release() restored {self.mon_iface}",
                           f"could not read the mode: {info.strip()[:60]}")
        elif mode == "managed":
            self.r.verdict(PASS, f"release() restored {self.mon_iface}", "type=managed")
        else:
            self.r.verdict(FAIL, f"release() restored {self.mon_iface}",
                           f"type={mode} - radio stranded")
            print(f"  recover: sudo iw dev {self.mon_iface} set type managed && "
                  f"sudo nmcli device set {self.mon_iface} managed yes")
        # NB: no early return above — the uplink check below is the most important verdict in this
        # section and must run whatever the radio's mode turned out to be.

        # The whole reason the guard exists: the uplink must be untouched afterwards.
        now_route = parse_default_route(run(["ip", "route", "show", "default"])[1])
        code, _ = self.api.status_code("/")
        if now_route == self.uplink and code == 200:
            self.r.verdict(PASS, "uplink undisturbed",
                           f"route still {self.uplink or 'none'}, web 200")
        else:
            self.r.verdict(FAIL, "uplink undisturbed",
                           f"route {self.uplink or 'none'} -> {now_route or 'none'}, web {code}")

    # -- 2 ------------------------------------------------------------------
    def benchmark(self):
        self.r.section("2. Scan engine - rustscan batch tuning")
        self.r.info("use_rustscan", self.cfg("use_rustscan"))
        self.r.info("rustscan_batch_size", f"{self.cfg('rustscan_batch_size')} (0 = auto)")
        self.r.info("rustscan binary", shutil.which("rustscan") or "not on PATH")
        if self.quick:
            self.r.verdict(SKIP, "benchmark nmap vs rustscan", "--quick")
            return
        started = self.api.post("/run_benchmark") or {}
        if started.get("status") != "success":
            self.r.verdict(FAIL, "benchmark nmap vs rustscan", str(started.get("message")))
            return
        print("  ... benchmark running (two full discovery passes; polling up to 12min)")
        for _ in range(72):
            time.sleep(10)
            if (self.api.get("/benchmark_results") or {}).get("running") is False:
                break
        nmap_n, rust_n = benchmark_ports(os.path.join(self.data, "scan_engine_benchmark.csv"))
        batch = self.cfg("rustscan_batch_size")
        if nmap_n is None:
            self.r.verdict(WARN, "benchmark nmap vs rustscan",
                           "no comparable row (rustscan skipped? see the CSV)")
        elif rust_n >= nmap_n:
            self.r.verdict(PASS, "rustscan finds every port nmap does",
                           f"nmap={nmap_n} rustscan={rust_n} at batch {batch} - this batch is safe")
        else:
            self.r.verdict(FAIL, "rustscan finds every port nmap does",
                           f"nmap={nmap_n} rustscan={rust_n} - DROPPED PORTS: lower "
                           f"rustscan_batch_size and re-run")

    # -- 3 ------------------------------------------------------------------
    def usb_gadget(self):
        self.r.section("3. usb0 gadget (#68)")
        addr_rc, addr = run(["ip", "-4", "addr", "show", "usb0"])
        link_rc, link = run(["ip", "link", "show", "usb0"])
        # rc, not just output: run() folds stderr into its output, so a MISSING usb0 comes back
        # non-empty ("Device usb0 does not exist") and would read as a present interface with
        # carrier. The shell version sent stderr to /dev/null and got an empty string for free —
        # this is the one behaviour the port had to restore by hand.
        if link_rc != 0:
            link = ""
        ip4 = "" if addr_rc != 0 else next(
            (l.split()[1] for l in addr.splitlines() if l.strip().startswith("inet ")), "")
        self.r.info("usb0 address", ip4 or "none")
        if ip4.split("/")[0] == "172.20.2.1":
            self.r.verdict(PASS, "usb0 addressed without carrier", ip4)
        else:
            self.r.verdict(FAIL, "usb0 addressed without carrier",
                           f"expected 172.20.2.1/24, got {ip4 or 'nothing'}")
        if not link.strip():
            self.r.verdict(SKIP, "DHCP lease handed to a host",
                           "usb0 absent - the gadget never came up (see bjorn_diag.sh)")
        elif "NO-CARRIER" in link:
            self.r.verdict(SKIP, "DHCP lease handed to a host",
                           "nothing plugged in - plug a laptop in, re-run, open http://172.20.2.1:8000/")
        else:
            status = run(["networkctl", "status", "usb0"])[1]
            self.r.verdict(PASS if "lease" in status.lower() else WARN,
                           "DHCP lease handed to a host", "carrier up")

    # -- 4 ------------------------------------------------------------------
    def display_and_ui(self):
        self.r.section("4. Display + web UI (#122, #113, #176)")
        self.r.info("epd_type", self.cfg("epd_type"))
        code, size = self.api.status_code("/screen.png", timeout=15)
        if code == 200 and size > 1000:
            self.r.verdict(PASS, "#122 framebuffer renders",
                           f"screen.png {size} bytes - compare it against the physical panel for #113")
        else:
            self.r.verdict(FAIL, "#122 framebuffer renders", f"HTTP {code}, {size} bytes")
        portlist = (self.api.get("/load_config") or {}).get("portlist")
        self.r.info("portlist (from API)", json.dumps(portlist))
        if isinstance(portlist, list):
            self.r.verdict(PASS, "#176 portlist round-trips as a list",
                           "now edit it in the GUI with commas and re-run to confirm the save path")
        else:
            self.r.verdict(FAIL, "#176 portlist round-trips as a list", f"not a JSON array: {portlist!r}")

    # -- 5 ------------------------------------------------------------------
    def action_evidence(self):
        self.r.section("5. Action evidence (needs a real target)")

        def evidence(label, path, enabled, needs):
            n = csv_rows(path)
            self.r.info(os.path.basename(path), f"{n} rows, {age_str(path)}")
            if not enabled:
                self.r.verdict(SKIP, label, "disabled")
            elif n > 0:
                self.r.verdict(PASS, label, f"{n} rows ({age_str(path)})")
            else:
                self.r.verdict(WARN, label, f"no rows yet - {needs}")

        evidence("BLE recon", os.path.join(self.scan, "ble_devices.csv"),
                 truthy(self.cfg("ble_scan_enabled")), "needs a BLE device in range")
        evidence("HTTP fingerprint", os.path.join(self.scan, "http_fingerprints.csv"),
                 True, "needs a host with an open web port")
        evidence("Web templates", os.path.join(self.scan, "web_template_findings.csv"),
                 True, "hits only; empty is a valid result")
        evidence("SNMP enumeration", os.path.join(self.scan, "snmp_enum.csv"),
                 True, "needs a host answering UDP/161")
        evidence("Credential reuse", os.path.join(self.cracked, "known_creds.csv"),
                 True, "needs a crackable host (weak SSH/FTP/SMB password)")
        evidence("wpa-sec import", os.path.join(self.cracked, "wifi_wpasec.csv"),
                 bool(self.cfg("wpasec_api_key")), "needs wpasec_api_key + internet")

        n_vuln = len(glob.glob(os.path.join(self.vuln, "*")))
        self.r.info("vulnerabilities/", f"{n_vuln} files")
        self.r.verdict(PASS if n_vuln else WARN, "CVE enrichment",
                       f"{n_vuln} vuln files - grep one for a CVE line" if n_vuln
                       else "needs a host running a known-vulnerable service version")

    # -- 6 ------------------------------------------------------------------
    def delivery(self):
        self.r.section("6. Report delivery (Telegram / SMTP)")
        tg, smtp = truthy(self.cfg("telegram_enabled")), truthy(self.cfg("smtp_enabled"))
        self.r.info("telegram_enabled", tg)
        self.r.info("smtp_enabled", smtp)
        if self.no_send:
            self.r.verdict(SKIP, "delivery test", "--no-send")
        elif not tg and not smtp:
            self.r.verdict(SKIP, "delivery test", "neither channel enabled")
        else:
            result = self.api.post("/telegram_test") or {}
            if result.get("status") == "success":
                self.r.verdict(PASS, "delivery test", "sent - confirm it arrived in the chat/mailbox")
            else:
                self.r.verdict(FAIL, "delivery test", str(result.get("message")))

    # -- 7 ------------------------------------------------------------------
    def dependencies(self):
        self.r.section("7. Dependency set (P1-2)")
        # Always this interpreter, never a pip found inside $REPO: executing anything out of a tree
        # this script merely *located* is a root shell (2026-08-08 security review).
        self.r.info("python3", sys.version.split()[0])
        unit = run(["systemctl", "show", "-p", "ExecStart", "--value", "bjorn.service"])[1]
        match = re.search(r"/\S*python[0-9.]*", unit)
        self.r.info("service interpreter", match.group(0) if match else "?")
        rc, out = run([sys.executable, "-m", "pip", "freeze"], timeout=120)
        packages = [l for l in out.splitlines() if l.strip()] if rc == 0 else []
        if packages:
            os.makedirs(self.out, exist_ok=True)
            freeze = os.path.join(self.out, f"pip_freeze_{datetime.now():%Y%m%d}.txt")
            with open(freeze, "w") as f:
                f.write("\n".join(packages) + "\n")
            self.r.verdict(PASS, "pip freeze captured", f"{freeze} ({len(packages)} packages)")
        else:
            self.r.verdict(WARN, "pip freeze captured", "pip freeze produced nothing")

    # -- 8a -----------------------------------------------------------------
    def defaults(self):
        self.r.section("8a. Collect-by-default (c5b2b44)")
        # The EFFECTIVE config: a shared_config.json saved before the upgrade silently overrides a
        # changed default - everything keeps working, it just collects nothing.
        for key, label in (("ble_scan_enabled", "BLE recon on by default"),
                           ("wifi_scan_enabled", "Wi-Fi survey on by default"),
                           ("use_rustscan", "RustScan is the default engine")):
            value = self.cfg(key, "<absent>")
            if truthy(value):
                self.r.verdict(PASS, label, f"{key}={value}")
            else:
                self.r.verdict(FAIL, label, f"{key}={value} - a pre-upgrade saved config wins over "
                                            f"the new default; fix it on /config")
        offline = self.cfg("ble_scan_interval_offline")
        self.r.verdict(PASS if offline else WARN, "BLE hunts faster offline",
                       f"{offline}s vs {self.cfg('ble_scan_interval')}s online" if offline
                       else "key absent from the saved config - the 60s default still applies")
        # The engine actually SELECTED, not the toggle: rustscan resolves off-PATH cargo installs,
        # so the toggle being on is not proof the binary was found.
        engine = engine_from_log(_read(self.log("scanning.py.log")))
        if engine == "rustscan":
            self.r.verdict(PASS, "rustscan is the engine in use", "confirmed from scanning.py.log")
        elif engine == "nmap":
            self.r.verdict(FAIL, "rustscan is the engine in use",
                           "fell back to nmap - the binary was not found")
        else:
            self.r.verdict(WARN, "rustscan is the engine in use", "no engine line logged yet")

    # -- 8b -----------------------------------------------------------------
    def radio_ownership(self):
        self.r.section("8b. Radio ownership - busy must SKIP, not FAIL (Stage A)")
        wlog = self.log("wifi_scan.py.log")
        if self.quick or not self.mon_iface or not have("airodump-ng"):
            self.r.verdict(SKIP, "busy radio is a clean skip", "needs a monitor radio + airodump-ng")
            return
        before = count_matching(wlog, "ERROR")
        self.api.post("/wifi_scan_now")          # takes the radio
        time.sleep(5)
        self.api.post("/wifi_scan_now")          # must be turned away politely
        time.sleep(5)
        after = count_matching(wlog, "ERROR")
        busy = last_matching(wlog, "radio is in use")
        self.r.info("wifi_scan errors", f"{before} -> {after}")
        if busy and after == before:
            self.r.verdict(PASS, "busy radio is a clean skip",
                           "second capture declined, no new ERROR")
        elif after > before:
            self.r.verdict(FAIL, "busy radio is a clean skip",
                           "a contended radio logged an ERROR - Stage A regressed")
        else:
            self.r.verdict(WARN, "busy radio is a clean skip",
                           "no contention observed (the first capture may have finished first)")
        self._wait_for_airodump()

    # -- 8c -----------------------------------------------------------------
    def bettercap(self):
        self.r.section("8c. Bettercap plumbing (Stage B)")
        self.r.info("bettercap binary", shutil.which("bettercap") or "not installed (optional)")
        self.r.info("bettercap_enabled", self.cfg("bettercap_enabled"))
        page, _ = self.api.status_code("/bettercap.html")
        status = self.api.get("/bettercap_status")
        if page == 200 and status is not None:
            self.r.verdict(PASS, "Bettercap panel reachable", f"status: {status.get('message')}")
        else:
            self.r.verdict(FAIL, "Bettercap panel reachable",
                           f"page {page}, status endpoint {'answered' if status else 'silent'}")

        unit_path = "/etc/systemd/system/bettercap.service"
        if not os.path.exists(unit_path):
            self.r.verdict(SKIP, "bettercap.service provisioned",
                           "no unit - the optional installer step did not run")
            return
        enabled = run(["systemctl", "is-enabled", "bettercap.service"])[1].strip()
        if enabled == "enabled" and not truthy(self.cfg("bettercap_enabled")):
            self.r.verdict(FAIL, "bettercap stays off until asked",
                           "unit enabled but bettercap_enabled is false - it starts at boot with "
                           "nothing reading it")
        else:
            self.r.verdict(PASS, "bettercap stays off until asked", f"is-enabled={enabled}")

        unit_text = _read(unit_path)          # chmod 600, so this needs sudo
        if not unit_text:
            self.r.verdict(SKIP, "bettercap password generated + in sync", "needs sudo to read the unit")
            return
        unit_pw, cfg_pw = parse_unit_password(unit_text), self.cfg("bettercap_password")
        if not unit_pw:
            self.r.verdict(WARN, "bettercap password generated + in sync", "not found in the unit")
        elif unit_pw in ("pass", "bjorn"):
            self.r.verdict(FAIL, "bettercap password generated + in sync",
                           "the unit still carries a guessable password - regenerate it")
        elif unit_pw != cfg_pw:
            self.r.verdict(FAIL, "bettercap password generated + in sync",
                           "unit and shared_config.json disagree - the panel reports 'unauthorized'")
        else:
            self.r.verdict(PASS, "bettercap password generated + in sync",
                           f"generated ({len(unit_pw)} chars), matches the config")

    # -- 8d -----------------------------------------------------------------
    def unreleased_wave(self):
        self.r.section("8d. The Unreleased wave")
        orch = self.log("orchestrator.py.log")
        planner = last_matching(orch, "Planner chose")
        self.r.verdict(PASS if planner else WARN, "scored work selection runs",
                       planner[-70:] if planner
                       else "no 'Planner chose' line yet - needs an alive host with work to rank")
        idle = count_matching(orch, "idling")
        self.r.verdict(PASS if idle < 200 else WARN, "idle notice logged once per window",
                       f"{idle} idle lines (the P1 flood wrote 7000+)")
        off_log = self.log("offline_mode.py.log")
        self.r.verdict(PASS if os.path.exists(off_log) else SKIP, "offline mode has run",
                       age_str(off_log) if os.path.exists(off_log)
                       else "never triggered - unplug the uplink for a few minutes to exercise it")
        empty = [g for g in ("wifi", "ble", "scan", "web", "snmp", "telegram", "bettercap")
                 if file_group_count(self.api.get(f"/module_files/{g}")) == 0]
        self.r.verdict(PASS if not empty else FAIL, "per-page file groups resolve",
                       "all seven" if not empty else "empty or erroring: " + " ".join(empty))
        code, _ = self.api.status_code("/help.html")
        self.r.verdict(PASS if code == 200 else FAIL, "help page served", f"GET /help.html -> {code}")
        misses = count_matching(self.log("comment.py.log"), "No comment found for theme")
        self.r.verdict(PASS if misses == 0 else WARN, "every action has a comment theme",
                       "no theme-miss warnings" if misses == 0
                       else f"{misses} misses - an action falls back to IDLE")

    def all_checks(self):
        return (self.preflight, self.wifi_recon, self.benchmark, self.usb_gadget,
                self.display_and_ui, self.action_evidence, self.delivery, self.dependencies,
                self.defaults, self.radio_ownership, self.bettercap, self.unreleased_wave)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Bjorn on-device verification")
    ap.add_argument("--quick", action="store_true", help="skip the slow active checks")
    ap.add_argument("--no-send", action="store_true", help="skip the Telegram/SMTP test message")
    ap.add_argument("--save", action="store_true", help="write the report under data/output/")
    ap.add_argument("--repo", default="", help="override the install path")
    ap.add_argument("--url", default="127.0.0.1:8000", help="web API address")
    args = ap.parse_args(argv)

    repo = resolve_repo(args.repo, os.path.dirname(os.path.abspath(__file__)))
    if not repo:
        print("Could not locate the Bjorn install (no config/shared_config.json via the systemd "
              "unit, this script's parent, /home/*/Bjorn or /opt/Bjorn).")
        print(f"Pass it explicitly:  {sys.argv[0]} --repo /home/bjorn/Bjorn")
        return 1

    save_path = None
    if args.save:
        out = os.path.join(repo, "data", "output")
        os.makedirs(out, exist_ok=True)
        save_path = os.path.join(out, f"verify_{datetime.now():%Y%m%d_%H%M%S}.txt")

    report = Report(save_path)
    report.line(f"Bjorn verification - {datetime.now().isoformat(timespec='seconds')}")
    # geteuid is Unix-only. The script targets the Pi, but it must still start on a dev box —
    # otherwise the only way to smoke-test the report is on the hardware it exists to test.
    euid = getattr(os, "geteuid", lambda: -1)()
    report.line(f"Repo: {repo}  |  Root: {'yes' if euid == 0 else 'no' if euid > 0 else 'n/a'}  |  "
                f"Mode: {'quick' if args.quick else 'full'}{', no-send' if args.no_send else ''}")

    verifier = Verifier(repo, Api(args.url), report, args.quick, args.no_send)
    for check in verifier.all_checks():
        try:
            check()
        except Exception as e:      # one broken check must not cost the rest of the report
            report.verdict(WARN, f"{check.__name__} crashed", f"{type(e).__name__}: {e}")

    report.section("Summary")
    for verdict, label, detail in report.results:
        report.line(f"  {verdict:<5} {label}" + (f" - {detail}" if detail else ""))
    counts = summarize(report.results)
    report.line(f"\n  {counts[PASS]} PASS, {counts[FAIL]} FAIL, {counts[WARN]} WARN, "
                f"{counts[SKIP]} SKIP")
    if save_path:
        report.line(f"  Saved to {save_path}")
    report.line("\n  A FAIL is a backlog item that stays open. A WARN usually means 'needs a "
                "target', not a bug.")
    report.close()
    return 1 if counts[FAIL] else 0


if __name__ == "__main__":
    sys.exit(main())
