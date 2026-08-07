#utils.py
#
# MIGRATION NOTE (webapp v3 / FastAPI):
# Every WebUtils method used to take a raw http.server `handler` and write status/headers/body
# to it directly (handler.send_response / handler.send_header / handler.wfile.write). FastAPI
# route functions instead return a Response object (or a plain dict, which FastAPI auto-wraps
# as JSON), so every method below has been converted to `return JSONResponse(...)` /
# `return HTMLResponse(...)` / etc. instead of writing to a handler. The internal logic
# (what each endpoint actually does) is unchanged from the previous version, so this should
# behave identically from the browser's point of view, with two exceptions noted inline:
#   1. serve_favicon(): fixed a real path bug (see comment at that method).
#   2. restore(): now takes a FastAPI UploadFile instead of manually parsing
#      multipart/form-data with `cgi.FieldStorage` (the `cgi` module is deprecated/removed
#      upstream in Python 3.13, so this also removes a future breakage).
# New in this version: get_stats_snapshot() for the live stats dashboard (/api/stats, /ws/stats).

import json
import subprocess
import os
import csv
import ipaddress
import threading
import zipfile
import uuid
import importlib
import logging
from datetime import datetime, timezone
from logger import Logger
import monitor_mode
import offline_mode
from starlette.responses import JSONResponse, HTMLResponse, PlainTextResponse, Response, FileResponse
from actions.nmap_vuln_scanner import NmapVulnScanner
import telegram_client


logger = Logger(name="utils.py", level=logging.DEBUG)


def _err(message, status_code=500):
    """Shorthand for the {"status": "error", "message": ...} JSON body every old handler used."""
    return JSONResponse({"status": "error", "message": str(message)}, status_code=status_code)


def _ok(payload=None, message=None, status_code=200):
    """Shorthand for the {"status": "success", ...} JSON body every old handler used."""
    body = {"status": "success"}
    if message is not None:
        body["message"] = message
    if payload:
        body.update(payload)
    return JSONResponse(body, status_code=status_code)


class WebUtils:
    def __init__(self, shared_data, logger):
        self.shared_data = shared_data
        self.logger = logger
        self.actions = None  # List that contains all actions
        self.standalone_actions = None  # List that contains all standalone actions

    def load_actions(self):
        """Load all actions from the actions file"""
        if self.actions is None or self.standalone_actions is None:
            self.actions = []  # reset the actions list
            self.standalone_actions = []  # reset the standalone actions list
            self.actions_dir = self.shared_data.actions_dir
            with open(self.shared_data.actions_file, 'r') as file:
                actions_config = json.load(file)
            for action in actions_config:
                module_name = action["b_module"]
                if module_name == 'scanning':
                    self.load_scanner(module_name)
                elif module_name == 'nmap_vuln_scanner':
                    self.load_nmap_vuln_scanner(module_name)
                else:
                    self.load_action(module_name, action)

    def load_scanner(self, module_name):
        """Load the network scanner"""
        module = importlib.import_module(f'actions.{module_name}')
        b_class = getattr(module, 'b_class')
        self.network_scanner = getattr(module, b_class)(self.shared_data)

    def load_nmap_vuln_scanner(self, module_name):
        """Load the nmap vulnerability scanner"""
        self.nmap_vuln_scanner = NmapVulnScanner(self.shared_data)

    def load_action(self, module_name, action):
        """Load an action from the actions file"""
        module = importlib.import_module(f'actions.{module_name}')
        try:
            b_class = action["b_class"]
            action_instance = getattr(module, b_class)(self.shared_data)
            action_instance.action_name = b_class
            action_instance.port = action.get("b_port")
            action_instance.b_parent_action = action.get("b_parent")
            if action_instance.port == 0:
                self.standalone_actions.append(action_instance)
            else:
                self.actions.append(action_instance)
        except AttributeError as e:
            self.logger.error(f"Module {module_name} is missing required attributes: {e}")

    # ------------------------------------------------------------------
    # Stats snapshot (new) — feeds GET /api/stats and the WS /ws/stats push
    # ------------------------------------------------------------------
    def get_stats_snapshot(self):
        """Build a plain dict of the live "gamified" stats plus a bit of status context.

        These numbers (coinnbr, levelnbr, networkkbnbr, ...) already exist on shared_data —
        they're what update_stats() in shared.py computes and what display.py draws onto the
        e-Paper image — but previously nothing exposed them over the web. This is the single
        source of truth for both the REST endpoint and the WebSocket push, so the two can never
        drift out of sync.
        """
        sd = self.shared_data
        return {
            "coins": getattr(sd, "coinnbr", 0),
            "level": getattr(sd, "levelnbr", 0),
            "known_hosts": getattr(sd, "networkkbnbr", 0),
            "credentials_cracked": getattr(sd, "crednbr", 0),
            "data_stolen": getattr(sd, "datanbr", 0),
            "zombies": getattr(sd, "zombiesnbr", 0),
            "attacks": getattr(sd, "attacksnbr", 0),
            "vulnerabilities": getattr(sd, "vulnnbr", 0),
            "targets": getattr(sd, "targetnbr", 0),
            "open_ports": getattr(sd, "portnbr", 0),
            "breakdown": getattr(sd, "_stats_breakdown", {}),  # per-category earned coins (Wave 1 #3)
            "orchestrator_status": getattr(sd, "bjornorch_status", "UNKNOWN"),
            "manual_mode": getattr(sd, "manual_mode", False),
            "wifi_connected": getattr(sd, "wifi_connected", False),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------
    # BLE recon results — GET /ble_data
    # ------------------------------------------------------------------
    def serve_ble_data(self):
        path = os.path.join(self.shared_data.scan_results_dir, "ble_devices.csv")
        try:
            with open(path, newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
        except FileNotFoundError:
            rows = []
        return JSONResponse({"devices": rows})

    # ------------------------------------------------------------------
    # Wi-Fi recon (airodump-ng) — GET /wifi_data, GET /wifi_ifaces, POST /wifi_monitor_test
    # ------------------------------------------------------------------
    def serve_wifi_data(self):
        def _rows(name):
            try:
                with open(os.path.join(self.shared_data.scan_results_dir, name),
                          newline="", encoding="utf-8") as f:
                    return list(csv.DictReader(f))
            except FileNotFoundError:
                return []
        return JSONResponse({"aps": _rows("wifi_aps.csv"), "clients": _rows("wifi_clients.csv")})

    def wifi_ifaces(self):
        """Wireless interfaces for the config dropdown, flagging the uplink so the user can't pick
        it by mistake (monitor_mode.acquire refuses it anyway — this just explains why)."""
        uplink = monitor_mode.default_route_iface()
        present = monitor_mode.wireless_ifaces()
        configured = (getattr(self.shared_data, "wifi_scan_iface", "") or "").strip()
        return JSONResponse({
            "interfaces": [{"name": n, "uplink": n == uplink} for n in present],
            "uplink": uplink,
            "configured": configured,
            # Interface names follow probe order, not the physical port, so a dongle moved to
            # another socket or re-enumerated after a reboot can come back under a different name —
            # or not at all. The saved name then points at nothing and the dropdown just renders
            # blank, which reads as "my config was lost" rather than "the radio is gone".
            "configured_missing": bool(configured and configured not in present),
        })

    def wifi_scan_now(self):
        """'Scan now' button: run one capture immediately, ignoring the enabled flag and the
        interval. Backgrounded like the benchmark — a capture is 30s+ and must not hold the HTTP
        request open. Overlap is refused by the radio lock in monitor_mode, not here: the scheduled
        WiFiScan can start at any moment, so a flag on this object would only cover half the race."""
        # Same resolver the scheduled action uses, so the button and the loop can never disagree
        # about which radio is fair game (offline, that includes the onboard one).
        iface = offline_mode.scan_iface(self.shared_data)
        problem = monitor_mode.check_usable(iface)
        if problem:
            return _err(problem)

        def _run():
            try:
                from actions.wifi_scan import WiFiScan
                WiFiScan(self.shared_data).execute(force=True)
            except Exception as e:
                self.logger.error(f"Manual Wi-Fi scan failed: {e}")

        threading.Thread(target=_run, daemon=True).start()
        duration = max(10, int(getattr(self.shared_data, "wifi_scan_duration", 30)))
        return _ok(message=f"Capture started on {iface} (~{duration}s).", payload={"duration": duration})

    def wifi_monitor_test(self, iface):
        """'Test monitor mode' button: check the guard and the radio's capability without capturing."""
        problem = monitor_mode.check_usable(iface)
        if problem:
            return _err(problem)
        if not monitor_mode.supports_monitor(iface):
            return _err(f"{iface} does not report monitor mode support")
        return _ok(message=f"{iface} supports monitor mode and is safe to use.")

    # ------------------------------------------------------------------
    # Report delivery (Telegram, SMTP fallback) — POST /telegram_test, POST /telegram_send
    # ------------------------------------------------------------------
    def telegram_test(self):
        """Test message down whichever channel is configured (Telegram first, then SMTP)."""
        ok, detail = telegram_client.send_test(self.shared_data)
        return _ok(message=f"Test message {detail}.") if ok else _err(detail)

    def telegram_send(self):
        """Force-compile the raw target dataset and send it now (ignores the delta check)."""
        ok, detail, _sent = telegram_client.send_targets(self.shared_data, force=True)
        return _ok(message=f"Target data {detail}.") if ok else _err(f"Send failed: {detail}")

    # ------------------------------------------------------------------
    # Scan-engine benchmark (nmap vs RustScan) — POST /run_benchmark, GET /benchmark_results
    # ------------------------------------------------------------------
    def run_benchmark(self):
        """Start NetworkScanner.benchmark_scan_engines() in a background thread (it runs two full
        discovery passes, so it must not block the HTTP request). Results append to
        data/scan_engine_benchmark.csv. Guarded so two runs can't overlap."""
        if getattr(self.shared_data, "benchmark_running", False):
            return _err("A benchmark is already running.", status_code=409)
        try:
            self.load_actions()  # loads self.network_scanner (idempotent)
        except Exception as e:
            return _err(e)
        scanner = getattr(self, "network_scanner", None)
        if scanner is None:
            return _err("Network scanner is not loaded")

        def _run():
            self.shared_data.benchmark_running = True
            try:
                scanner.benchmark_scan_engines()
            except Exception as e:
                self.logger.error(f"Benchmark failed: {e}")
            finally:
                self.shared_data.benchmark_running = False

        threading.Thread(target=_run, daemon=True).start()
        return _ok(message="Benchmark started — running nmap vs RustScan on the current network.")

    def benchmark_results(self, limit=10):
        """Return the most recent benchmark rows (from data/scan_engine_benchmark.csv) plus whether
        a run is currently in progress — the config page polls this to show the result when done."""
        path = os.path.join(self.shared_data.datadir, "scan_engine_benchmark.csv")
        rows = []
        try:
            if os.path.exists(path):
                with open(path, newline="") as f:
                    rows = list(csv.DictReader(f))
        except Exception as e:
            return _err(e)
        return JSONResponse({
            "running": getattr(self.shared_data, "benchmark_running", False),
            "results": rows[-limit:],
        })

    # ------------------------------------------------------------------
    # Per-page dumps & logs — GET /module_files/{group}, GET /module_file/{group}/{key}
    # ------------------------------------------------------------------
    def _file_groups(self):
        """Whitelist of what each page may expose: group -> [(key, label, absolute path)].

        A registry rather than a path parameter on purpose. The obvious version of this endpoint
        takes ?path= and sanitizes it, and then the security of every dump on the device rests on
        that sanitizer being right forever. Here the client sends a key, never a path, so directory
        traversal has nothing to traverse — and adding a file is one line, in one place."""
        sd = self.shared_data
        sr = sd.scan_results_dir
        logs = sd.logsdir

        def csvf(name):
            return os.path.join(sr, name)

        def logf(name):
            return os.path.join(logs, name)

        return {
            "wifi": [
                ("aps", "Access points (CSV)", csvf("wifi_aps.csv")),
                ("clients", "Clients (CSV)", csvf("wifi_clients.csv")),
                ("log", "wifi_scan log", logf("wifi_scan.py.log")),
                ("monitor", "monitor_mode log", logf("monitor_mode.py.log")),
                ("offline", "offline_mode log", logf("offline_mode.py.log")),
            ],
            "ble": [
                ("devices", "BLE devices (CSV)", csvf("ble_devices.csv")),
                ("log", "ble_scan log", logf("ble_scan.py.log")),
            ],
            "web": [
                ("fingerprints", "HTTP fingerprints (CSV)", csvf("http_fingerprints.csv")),
                ("findings", "Template findings (CSV)", csvf("web_template_findings.csv")),
                ("fp_log", "http_fingerprint log", logf("http_fingerprint.py.log")),
                ("tpl_log", "web_template_scan log", logf("web_template_scan.py.log")),
            ],
            "snmp": [
                ("enum", "SNMP enumeration (CSV)", csvf("snmp_enum.csv")),
                ("log", "snmp_enum log", logf("snmp_enum.py.log")),
            ],
            "scan": [
                ("netkb", "netkb (CSV)", sd.netkbfile),
                ("livestatus", "Live status (CSV)", sd.livestatusfile),
                ("benchmark", "Scan engine benchmark (CSV)", os.path.join(sd.datadir,
                                                                          "scan_engine_benchmark.csv")),
                ("log", "scanning log", logf("scanning.py.log")),
                ("orch_log", "orchestrator log", logf("orchestrator.py.log")),
            ],
            "telegram": [
                ("log", "telegram_client log", logf("telegram_client.py.log")),
                ("report_log", "telegram_report log", logf("telegram_report.py.log")),
            ],
        }

    @staticmethod
    def _file_meta(path):
        try:
            st = os.stat(path)
        except OSError:
            return {"exists": False, "size": 0, "modified": None, "lines": 0}
        lines = 0
        try:
            with open(path, "rb") as f:
                lines = sum(1 for _ in f)
        except OSError:
            pass
        return {
            "exists": True,
            "size": st.st_size,
            "modified": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(),
            # CSVs carry a header row; a "0 rows" file and a missing file are different states and
            # the panel says which.
            "lines": max(0, lines - 1) if path.endswith(".csv") else lines,
        }

    def serve_module_files(self, group):
        entries = self._file_groups().get(group)
        if entries is None:
            return _err(f"unknown file group {group!r}", status_code=404)
        return JSONResponse({"group": group, "files": [
            dict(key=key, label=label, name=os.path.basename(path), **self._file_meta(path))
            for key, label, path in entries
        ]})

    def serve_module_file(self, group, key, download=False, tail=400):
        entry = next((e for e in self._file_groups().get(group, []) if e[0] == key), None)
        if not entry:
            return _err("unknown file", status_code=404)
        path = entry[2]
        if not os.path.isfile(path):
            return _err("file does not exist yet", status_code=404)
        if download:
            return FileResponse(path, filename=os.path.basename(path))
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except OSError as e:
            return _err(e)
        # Tail, not whole file: orchestrator.py.log has been 800 KB before, and the viewer is a
        # panel on a page, not a log tool.
        truncated = len(lines) > tail
        return JSONResponse({
            "name": os.path.basename(path),
            "truncated": truncated,
            "content": "".join(lines[-tail:]),
        })

    def serve_netkb_data_json(self):
        try:
            netkb_file = self.shared_data.netkbfile
            with open(netkb_file, 'r', encoding='utf-8') as file:
                reader = csv.DictReader(file)
                data = [row for row in reader if row['Alive'] == '1']

            # Only offer actions the manual-attack handler can actually run per host: the
            # port-based connectors plus the special-cased NmapVulnScanner. Excludes NetworkScanner,
            # IDLE, and the standalone log actions, which otherwise 500'd with
            # "Action class <name> not found" when picked from the dropdown.
            self.load_actions()
            attackable = {a.action_name for a in self.actions if getattr(a, "port", None) not in (0, None)}
            attackable.add("NmapVulnScanner")
            actions = [a for a in reader.fieldnames[5:] if a in attackable]  # fields after 'Ports'
            response_data = {
                'ips': [row['IPs'] for row in data],
                'ports': {row['IPs']: row['Ports'].split(';') for row in data},
                'actions': actions
            }
            return JSONResponse(response_data)
        except Exception as e:
            return _err(e)

    def execute_manual_attack(self, params):
        try:
            ip = params['ip']
            port = params['port']
            action_class = params['action']

            self.logger.info(f"Received request to execute {action_class} on {ip}:{port}")

            # Charger les actions si ce n'est pas déjà fait
            self.load_actions()

            # Load current netKB data (both branches below need the target host's row).
            current_data = self.shared_data.read_data()
            row = next((r for r in current_data if r["IPs"] == ip), None)
            if row is None:
                raise Exception(f"No data found for IP: {ip}")

            action_key = action_class
            self.logger.info(f"Executing {action_key} on {ip}:{port}")

            # NmapVulnScanner is loaded separately (not into self.actions) and its execute()
            # signature is (ip, row, status_key) — not the connectors' (ip, port, row, action_key).
            # Handle it explicitly so a manual vuln scan works instead of "action not found".
            if action_class == "NmapVulnScanner":
                vuln_scanner = getattr(self, "nmap_vuln_scanner", None)
                if vuln_scanner is None:
                    raise Exception("NmapVulnScanner is not loaded")
                result = vuln_scanner.execute(ip, row, action_key)
            else:
                action_instance = next((action for action in self.actions if action.action_name == action_class), None)
                if action_instance is None:
                    raise Exception(f"Action class {action_class} not found")
                result = action_instance.execute(ip, port, row, action_key)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            if result == 'success':
                row[action_key] = f'success_{timestamp}'
                self.logger.info(f"Action {action_key} executed successfully on {ip}:{port}")
            else:
                row[action_key] = f'failed_{timestamp}'
                self.logger.error(f"Action {action_key} failed on {ip}:{port}")
            self.shared_data.write_data(current_data)

            return _ok(message="Manual attack executed")
        except Exception as e:
            self.logger.error(f"Error executing manual attack: {e}")
            return _err(e)

    def serve_logs(self):
        try:
            log_file_path = self.shared_data.webconsolelog
            if not os.path.exists(log_file_path):
                subprocess.Popen(f"sudo tail -f /home/bjorn/Bjorn/data/logs/* > {log_file_path}", shell=True)

            with open(log_file_path, 'r') as log_file:
                log_lines = log_file.readlines()

            max_lines = 2000
            if len(log_lines) > max_lines:
                log_lines = log_lines[-max_lines:]
                with open(log_file_path, 'w') as log_file:
                    log_file.writelines(log_lines)

            log_data = ''.join(log_lines)
            return PlainTextResponse(log_data)
        except BrokenPipeError:
            # Ignore broken pipe errors
            return PlainTextResponse("")
        except Exception as e:
            return _err(e)

    def start_orchestrator(self):
        try:
            bjorn_instance = self.shared_data.bjorn_instance
            bjorn_instance.start_orchestrator()
            return _ok(message="Orchestrator starting...")
        except Exception as e:
            return _err(e)

    def stop_orchestrator(self):
        try:
            bjorn_instance = self.shared_data.bjorn_instance
            bjorn_instance.stop_orchestrator()
            self.shared_data.orchestrator_should_exit = True
            return _ok(message="Orchestrator stopping...")
        except Exception as e:
            return _err(e)

    def backup(self):
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_filename = f"backup_{timestamp}.zip"
            backup_path = os.path.join(self.shared_data.backupdir, backup_filename)

            with zipfile.ZipFile(backup_path, 'w') as backup_zip:
                for folder in [self.shared_data.configdir, self.shared_data.datadir, self.shared_data.actions_dir, self.shared_data.resourcesdir]:
                    for root, dirs, files in os.walk(folder):
                        for file in files:
                            file_path = os.path.join(root, file)
                            backup_zip.write(file_path, os.path.relpath(file_path, self.shared_data.currentdir))

            return _ok({"url": f"/download_backup?filename={backup_filename}", "filename": backup_filename})
        except Exception as e:
            return _err(e)

    async def restore(self, file):
        """`file` is a FastAPI/Starlette UploadFile (multipart/form-data field name "file").

        Replaces the old manual `cgi.FieldStorage` parsing — `cgi` is deprecated (PEP 594) and
        gone entirely in Python 3.13, so this also removes a landmine for the "possible OS
        upgrade" you mentioned wanting to stay ahead of.
        """
        try:
            if not file or not file.filename:
                return JSONResponse({"status": "error", "message": "No selected file"}, status_code=400)

            backup_path = os.path.join(self.shared_data.upload_dir, file.filename)
            contents = await file.read()
            with open(backup_path, 'wb') as output_file:
                output_file.write(contents)

            with zipfile.ZipFile(backup_path, 'r') as backup_zip:
                backup_zip.extractall(self.shared_data.currentdir)

            return _ok(message="Restore completed successfully")
        except Exception as e:
            return _err(e)

    def download_backup(self, filename):
        backup_path = os.path.join(self.shared_data.backupdir, filename)
        if os.path.isfile(backup_path):
            return FileResponse(
                backup_path,
                media_type="application/zip",
                filename=os.path.basename(backup_path),
            )
        return Response(status_code=404)

    def serve_credentials_data(self):
        try:
            directory = self.shared_data.crackedpwddir
            html_content = self.generate_html_for_csv_files(directory)
            return HTMLResponse(html_content)
        except Exception as e:
            return _err(e)

    def generate_html_for_csv_files(self, directory):
        html = '<div class="credentials-container">\n'
        for filename in os.listdir(directory):
            if filename.endswith('.csv'):
                filepath = os.path.join(directory, filename)
                html += f'<h2>{filename}</h2>\n'
                html += '<table class="styled-table">\n<thead>\n<tr>\n'
                with open(filepath, 'r') as file:
                    reader = csv.reader(file)
                    headers = next(reader)
                    for header in headers:
                        html += f'<th>{header}</th>\n'
                    html += '</tr>\n</thead>\n<tbody>\n'
                    for row in reader:
                        html += '<tr>\n'
                        for cell in row:
                            html += f'<td>{cell}</td>\n'
                        html += '</tr>\n'
                html += '</tbody>\n</table>\n'
        html += '</div>\n'
        return html

    def list_files(self, directory):
        files = []
        for entry in os.scandir(directory):
            if entry.is_dir():
                files.append({
                    "name": entry.name,
                    "is_directory": True,
                    "children": self.list_files(entry.path)
                })
            else:
                files.append({
                    "name": entry.name,
                    "is_directory": False,
                    "path": entry.path
                })
        return files

    def serve_current_config(self):
        with open(self.shared_data.shared_config_json, 'r') as f:
            config = json.load(f)
        return JSONResponse(config)

    def restore_default_config(self):
        self.shared_data.config = self.shared_data.default_config.copy()
        self.shared_data.save_config()
        return JSONResponse(self.shared_data.config)

    def serve_image(self):
        image_path = os.path.join(self.shared_data.webdir, 'screen.png')
        try:
            return FileResponse(
                image_path,
                media_type="image/png",
                headers={"Cache-Control": "max-age=0, must-revalidate"},
            )
        except FileNotFoundError:
            return Response(status_code=404)
        except BrokenPipeError:
            return Response(status_code=200)
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}")
            return Response(status_code=500)

    def serve_favicon(self):
        # BUG FIX: the previous version built this path with
        #   os.path.join(self.shared_data.webdir, '/images/favicon.ico')
        # A second argument starting with "/" makes os.path.join() DISCARD the first argument
        # entirely (documented Python behavior), so this was resolving to the filesystem-root
        # path "/images/favicon.ico" instead of "<webdir>/images/favicon.ico" — the favicon
        # route has always 404'd. Fixed by dropping the leading slash.
        favicon_path = os.path.join(self.shared_data.webdir, 'images', 'favicon.ico')
        try:
            return FileResponse(favicon_path, media_type="image/x-icon")
        except FileNotFoundError:
            self.logger.error(f"Favicon not found at {favicon_path}")
            return Response(status_code=404)

    def serve_manifest(self):
        manifest_path = os.path.join(self.shared_data.webdir, 'manifest.json')
        try:
            return FileResponse(manifest_path, media_type="application/json")
        except FileNotFoundError:
            return Response(status_code=404)

    def serve_apple_touch_icon(self):
        icon_path = os.path.join(self.shared_data.webdir, 'icons/apple-touch-icon.png')
        try:
            return FileResponse(icon_path, media_type="image/png")
        except FileNotFoundError:
            return Response(status_code=404)

    def scan_wifi(self):
        try:
            # nmcli instead of the deprecated `iwlist wlan0 scan` (nmcli is already a dependency,
            # used by connect_wifi). `-t -f SSID dev wifi` lists one SSID per line (L4).
            result = subprocess.Popen(['sudo', 'nmcli', '-t', '-f', 'SSID', 'dev', 'wifi'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = result.communicate()
            if result.returncode != 0:
                raise Exception(stderr)
            networks = list(dict.fromkeys(line.strip() for line in stdout.splitlines() if line.strip()))
            self.logger.info(f"Found {len(networks)} networks")
            current_ssid = subprocess.Popen(['iwgetid', '-r'], stdout=subprocess.PIPE, text=True)
            ssid_out, ssid_err = current_ssid.communicate()
            if current_ssid.returncode != 0:
                raise Exception(ssid_err)
            current_ssid = ssid_out.strip()
            self.logger.info(f"Current SSID: {current_ssid}")
            return JSONResponse({"networks": networks, "current_ssid": current_ssid})
        except Exception as e:
            self.logger.error(f"Error scanning Wi-Fi networks: {e}")
            return JSONResponse({"error": str(e)}, status_code=500)

    def _static_ipv4(self, params):
        """Validate optional static-IP params from the WebUI.

        Returns a dict {address, gateway, dns:[...]} using canonical strings parsed by the
        stdlib ipaddress module, or None for DHCP. Raises ValueError on malformed input so the
        caller rejects it *before* anything is written to the NetworkManager keyfile — the
        parsed/reconstructed values can't inject extra config lines.
        """
        address = (params.get('ip_address') or "").strip()
        if not address:
            return None
        if '/' not in address:
            # A bare IP would become /32 and silently break LAN routing — require the prefix.
            raise ValueError("address must include a prefix, e.g. 192.168.1.50/24")
        iface = ipaddress.ip_interface(address)  # e.g. 192.168.1.50/24
        gateway = (params.get('gateway') or "").strip()
        if gateway:
            gateway = str(ipaddress.ip_address(gateway))
        dns = []
        for d in (params.get('dns') or "").replace(',', ' ').split():
            dns.append(str(ipaddress.ip_address(d)))
        return {"address": str(iface), "gateway": gateway, "dns": dns}

    def update_nmconnection(self, ssid, password, ipv4=None):
        if ipv4:
            a1 = f"{ipv4['address']},{ipv4['gateway']}" if ipv4['gateway'] else ipv4['address']
            ipv4_block = f"method=manual\naddress1={a1}\n"
            if ipv4['dns']:
                ipv4_block += "dns=" + ";".join(ipv4['dns']) + ";\n"
        else:
            ipv4_block = "method=auto\n"
        config_path = '/etc/NetworkManager/system-connections/preconfigured.nmconnection'
        with open(config_path, 'w') as f:
            f.write(f"""
[connection]
id=preconfigured
uuid={uuid.uuid4()}
type=wifi
autoconnect=true

[wifi]
ssid={ssid}
mode=infrastructure

[wifi-security]
key-mgmt=wpa-psk
psk={password}

[ipv4]
{ipv4_block}
[ipv6]
method=auto
""")
        subprocess.Popen(['sudo', 'chmod', '600', config_path]).communicate()
        subprocess.Popen(['sudo', 'nmcli', 'connection', 'reload']).communicate()

    def connect_wifi(self, params):
        try:
            ssid = params['ssid']
            password = params['password']
            try:
                ipv4 = self._static_ipv4(params)
            except ValueError as ve:
                return _err(f"Invalid static IP: {ve}")

            self.update_nmconnection(ssid, password, ipv4)
            command = 'sudo nmcli connection up "preconfigured"'
            connect_result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = connect_result.communicate()
            if connect_result.returncode != 0:
                raise Exception(stderr)

            self.shared_data.wifichanged = True
            return _ok(message="Connected to " + ssid)
        except Exception as e:
            return _err(e)

    def disconnect_and_clear_wifi(self):
        try:
            command_disconnect = 'sudo nmcli connection down "preconfigured"'
            disconnect_result = subprocess.Popen(command_disconnect, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = disconnect_result.communicate()
            if disconnect_result.returncode != 0:
                raise Exception(stderr)

            config_path = '/etc/NetworkManager/system-connections/preconfigured.nmconnection'
            with open(config_path, 'w') as f:
                f.write("")
            subprocess.Popen(['sudo', 'chmod', '600', config_path]).communicate()
            subprocess.Popen(['sudo', 'nmcli', 'connection', 'reload']).communicate()

            self.shared_data.wifichanged = False
            return _ok(message="Disconnected from Wi-Fi and cleared preconfigured settings")
        except Exception as e:
            return _err(e)

    def clear_files(self):
        try:
            command = """
            sudo rm -rf config/*.json && sudo rm -rf data/*.csv && sudo rm -rf data/*.log  && sudo rm -rf backup/backups/* && sudo rm -rf backup/uploads/* && sudo rm -rf data/output/data_stolen/* && sudo rm -rf data/output/crackedpwd/* && sudo rm -rf config/* && sudo rm -rf data/output/scan_results/* && sudo rm -rf __pycache__ && sudo rm -rf config/__pycache__ && sudo rm -rf data/__pycache__  && sudo rm -rf actions/__pycache__  && sudo rm -rf resources/__pycache__ && sudo rm -rf web/__pycache__ && sudo rm -rf *.log && sudo rm -rf resources/waveshare_epd/__pycache__ && sudo rm -rf data/logs/*  && sudo rm -rf data/output/vulnerabilities/* && sudo rm -rf data/logs/*
            """
            result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = result.communicate()
            if result.returncode == 0:
                return _ok(message="Files cleared successfully")
            return _err(stderr)
        except Exception as e:
            return _err(e)

    def clear_files_light(self):
        try:
            command = """
            sudo rm -rf data/*.log && sudo rm -rf data/output/data_stolen/* && sudo rm -rf data/output/crackedpwd/*  && sudo rm -rf data/output/scan_results/* && sudo rm -rf __pycache__ && sudo rm -rf config/__pycache__ && sudo rm -rf data/__pycache__  && sudo rm -rf actions/__pycache__  && sudo rm -rf resources/__pycache__ && sudo rm -rf web/__pycache__ && sudo rm -rf *.log && sudo rm -rf resources/waveshare_epd/__pycache__ && sudo rm -rf data/logs/*  && sudo rm -rf data/output/vulnerabilities/* && sudo rm -rf data/logs/*
            """
            result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = result.communicate()
            if result.returncode == 0:
                return _ok(message="Files cleared successfully")
            return _err(stderr)
        except Exception as e:
            return _err(e)

    def initialize_csv(self):
        try:
            self.shared_data.generate_actions_json()
            self.shared_data.initialize_csv()
            self.shared_data.create_livestatusfile()
            return _ok(message="CSV files initialized successfully")
        except Exception as e:
            return _err(e)

    def reboot_system(self):
        try:
            subprocess.Popen("sudo reboot", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            return _ok(message="System is rebooting")
        except subprocess.CalledProcessError as e:
            return _err(e)

    def shutdown_system(self):
        try:
            subprocess.Popen("sudo shutdown now", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            return _ok(message="System is shutting down")
        except subprocess.CalledProcessError as e:
            return _err(e)

    def restart_bjorn_service(self):
        try:
            subprocess.Popen("sudo systemctl restart bjorn.service", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            return _ok(message="Bjorn service restarted successfully")
        except subprocess.CalledProcessError as e:
            return _err(e)

    def generate_html_table(self, file_path):
        table_html = '<table class="styled-table"><thead><tr>'
        with open(file_path, 'r') as file:
            reader = csv.reader(file)
            headers = next(reader)
            for header in headers:
                table_html += f'<th>{header}</th>'
            table_html += '</tr></thead><tbody>'
            for row in reader:
                table_html += '<tr>'
                for cell in row:
                    cell_class = "green" if cell.strip() else "red"
                    table_html += f'<td class="{cell_class}">{cell}</td>'
                table_html += '</tr>'
            table_html += '</tbody></table>'
        return table_html

    def generate_html_table_netkb(self, file_path):
        table_html = '<table class="styled-table"><thead><tr>'
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                reader = csv.reader(file)
                headers = next(reader)
                for header in headers:
                    table_html += f'<th>{header}</th>'
                table_html += '</tr></thead><tbody>'
                for row in reader:
                    row_class = "blue-row" if '0' in row[3] else ""
                    table_html += f'<tr class="{row_class}">'
                    for cell in row:
                        cell_class = ""
                        if "success" in cell:
                            cell_class = "green bold"
                        elif "failed" in cell:
                            cell_class = "red bold"
                        elif cell.strip() == "":
                            cell_class = "grey"
                        table_html += f'<td class="{cell_class}">{cell}</td>'
                    table_html += '</tr>'
                table_html += '</tbody></table>'
        except Exception as e:
            self.logger.error(f"Error in generate_html_table_netkb: {e}")
        return table_html

    def serve_netkb_data(self):
        try:
            latest_file = self.shared_data.netkbfile
            table_html = self.generate_html_table_netkb(latest_file)
            return HTMLResponse(table_html)
        except Exception as e:
            return _err(e)

    # Config keys whose *values* must never reach a log file. Substring match on the key name, so a
    # future `*_token` / `*_password` key is covered without anyone remembering to add it here.
    _SECRET_KEY_PARTS = ("token", "password", "api_key", "secret", "passwd")

    @classmethod
    def _redact_params(cls, params):
        """Copy of `params` with secret values replaced. Pure/testable.

        save_configuration used to log the whole dict at INFO, so every save from the Telegram page
        wrote the bot token and SMTP password into data/logs — which the diagnostic script then
        tails into a report meant for sharing. Logging the *keys* is genuinely useful for debugging
        a save; logging their values never was."""
        return {k: ("***" if any(p in k.lower() for p in cls._SECRET_KEY_PARTS) and v else v)
                for k, v in params.items()}

    def save_configuration(self, params):
        try:
            fichier = self.shared_data.shared_config_json
            self.logger.info(f"Received params: {self._redact_params(params)}")

            with open(fichier, 'r') as f:
                current_config = json.load(f)

            for key, value in params.items():
                if isinstance(value, bool):
                    current_config[key] = value
                elif isinstance(value, str) and value.lower() in ['true', 'false']:
                    current_config[key] = value.lower() == 'true'
                elif isinstance(value, (int, float)):
                    current_config[key] = value
                elif isinstance(value, list):
                    # Lets boot any values in a list that are just empty strings
                    for val in value[:]:
                        if val == "":
                            value.remove(val)
                    current_config[key] = value
                elif isinstance(value, str):
                    if value.replace('.', '', 1).isdigit():
                        current_config[key] = float(value) if '.' in value else int(value)
                    else:
                        current_config[key] = value
                else:
                    current_config[key] = value

            with open(fichier, 'w') as f:
                json.dump(current_config, f, indent=4)
            self.logger.info("Configuration saved to file")

            self.shared_data.load_config()
            self.logger.info("Configuration reloaded (web)")

            return _ok(message="Configuration saved")
        except Exception as e:
            self.logger.error(f"Error saving configuration: {e}")
            return _err(e)

    def list_files_endpoint(self):
        try:
            files = self.list_files(self.shared_data.datastolendir)
            return JSONResponse(files)
        except Exception as e:
            return _err(e)

    def download_file(self, path):
        try:
            file_path = os.path.join(self.shared_data.datastolendir, path)
            if os.path.isfile(file_path):
                return FileResponse(file_path, filename=os.path.basename(file_path))
            return Response(status_code=404)
        except Exception as e:
            return _err(e)

    def serve_network_data(self):
        try:
            latest_file = max(
                [os.path.join(self.shared_data.scan_results_dir, f) for f in os.listdir(self.shared_data.scan_results_dir) if f.startswith('result_')],
                key=os.path.getctime
            )
            table_html = self.generate_html_table(latest_file)
            return HTMLResponse(table_html)
        except Exception as e:
            return _err(e)
