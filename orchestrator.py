# orchestrator.py
# Description:
# This file, orchestrator.py, is the heuristic Bjorn brain, and it is responsible for coordinating and executing various network scanning and offensive security actions 
# It manages the loading and execution of actions, handles retries for failed and successful actions, 
# and updates the status of the orchestrator.
#
# Key functionalities include:
# - Initializing and loading actions from a configuration file, including network and vulnerability scanners.
# - Managing the execution of actions on network targets, checking for open ports and handling retries based on success or failure.
# - Coordinating the execution of parent and child actions, ensuring actions are executed in a logical order.
# - Running the orchestrator cycle to continuously check for and execute actions on available network targets.
# - Handling and updating the status of the orchestrator, including scanning for new targets and performing vulnerability scans.
# - Implementing threading to manage concurrent execution of actions with a semaphore to limit active threads.
# - Logging events and errors to ensure maintainability and ease of debugging.
# - Handling graceful degradation by managing retries and idle states when no new targets are found.
#
# Work selection lives in action_planner.py: instead of walking the action list in load order and
# breaking on the first success, every eligible (host, action) pair and standalone action is scored
# each cycle and the top picks run. See docs/SMART_ORCHESTRATOR.md.

import json
import importlib
import os
import time
import logging
import threading
from datetime import datetime, timedelta
from actions.nmap_vuln_scanner import NmapVulnScanner
from init_shared import shared_data
from logger import Logger
from retry_policy import retry_wait_remaining
from action_planner import Planner, load_service_hints, load_vuln_ips, plan_idle_seconds
import offline_mode

logger = Logger(name="orchestrator.py", level=logging.DEBUG)

class Orchestrator:
    def __init__(self):
        """Initialise the orchestrator"""
        self.shared_data = shared_data
        self.actions = []  # List of actions to be executed
        self.standalone_actions = []  # List of standalone actions to be executed
        self.failed_scans_count = 0  # Count the number of failed scans
        self.network_scanner = None
        self.last_vuln_scan_time = datetime.min  # Set the last vulnerability scan time to the minimum datetime value
        self.run_id = datetime.now().strftime("%Y%m%d_%H%M%S")  # process-lifetime id for the run report (see docs/PRD.md §4a)
        self.action_stats = {}  # action_name -> {"success": int, "failed": int, "errors": [str, ...]}
        self.load_actions()  # Load all actions from the actions file
        actions_loaded = [action.__class__.__name__ for action in self.actions + self.standalone_actions]  # Get the names of the loaded actions
        logger.info(f"Actions loaded: {actions_loaded}")
        self.semaphore = threading.Semaphore(10)  # Limit the number of active threads to 10
        self.planner = Planner()  # knobs re-read from config each cycle via sync_config()
        self.offline_since = None  # set on the cycle the uplink disappears, cleared when it returns
        self.last_autojoin_detail = None  # dedupes the once-a-minute auto-join outcome in the log

    def load_actions(self):
        """Load all actions from the actions file"""
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

            # An action the orchestrator cannot call has no business in the work queue.
            # actions/IDLE.py is a stub with no execute(): it was registered anyway, scored by the
            # planner as "never tried" on every host, and then raised AttributeError every cycle —
            # 7 errors and 7 failed netkb marks in a 10-minute run, for something that is not a
            # real action. Checked at load, so any future stub is simply never registered rather
            # than failing once per host per cycle.
            if not callable(getattr(action_instance, "execute", None)):
                logger.info(f"Skipping {b_class}: no execute() — not a runnable action.")
                return

            action_instance.action_name = b_class
            action_instance.port = action.get("b_port")
            action_instance.b_parent_action = action.get("b_parent")
            # Module-level opt-in flag (part of the b_* contract): actions that call out to the
            # internet are skipped while offline instead of failing once per cycle.
            action_instance.needs_internet = getattr(module, "b_needs_internet", False)
            # None means portless, not "some port". `None == 0` is False, so a b_port of None filed
            # a portless action under the *host* actions, to be called with an ip and a port it
            # never had. The manual-attack dropdown already works around this downstream
            # (`port not in (0, None)`, utils.py); this is the same rule applied at the source.
            if action_instance.port in (0, None):
                self.standalone_actions.append(action_instance)
            else:
                self.actions.append(action_instance)
        except AttributeError as e:
            logger.error(f"Module {module_name} is missing required attributes: {e}")

    def _record_result(self, action_name, success, error=None):
        """Track per-action outcome counts for the run report. Counts and exception
        messages only — never raw scan results, credentials, or loot (see docs/PRD.md §4a DEV-1)."""
        stats = self.action_stats.setdefault(action_name, {"success": 0, "failed": 0, "errors": []})
        stats["success" if success else "failed"] += 1
        if error and len(stats["errors"]) < 5:
            stats["errors"].append(str(error)[:200])

    def write_run_report(self):
        """Write a redacted run-summary snapshot for the offline improvement process (docs/PRD.md §4a)."""
        try:
            version = open(os.path.join(self.shared_data.currentdir, "version.txt")).read().strip()
        except OSError:
            version = "unknown"
        report_dir = os.path.join(self.shared_data.output_dir, "run_reports")
        os.makedirs(report_dir, exist_ok=True)
        report = {
            "run_id": self.run_id,
            "written_at": datetime.now().isoformat(),
            "version": version,
            "actions": self.action_stats,
        }
        with open(os.path.join(report_dir, f"{self.run_id}.json"), "w") as f:
            json.dump(report, f, indent=2)

    def process_alive_ips(self, current_data, idle_boost=0):
        """Score every eligible unit of work and run this cycle's top picks.

        Replaces a walk over `self.actions` in load order that `break`ed on the first success per
        host, which meant: the earliest-loaded action always went first regardless of how promising
        the target was, and a child action only ran if it happened to follow its parent in the same
        pass. Ranking lives in action_planner.py; this method only executes.

        Note the one behaviour traded away: a parent unlocked *during* this cycle no longer has its
        child run immediately after it. The child becomes eligible next cycle, where "parent ok"
        (+55) puts it at the top — one cycle of latency, and cycles with work don't sleep."""
        self.planner.sync_config(self.shared_data)
        candidates = self.planner.collect(
            self.actions, self.standalone_actions, current_data,
            idle_boost=idle_boost,
            vuln_ips=load_vuln_ips(self.shared_data.vuln_summary_file),
            service_hints=load_service_hints(
                os.path.join(self.shared_data.scan_results_dir, "http_fingerprints.csv")),
        )
        work = self.planner.select(candidates)
        if not work:
            return False

        any_action_executed = False
        for cand in work:
            with self.semaphore:
                self.shared_data.bjornorch_status = cand.action_name
                self.shared_data.bjornstatustext2 = cand.reason[:40]
                logger.info(f"Planner chose: {cand.reason} (score={cand.score})")
                if cand.kind == "standalone":
                    if self.execute_standalone_action(cand.action, current_data):
                        any_action_executed = True
                elif cand.row is not None:
                    ports = str(cand.row.get("Ports", "") or "").split(';')
                    if self.execute_action(cand.action, cand.ip, ports, cand.row,
                                           cand.action_name, current_data):
                        any_action_executed = True

        return any_action_executed


    def execute_action(self, action, ip, ports, row, action_key, current_data):
        """Execute an action on a target.

        The planner pre-checks all of these gates, but they stay here: this is also the manual-attack
        entry point, and a candidate ranked at the top of the cycle can have been invalidated by an
        earlier action in the same cycle writing to the same row."""
        if hasattr(action, 'port') and str(action.port) not in ("0", "None"):
            if str(action.port) not in ports:
                return False

        # Check parent action status
        if action.b_parent_action:
            parent_status = row.get(action.b_parent_action, "")
            if 'success' not in parent_status:
                return False  # Skip child action if parent action has not succeeded

        # Skip if the action succeeded recently and is still within its retry-delay window.
        status = row.get(action_key, "") or ""
        if 'success' in status:
            if not self.shared_data.retry_success_actions:
                return False
            remaining = retry_wait_remaining(status, self.shared_data.success_retry_delay)
            if remaining > 0:
                logger.warning(f"Skipping action {action.action_name} for {ip}:{action.port} due to success retry delay, retry possible in: {timedelta(seconds=remaining)}")
                return False

        # Skip if the action failed recently and is still within its retry-delay window.
        if 'failed' in status:
            remaining = retry_wait_remaining(status, self.shared_data.failed_retry_delay)
            if remaining > 0:
                logger.warning(f"Skipping action {action.action_name} for {ip}:{action.port} due to failed retry delay, retry possible in: {timedelta(seconds=remaining)}")
                return False

        try:
            logger.info(f"Executing action {action.action_name} for {ip}:{action.port}")
            # The planner has already put its reason on the display; only fall back to the bare IP
            # when nothing set one (e.g. a manual attack from the web UI).
            if not getattr(self.shared_data, "bjornstatustext2", ""):
                self.shared_data.bjornstatustext2 = ip
            result = action.execute(ip, str(action.port), row, action_key)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            if result == 'success':
                row[action_key] = f'success_{timestamp}'
            else:
                row[action_key] = f'failed_{timestamp}'
            self._record_result(action.action_name, result == 'success')
            return result == 'success'
        except Exception as e:
            logger.error(f"Action {action.action_name} failed: {e}")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            row[action_key] = f'failed_{timestamp}'
            self._record_result(action.action_name, False, error=e)
            return False

    def run_standalone_actions(self, current_data, offline=False):
        """Give every standalone action a turn this idle window. Returns the names that ran.

        These are recurring recon/reporting jobs that police their own cadence
        (ble_scan_interval, wpasec_interval, telegram_min_interval; SNMPEnum tracks probed IPs).
        The old loop `break`ed on the first action returning success — and a *disabled or
        throttled* action also returns 'success' — so a single switched-off action consumed the
        whole cycle and starved every action registered after it."""
        ran = []
        for action in self.standalone_actions:
            # Offline, a reporting action has nowhere to send and would fail once per cycle — at a
            # 60s offline cadence that is the log flood the idle-loop fix already had to clean up
            # once. Skipping is not throttling: the delta/interval logic is untouched, so the first
            # cycle back online still sends.
            if offline and getattr(action, "needs_internet", False):
                continue
            with self.semaphore:
                self.execute_standalone_action(action, current_data)
                ran.append(action.action_name)
        return ran

    def run_offline_cycle(self):
        """Own this cycle when there is no uplink. Returns True if it did.

        With no default route the IP pipeline has nothing to find — netkb is empty and every sweep
        is a Pi Zero burning cycles on a network it isn't on. The wireless recon, by contrast, works
        exactly as well offline: that is the whole point of carrying the thing around. So: survey
        first, then try to get back on a network.

        Order is load-bearing. A capture holds the radio in monitor mode, and nmcli cannot associate
        such an interface — it fails quietly, which would look like "auto-join doesn't work" rather
        than "auto-join ran too early". WiFiScan releases in a finally-block, so by the time
        reconnect() runs the radio is managed again; reconnect() re-checks anyway."""
        if not getattr(self.shared_data, "offline_mode_enabled", True):
            return False
        if offline_mode.is_online():
            if self.offline_since:
                logger.info("Uplink is back; resuming normal scanning.")
                self.offline_since = None
            return False

        if self.offline_since is None:
            self.offline_since = datetime.now()
            logger.info("No uplink — IP scanning paused, running wireless recon instead.")
        self.shared_data.bjornorch_status = "IDLE"
        self.shared_data.bjornstatustext2 = "offline · surveying"

        current_data = self.shared_data.read_data()
        self.run_standalone_actions(current_data, offline=True)  # WiFiScan/BLEScan self-throttle
        self.shared_data.write_data(current_data)

        if getattr(self.shared_data, "wifi_autojoin", True):
            self.shared_data.bjornstatustext2 = "offline · reconnecting"
            ok, detail = offline_mode.reconnect_best(self.shared_data)
            if ok:
                logger.success(f"Back online: {detail}")
                self.offline_since = None
                self.last_autojoin_detail = None
                return True
            # Offline cycles repeat every 60s and this message is usually identical every time
            # ("nothing joinable in range"). Log a change, not a heartbeat — the per-second idle
            # notice that wrote 800 KB per window is the cautionary tale here.
            if detail != self.last_autojoin_detail:
                logger.info(f"Auto-join: {detail}")
                self.last_autojoin_detail = detail
            else:
                logger.debug(f"Auto-join: {detail}")

        wait = max(15, int(getattr(self.shared_data, "offline_cycle_interval", 60)))
        self.shared_data.bjornstatustext2 = "offline · resting"
        deadline = datetime.now() + timedelta(seconds=wait)
        while datetime.now() < deadline and not self.shared_data.orchestrator_should_exit:
            time.sleep(1)
        return True

    def execute_standalone_action(self, action, current_data):
        """Execute a standalone action"""
        row = next((r for r in current_data if r["MAC Address"] == "STANDALONE"), None)
        if not row:
            row = {
                "MAC Address": "STANDALONE",
                "IPs": "STANDALONE",
                "Hostnames": "STANDALONE",
                "Ports": "0",
                "Alive": "0"
            }
            current_data.append(row)

        action_key = action.action_name
        if action_key not in row:
            row[action_key] = ""

        # NOTE: no success-retry gate here, unlike per-host actions. `retry_success_actions`
        # defaults to False, which for a *host* action correctly means "don't re-attack a box you
        # already cracked" — but applied to a standalone action it meant a single success marked it
        # done forever, so BLEScan/WpaSecImport/SNMPEnum/TelegramReport each ran exactly once per
        # netkb lifetime and their own interval keys never got a second turn to take effect.
        # Recurring jobs self-throttle; the orchestrator must not also latch them off.

        # Skip if the action failed recently and is still within its retry-delay window.
        if 'failed' in row.get(action_key, ""):
            remaining = retry_wait_remaining(row[action_key], self.shared_data.failed_retry_delay)
            if remaining > 0:
                logger.warning(f"Skipping standalone action {action.action_name} due to failed retry delay, retry possible in: {timedelta(seconds=remaining)}")
                return False

        try:
            logger.info(f"Executing standalone action {action.action_name}")
            result = action.execute()
            # 'skipped' = the action was disabled, throttled, or its tool isn't installed, so it did
            # no work. It must leave no trace: writing 'success' to netkb and counting it in the run
            # report made a switched-off action indistinguishable from a working one — a diagnostic
            # pull read "WiFiScan: success=4" for an action that had never completed a capture.
            if result == 'skipped':
                logger.debug(f"Standalone action {action.action_name} skipped (nothing to do)")
                return False
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            if result == 'success':
                row[action_key] = f'success_{timestamp}'
                logger.info(f"Standalone action {action.action_name} executed successfully")
            else:
                row[action_key] = f'failed_{timestamp}'
                logger.error(f"Standalone action {action.action_name} failed")
            self._record_result(action.action_name, result == 'success')
            return result == 'success'
        except Exception as e:
            logger.error(f"Standalone action {action.action_name} failed: {e}")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            row[action_key] = f'failed_{timestamp}'
            self._record_result(action.action_name, False, error=e)
            return False

    def run(self):
        """Run the orchestrator cycle to execute actions"""
        #Run the scanner a first time to get the initial data
        self.shared_data.bjornorch_status = "NetworkScanner"
        self.shared_data.bjornstatustext2 = "First scan..."
        self.network_scanner.scan()
        self.shared_data.bjornstatustext2 = ""
        while not self.shared_data.orchestrator_should_exit:
            if self.run_offline_cycle():
                continue
            current_data = self.shared_data.read_data()
            any_action_executed = False
            action_retry_pending = False
            # Consecutive fruitless scans raise the standalone score, so recon that needs no target
            # (BLE, Wi-Fi, SNMP, reporting) takes over as host work dries up.
            idle_boost = min(40, self.failed_scans_count * 12)
            any_action_executed = self.process_alive_ips(current_data, idle_boost=idle_boost)

            # P3: one netkb write per cycle here — execute_action no longer writes per action.
            self.shared_data.write_data(current_data)

            if not any_action_executed:
                self.shared_data.bjornorch_status = "IDLE"
                self.shared_data.bjornstatustext2 = "thinking..."
                self.write_run_report()
                logger.info("No available targets. Running network scan...")
                if self.network_scanner:
                    self.shared_data.bjornorch_status = "NetworkScanner"
                    self.network_scanner.scan()
                     # Relire les données mises à jour après le scan
                    current_data = self.shared_data.read_data()
                    any_action_executed = self.process_alive_ips(
                        current_data, idle_boost=min(50, idle_boost + 15))
                    if self.shared_data.scan_vuln_running:
                        current_time = datetime.now()
                        if current_time >= self.last_vuln_scan_time + timedelta(seconds=self.shared_data.scan_vuln_interval):
                            try:
                                logger.info("Starting vulnerability scans...")
                                for row in current_data:
                                    if row["Alive"] == '1':
                                        ip = row["IPs"]
                                        scan_status = row.get("NmapVulnScanner", "")

                                        # Skip a host whose vuln scan succeeded recently.
                                        if 'success' in scan_status:
                                            if not self.shared_data.retry_success_actions:
                                                logger.warning(f"Skipping vulnerability scan for {ip} because retry on success is disabled.")
                                                continue
                                            remaining = retry_wait_remaining(scan_status, self.shared_data.success_retry_delay)
                                            if remaining > 0:
                                                logger.warning(f"Skipping vulnerability scan for {ip} due to success retry delay, retry possible in: {timedelta(seconds=remaining)}")
                                                continue

                                        # Skip a host whose vuln scan failed recently.
                                        if 'failed' in scan_status:
                                            remaining = retry_wait_remaining(scan_status, self.shared_data.failed_retry_delay)
                                            if remaining > 0:
                                                logger.warning(f"Skipping vulnerability scan for {ip} due to failed retry delay, retry possible in: {timedelta(seconds=remaining)}")
                                                continue

                                        with self.semaphore:
                                            result = self.nmap_vuln_scanner.execute(ip, row, "NmapVulnScanner")
                                            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                                            if result == 'success':
                                                row["NmapVulnScanner"] = f'success_{timestamp}'
                                            else:
                                                row["NmapVulnScanner"] = f'failed_{timestamp}'
                                self.last_vuln_scan_time = current_time
                            except Exception as e:
                                logger.error(f"Error during vulnerability scan: {e}")


                else:
                    logger.warning("No network scanner available.")
                self.failed_scans_count += 1
                if self.failed_scans_count >= 1:
                    # Belt and braces: the planner already interleaves standalone actions during
                    # active cycles, but a fully idle net never reaches a cycle with work to
                    # interleave into. Every action still gets its own turn here — they self-
                    # throttle, so a second call in one cycle is a no-op for anything not due.
                    self.run_standalone_actions(current_data)
                    # P3: batch the idle-cycle netkb write — one write for the whole branch
                    # (post-scan action pass + vuln scan + standalone) instead of after every
                    # action. ponytail: mid-cycle results are lost on a crash, but the actions
                    # just re-run next cycle.
                    self.shared_data.write_data(current_data)
                    idle_start_time = datetime.now()
                    idle_seconds = self.shared_data.scan_interval
                    if getattr(self.shared_data, "adaptive_scan_interval", True):
                        # Back off while the net stays barren, but cut the wait short when the only
                        # thing blocking real work is a retry window that expires sooner.
                        idle_seconds = plan_idle_seconds(
                            self.shared_data.scan_interval, self.failed_scans_count,
                            self.planner.next_retry_wait)
                    idle_end_time = idle_start_time + timedelta(seconds=idle_seconds)
                    # Log the idle notice ONCE, not once per second: the old per-second
                    # logger.warning wrote ~180 lines per idle window to the rotating file log
                    # (7000+ lines / ~800KB), which is log spam and made the WebUI log viewer
                    # choke on the huge file. INFO, not WARNING — "no new targets" is normal.
                    logger.info(f"Scanner found no new targets; idling {idle_seconds}s until next scan.")
                    self.shared_data.bjornorch_status = "IDLE"
                    self.shared_data.bjornstatustext2 = "resting..."
                    while datetime.now() < idle_end_time:
                        if self.shared_data.orchestrator_should_exit:
                            break
                        time.sleep(1)
                    self.failed_scans_count = 0
                    continue
            else:
                self.failed_scans_count = 0
                action_retry_pending = True

            if action_retry_pending:
                self.failed_scans_count = 0

if __name__ == "__main__":
    orchestrator = Orchestrator()
    orchestrator.run()
