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
import os
import time
import logging
import threading
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from init_shared import shared_data
from logger import Logger
from retry_policy import retry_wait_remaining
from action_planner import Planner, load_service_hints, load_vuln_ips, plan_idle_seconds
import action_loader
import offline_mode
import bettercap_client
import bettercap_pwn
from action_outcome import OutcomeCode, normalize_outcome
from action_telemetry import ActionTelemetry

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
        # Legacy vestige kept as a soft upper bound on concurrent action bodies.
        # Real cross-host parallelism is the ThreadPoolExecutor in process_alive_ips;
        # the semaphore alone never provided it (the old loop held it serially).
        self.semaphore = threading.Semaphore(10)
        # One lock per action class so two hosts that both need SSHBruteforce cannot
        # interleave on the shared connector singleton (shared queue/results).
        self._action_locks = {}
        self._action_locks_guard = threading.Lock()
        # Aggregate history is small, local and flushed once per completed cycle to limit SD wear.
        self.action_telemetry = ActionTelemetry(
            os.path.join(self.shared_data.datadir, "action_telemetry.json"))
        self.planner = Planner(telemetry=self.action_telemetry)
        # Planner knobs are re-read from live config each cycle via sync_config().
        self.offline_since = None  # set on the cycle the uplink disappears, cleared when it returns
        self.last_autojoin_detail = None  # dedupes the once-a-minute auto-join outcome in the log
        self.last_hunt_detail = None      # same, for the hunter's refusal reason
        # #9: the vuln sweep runs off the cycle. The pool is long-lived (one per orchestrator, not
        # one per sweep) so submitting never waits; workers hand back (ip, result) on a queue and
        # the *main thread* stamps netkb from it. Workers touch no shared state, which is why this
        # needs no new lock — #7's single-writer discipline is untouched.
        self._vuln_pool = None            # created on first sweep; nmap is CPU-heavy, so 2 workers
        self._vuln_results = queue.Queue()
        self._vuln_inflight = set()       # IPs submitted and not yet drained; main-thread only

    def load_actions(self):
        """Build the action set. Shared with the web UI — see action_loader for why."""
        loaded = action_loader.load_actions(self.shared_data, logger)
        self.actions = loaded.actions
        self.standalone_actions = loaded.standalone
        self.network_scanner = loaded.network_scanner
        self.nmap_vuln_scanner = loaded.nmap_vuln_scanner

    def _record_result(self, action_name, success, error=None):
        """Track per-action outcome counts for the run report. Counts and exception
        messages only — never raw scan results, credentials, or loot (see docs/PRD.md §4a DEV-1)."""
        stats = self.action_stats.setdefault(action_name, {"success": 0, "failed": 0, "errors": []})
        stats["success" if success else "failed"] += 1
        if error and len(stats["errors"]) < 5:
            stats["errors"].append(str(error)[:200])

    def _record_execution(self, action_name, target, outcome, *, planner_score=None,
                          planner_reason=""):
        """Update the legacy run report and the richer persistent planner history."""
        error = outcome.reason if outcome.code is OutcomeCode.ERROR else None
        self._record_result(action_name, outcome.succeeded, error=error)
        self.action_telemetry.record(
            action_name,
            target,
            outcome,
            planner_score=planner_score,
            planner_reason=planner_reason,
        )

    def _flush_action_telemetry(self):
        """Persist planner history without making optional learning a boot/runtime dependency."""
        try:
            self.action_telemetry.flush()
        except Exception as exc:
            # A read-only/full SD card may disable learning, but must not stop scanning.
            logger.error(f"Could not persist planner telemetry; continuing without write: {exc}")

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
            "planner": {
                "mode": "smart" if getattr(self.planner, "smart_enabled", False) else "legacy",
                "telemetry": "data/action_telemetry.json",
            },
        }
        with open(os.path.join(report_dir, f"{self.run_id}.json"), "w") as f:
            json.dump(report, f, indent=2)

    def _action_lock(self, action_name):
        """Return the per-action-class lock, creating it on first use."""
        with self._action_locks_guard:
            lock = self._action_locks.get(action_name)
            if lock is None:
                lock = threading.Lock()
                self._action_locks[action_name] = lock
            return lock

    def _host_parallel_workers(self, n_groups):
        """How many host groups to run at once.

        Connectors spawn bruteforce_threads internally, so outer_workers × inner
        must stay under a total budget or a Pi Zero thrashes.  Budget defaults to
        cores×4 (same formula as bruteforce_threads auto).  Config key
        host_parallel: 0 = auto, 1 = serial (old behaviour), N = hard cap.
        """
        configured = int(getattr(self.shared_data, "host_parallel", 0) or 0)
        if configured == 1:
            return 1
        cores = os.cpu_count() or 1
        inner = max(1, int(getattr(self.shared_data, "bruteforce_threads", 0) or 1))
        budget = max(cores * 4, 1)
        auto = max(1, budget // inner)
        # Never more workers than groups, never more than the planner's host cap.
        cap = min(n_groups, max(1, int(getattr(self.planner, "max_host_actions", 4) or 4)))
        if configured > 1:
            return max(1, min(configured, cap, auto))
        return max(1, min(cap, auto))

    def _run_candidate(self, cand, current_data):
        """Execute one planner candidate. Returns True on success.

        Holds the per-action-class lock so two hosts that need the same connector
        singleton cannot interleave on its shared queue/results.
        """
        with self.semaphore:
            with self._action_lock(cand.action_name):
                self.shared_data.bjornorch_status = cand.action_name
                self.shared_data.bjornstatustext2 = cand.reason[:40]
                logger.info(f"Planner chose: {cand.reason} (score={cand.score})")
                if cand.kind == "standalone":
                    return bool(self.execute_standalone_action(
                        cand.action, current_data,
                        planner_score=cand.score, planner_reason=cand.reason))
                if cand.row is not None:
                    ports = str(cand.row.get("Ports", "") or "").split(';')
                    return bool(self.execute_action(
                        cand.action, cand.ip, ports, cand.row,
                        cand.action_name, current_data,
                        planner_score=cand.score, planner_reason=cand.reason,
                    ))
                return False

    def process_alive_ips(self, current_data, idle_boost=0):
        """Score every eligible unit of work and run this cycle's top picks.

        Ranking lives in action_planner.py; this method only executes.

        Cross-host parallelism (#8): candidates are grouped by host row so a
        parent+child on the same box still run sequentially (child sees the
        parent's row update), while distinct hosts run concurrently under a
        ThreadPoolExecutor.  The worker count is capped by a core-aware budget
        so outer_pool × bruteforce_threads cannot thrash a Pi Zero.

        Note: a parent unlocked *during* this cycle still does not unlock its
        child on a *different* host mid-cycle — children become eligible next
        cycle.  Same-host parent+child pairs are preserved by the row grouping.
        """
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

        # Partition: host actions grouped by row identity, standalones separate.
        # Grouping by MAC keeps parent→child order inside one host sequential.
        host_groups = {}  # key -> list[cand] in planner order
        standalones = []
        for cand in work:
            if cand.kind == "standalone":
                standalones.append(cand)
                continue
            key = None
            if cand.row is not None:
                key = cand.row.get("MAC Address") or cand.row.get("IPs") or id(cand.row)
            else:
                key = cand.ip or id(cand)
            host_groups.setdefault(key, []).append(cand)

        host_action_executed = False
        workers = self._host_parallel_workers(len(host_groups)) if host_groups else 1
        logger.info(
            f"Cycle work: {sum(len(v) for v in host_groups.values())} host action(s) "
            f"across {len(host_groups)} host(s), {len(standalones)} standalone; "
            f"parallel workers={workers}"
        )

        def _run_group(group):
            """Run every candidate for one host, in planner order. Returns True if any succeeded."""
            ok = False
            for cand in group:
                if self.shared_data.orchestrator_should_exit:
                    break
                if self._run_candidate(cand, current_data):
                    ok = True
            return ok

        if host_groups:
            if workers <= 1 or len(host_groups) == 1:
                for group in host_groups.values():
                    if self.shared_data.orchestrator_should_exit:
                        break
                    if _run_group(group):
                        host_action_executed = True
            else:
                with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="bjorn-host") as pool:
                    futures = [pool.submit(_run_group, g) for g in host_groups.values()]
                    for fut in as_completed(futures):
                        try:
                            if fut.result():
                                host_action_executed = True
                        except Exception as e:
                            logger.error(f"Host-group worker failed: {e}")

        # Standalones stay sequential — they often share global resources (radio, bettercap).
        # They run for their side effects but do NOT count as "the cycle did work": a periodic
        # standalone (e.g. SNMPEnum on a hostless net) must not keep the loop hot, or run() skips
        # its paced idle wait and spins the CPU — ~10 cycles/s was observed on an empty network.
        for cand in standalones:
            if self.shared_data.orchestrator_should_exit:
                break
            self._run_candidate(cand, current_data)

        # Worker threads update memory only; one atomic write per cycle protects the SD card.
        self._flush_action_telemetry()
        return host_action_executed


    def execute_action(self, action, ip, ports, row, action_key, current_data,
                       planner_score=None, planner_reason=""):
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

        logger.info(f"Executing action {action.action_name} for {ip}:{action.port}")
        # The planner has already put its reason on the display; only fall back to the bare IP
        # when nothing set one (e.g. a manual attack from the web UI).
        if not getattr(self.shared_data, "bjornstatustext2", ""):
            self.shared_data.bjornstatustext2 = ip
        started = time.monotonic()
        error = None
        result = None
        try:
            result = action.execute(ip, str(action.port), row, action_key)
        except Exception as exc:  # normalised below so telemetry receives the precise cause
            error = exc
            logger.error(f"Action {action.action_name} failed: {exc}")
        outcome = normalize_outcome(
            result, duration_s=time.monotonic() - started, error=error)

        # RESOURCE_BUSY and SKIPPED are deferrals, not failed work. Telemetry retains
        # RESOURCE_BUSY for a short retry delay while an ordinary skip leaves no trace.
        if outcome.skipped:
            if outcome.code is OutcomeCode.RESOURCE_BUSY:
                self._record_execution(
                    action.action_name, ip, outcome,
                    planner_score=planner_score, planner_reason=planner_reason)
            logger.debug(
                f"Action {action.action_name} deferred: {outcome.code.value} ({outcome.reason})")
            return False

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if outcome.succeeded:
            row[action_key] = f'success_{timestamp}'
        elif outcome.should_stamp_failure:
            row[action_key] = f'failed_{timestamp}'
        self._record_execution(
            action.action_name, ip, outcome,
            planner_score=planner_score, planner_reason=planner_reason)
        logger.info(
            f"Action outcome: {action.action_name}@{ip}={outcome.code.value}, "
            f"duration={outcome.duration_s:.2f}s, reason={outcome.reason or '-'}")
        return outcome.succeeded

    def merge_bettercap_hosts(self, current_data):
        """Fold anything the Bettercap poller has seen into this cycle's netkb rows.

        Called immediately before each write_data, which is what keeps the orchestrator the single
        writer to netkb: the poller thread only buffers, so there is no second read-modify-write
        cycle to interleave with this one and silently lose rows."""
        poller = getattr(self.shared_data, "bettercap_poller", None)
        if poller is None:
            return
        hosts = poller.drain()
        if not hosts:
            return
        added = bettercap_client.merge_into_netkb(current_data, hosts)
        logger.info(f"Bettercap: {len(hosts)} host(s) from events, {added} new to netkb.")

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
        telemetry = getattr(self, "action_telemetry", None)
        if telemetry is not None:
            flush = getattr(self, "_flush_action_telemetry", None)
            if callable(flush):
                flush()
            else:
                # Lightweight integration fakes may provide telemetry without the helper.
                telemetry.flush()
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

        # ONE pass of the standalones per cycle, then the idle window. That makes
        # offline_cycle_interval the ceiling on every offline cadence, not just the reconnect one:
        # ble_scan_interval_offline=60 cannot fire more often than the cycle it lives in, so a
        # 300s cycle silently turns a 60s BLE cadence into a 5-minute one and hunts a channel
        # picked from a survey of wherever the device was five minutes ago. Long cycles suit a
        # device sitting still; a device being carried wants the default.
        current_data = self.shared_data.read_data()
        self.run_standalone_actions(current_data, offline=True)  # WiFiScan/BLEScan self-throttle
        self.merge_bettercap_hosts(current_data)
        self.shared_data.write_data(current_data)
        # The only other call site is the online idle branch, which an offline cycle `continue`s
        # past — so a device carried around recorded nothing. A 9h field run left a report frozen
        # at the minute it lost its uplink (failed: 0, while four WiFiScans failed after it), and
        # the run either side of a power-yank left no report at all. Offline is when the report
        # matters most: it is the only cycle that ran.
        self.write_run_report()

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

        self._offline_idle(max(15, int(getattr(self.shared_data, "offline_cycle_interval", 60))))
        return True

    def _hunter(self):
        """The Handshake Hunter, created on first use and shared via SharedData so the web panel
        can read its status without the orchestrator handing it around."""
        hunter = getattr(self.shared_data, "hunter", None)
        if hunter is None:
            hunter = bettercap_pwn.Hunter(self.shared_data)
            self.shared_data.hunter = hunter
        return hunter

    def _offline_idle(self, seconds):
        """Spend the offline idle window hunting handshakes, or sleeping if the hunter cannot run.

        THE RULE THIS METHOD ENFORCES: the hunter is started and stopped inside this window and
        never outlives it. reconnect_best() runs near the top of the *next* cycle, by which point
        the radio is verifiably back in managed mode. nmcli cannot associate an interface still in
        monitor mode and it fails *quietly* — so without this the symptom would be "auto-join
        stopped working", not "the hunter is still holding the radio", and Bjorn would sit offline
        forever with a growing pile of handshakes it could never deliver.

        Sleeping was the alternative use of this window, so hunting costs nothing that was being
        spent on something else.
        """
        started = False
        hunter = None
        if getattr(self.shared_data, "bettercap_pwn_enabled", False):
            hunter = self._hunter()
            ok, detail = hunter.start()
            started = ok
            if ok:
                self.shared_data.bjornorch_status = "BettercapPwn"
                self.shared_data.bjornstatustext2 = detail[:40]
                self.last_hunt_detail = None
            elif detail != self.last_hunt_detail:
                # Offline cycles repeat every 60s and a refusal ("only 1 wireless radio") is
                # identical every time. Log the change, not the heartbeat.
                logger.info(f"Hunter not started: {detail}")
                self.last_hunt_detail = detail
        if not started:
            self.shared_data.bjornstatustext2 = "offline · resting"

        try:
            deadline = datetime.now() + timedelta(seconds=seconds)
            while datetime.now() < deadline and not self.shared_data.orchestrator_should_exit:
                time.sleep(1)
        finally:
            # finally, not after the loop: a shutdown mid-window must still hand the radio back,
            # or Bjorn restarts into an interface nothing can associate.
            if started:
                ok, detail = hunter.stop()
                (logger.info if ok else logger.error)(f"Hunter: {detail}")

    def _run_vuln_scans(self, current_data):
        """Submit every eligible alive host to the background vuln pool and return immediately (#9).

        This used to block the idle branch until every host was done. Each nmap is bounded at 300s
        (#4), so with 2 workers a ten-host sweep held the whole orchestrator for up to 25 minutes:
        no rescan, no connectors, no stealers, no standalone recon, and `stop_orchestrator()`'s
        un-timed `join()` waiting it out on shutdown. Now the sweep only *starts* here; results are
        drained and stamped by `_apply_vuln_results` at the top of a later cycle.

        Why this needs no new lock: a worker reads a snapshot of its row, and the only thing that
        leaves the thread is `(ip, result)` on a queue. Nothing touches `current_data` or netkb off
        the main thread, so #7's single-writer discipline is intact. `update_summary_file` was
        already `_summary_lock`-guarded, and each nmap keeps its own #4 timeout.

        2 workers, not #8's I/O budget: nmap -sV/vulners is CPU+network heavy, so keep the
        conservative RPi-Zero cap. The success/failed retry-delay gates are unchanged."""
        eligible = []
        for row in current_data:
            if row.get("Alive") != '1':
                continue
            ip = row["IPs"]
            # Already scanning this host from an earlier sweep — the interval gate fires again
            # while long nmaps are still running, and re-submitting would stack them.
            if ip in self._vuln_inflight:
                continue
            scan_status = row.get("NmapVulnScanner", "")

            # The three skips below are the throttle working as designed — every host in backoff
            # hits one on every sweep, 30 lines in three hours on a seven-host net. DEBUG, not
            # WARNING: the sweep being selective is not a problem anyone needs told about.

            # Skip a host whose vuln scan succeeded recently.
            if 'success' in scan_status:
                if not self.shared_data.retry_success_actions:
                    logger.debug(f"Skipping vulnerability scan for {ip} because retry on success is disabled.")
                    continue
                remaining = retry_wait_remaining(scan_status, self.shared_data.success_retry_delay)
                if remaining > 0:
                    logger.debug(f"Skipping vulnerability scan for {ip} due to success retry delay, retry possible in: {timedelta(seconds=remaining)}")
                    continue

            # Skip a host whose vuln scan failed recently.
            if 'failed' in scan_status:
                remaining = retry_wait_remaining(scan_status, self.shared_data.failed_retry_delay)
                if remaining > 0:
                    logger.debug(f"Skipping vulnerability scan for {ip} due to failed retry delay, retry possible in: {timedelta(seconds=remaining)}")
                    continue

            eligible.append(row)

        if not eligible:
            return

        if self._vuln_pool is None:
            self._vuln_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="bjorn-vuln")
        for row in eligible:
            ip = row["IPs"]
            # Snapshot the three fields execute() reads. The row dict belongs to this cycle's
            # current_data and is replaced by the next read_data(); the worker must not hold it.
            snapshot = {"Ports": row.get("Ports", ""), "Hostnames": row.get("Hostnames", ""),
                        "MAC Address": row.get("MAC Address", "")}
            self._vuln_inflight.add(ip)
            self._vuln_pool.submit(self._vuln_worker, ip, snapshot)
        logger.info(f"Vulnerability sweep submitted for {len(eligible)} host(s); "
                    f"results land on a later cycle.")

    def _vuln_worker(self, ip, row_snapshot):
        """One host's vuln scan, off the cycle. The only thing that leaves this thread is
        (ip, result) on the queue — never a netkb write."""
        result = None
        try:
            result = self.nmap_vuln_scanner.execute(ip, row_snapshot, "NmapVulnScanner")
        except Exception as e:
            logger.error(f"Vulnerability scan failed for {ip}: {e}")
        finally:
            # In a finally: a worker that raised past the except (or was interrupted) must still
            # report, or its IP stays in _vuln_inflight forever and the host is never rescanned.
            self._vuln_results.put((ip, result))

    def _apply_vuln_results(self, current_data):
        """Stamp finished background scans onto the freshly-read rows. Main thread only.

        Results are keyed by IP, not by row object: minutes pass between submit and completion, and
        read_data() builds new dicts every cycle, so the row that was submitted no longer exists.
        A host that left the netkb in the meantime is dropped."""
        applied = 0
        while True:
            try:
                ip, result = self._vuln_results.get_nowait()
            except queue.Empty:
                break
            self._vuln_inflight.discard(ip)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            # 'skipped' (scan did not run) leaves no netkb mark so the host is retried — the
            # contract NmapVulnScanner.execute() documents. Only stamp real success/failure.
            if result == 'success':
                mark = f'success_{timestamp}'
            elif result is not None and result != 'skipped':
                mark = f'failed_{timestamp}'
            else:
                continue
            row = next((r for r in current_data if r.get("IPs") == ip), None)
            if row is None:
                logger.info(f"Vuln result for {ip} dropped — the host is no longer in netkb.")
                continue
            row["NmapVulnScanner"] = mark
            applied += 1
        return applied

    def execute_standalone_action(self, action, current_data, planner_score=None,
                                  planner_reason=""):
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

        logger.info(f"Executing standalone action {action.action_name}")
        started = time.monotonic()
        error = None
        result = None
        try:
            result = action.execute()
        except Exception as exc:  # preserve the cycle while recording an actionable cause
            error = exc
            logger.error(f"Standalone action {action.action_name} failed: {exc}")
        outcome = normalize_outcome(
            result, duration_s=time.monotonic() - started, error=error)

        # Ordinary skipped work remains invisible. RESOURCE_BUSY is retained only in telemetry
        # so it can retry soon without poisoning the action's success statistics.
        if outcome.skipped:
            if outcome.code is OutcomeCode.RESOURCE_BUSY:
                recorder = getattr(self, "_record_execution", None)
                if callable(recorder):
                    recorder(
                        action.action_name, "STANDALONE", outcome,
                        planner_score=planner_score, planner_reason=planner_reason)
            logger.debug(
                f"Standalone action {action.action_name} deferred: {outcome.code.value}")
            return False

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if outcome.succeeded:
            row[action_key] = f'success_{timestamp}'
            logger.info(f"Standalone action {action.action_name} executed successfully")
        elif outcome.should_stamp_failure:
            row[action_key] = f'failed_{timestamp}'
            logger.error(
                f"Standalone action {action.action_name} failed ({outcome.code.value})")
        recorder = getattr(self, "_record_execution", None)
        if callable(recorder):
            recorder(
                action.action_name, "STANDALONE", outcome,
                planner_score=planner_score, planner_reason=planner_reason)
        else:
            # Lightweight test fakes and old integrations expose only the legacy recorder.
            self._record_result(
                action.action_name, outcome.succeeded,
                error=outcome.reason if outcome.code is OutcomeCode.ERROR else None)
        return outcome.succeeded

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
            # #9: stamp any background vuln scans that finished while the cycle was elsewhere.
            # Before the write_data below, so results reach netkb on the cycle they land.
            self._apply_vuln_results(current_data)
            any_action_executed = False
            action_retry_pending = False
            # Consecutive fruitless scans raise the standalone score, so recon that needs no target
            # (BLE, Wi-Fi, SNMP, reporting) takes over as host work dries up.
            idle_boost = min(40, self.failed_scans_count * 12)
            # True only when a *host* action ran; a periodic standalone alone returns False so this
            # falls into the paced idle branch below instead of spinning (see process_alive_ips).
            any_action_executed = self.process_alive_ips(current_data, idle_boost=idle_boost)

            # P3: one netkb write per cycle here — execute_action no longer writes per action.
            self.merge_bettercap_hosts(current_data)
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
                                self._run_vuln_scans(current_data)
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
                    self.merge_bettercap_hosts(current_data)
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

        # Don't wait on in-flight nmaps: each is bounded at 300s (#4) and a restart just rescans
        # the host. cancel_futures drops the ones that never started.
        if self._vuln_pool is not None:
            self._vuln_pool.shutdown(wait=False, cancel_futures=True)

if __name__ == "__main__":
    orchestrator = Orchestrator()
    orchestrator.run()
