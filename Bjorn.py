#bjorn.py
# This script defines the main execution flow for the Bjorn application. It initializes and starts
# various components such as network scanning, display, and web server functionalities. The Bjorn 
# class manages the primary operations, including initiating network scans and orchestrating tasks.
# The script handles startup delays and coordinates the execution of scanning and orchestrator
# tasks using semaphores to limit concurrent threads. It also sets up
# signal handlers to ensure a clean exit when the application is terminated.
#
# Connectivity is NOT checked here: the orchestrator handles being offline itself (offline_mode.py),
# and gating its startup on Wi-Fi is what kept the offline recon path from ever running.

# Functions:
# - handle_exit:  handles the termination of the main and display threads.

# The script starts by loading shared data configurations, then initializes and sta
# bjorn.py


import threading
import signal
import logging
import time
import sys
import subprocess
import battery
import bettercap_client
from init_shared import shared_data
from display import Display, handle_exit_display
from comment import Commentaireia
from webapp import web_thread
from orchestrator import Orchestrator
from logger import Logger

logger = Logger(name="Bjorn.py", level=logging.DEBUG)

# PG-4 watchdog: the main loop refreshes this heartbeat each iteration. A background loop in the
# systemd unit restarts bjorn.service if it goes stale (the main loop wedged). /run is tmpfs on
# Raspberry Pi OS, so this costs zero SD writes. Keep this path in sync with install_bjorn.sh.
HEARTBEAT_FILE = "/run/bjorn_heartbeat"


def touch_heartbeat():
    """Refresh the watchdog heartbeat. Best-effort — never raise (e.g. /run unwritable off-Pi)."""
    try:
        with open(HEARTBEAT_FILE, "w") as f:
            f.write(str(int(time.time())))
    except Exception:
        pass

class Bjorn:
    """Main class for Bjorn. Manages the primary operations of the application."""
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.commentaire_ia = Commentaireia()
        self.orchestrator_thread = None
        self.orchestrator = None

    def run(self):
        """Main loop for Bjorn. Keeps the Orchestrator running, online or not."""
        # Wait for startup delay if configured in shared data
        if hasattr(self.shared_data, 'startup_delay') and self.shared_data.startup_delay > 0:
            logger.info(f"Waiting for startup delay: {self.shared_data.startup_delay} seconds")
            time.sleep(self.shared_data.startup_delay)

        # Main loop to keep Bjorn running
        while not self.shared_data.should_exit:
            touch_heartbeat()  # PG-4: tell the systemd watchdog the main loop is alive
            self.check_battery()  # PG-3: shut down cleanly before the battery dies
            if not self.shared_data.manual_mode:
                self.check_and_start_orchestrator()
            time.sleep(10)  # Main loop idle waiting

    def check_battery(self):
        """PG-3: if a battery monitor is configured and charge is below the shutdown threshold,
        power off cleanly (systemd stops bjorn.service -> SIGTERM -> flush) to protect the SD."""
        if not getattr(self.shared_data, 'battery_monitor_enabled', False):
            return
        pct = battery.read_percent()
        if pct is None:
            return  # no battery hardware reachable — nothing to do
        threshold = getattr(self.shared_data, 'battery_shutdown_percent', 10)
        if pct <= threshold:
            logger.critical(f"Battery at {pct}% (<= {threshold}% threshold). Shutting down cleanly "
                            f"to protect the SD card.")
            self.shared_data.should_exit = True
            # Static command, no user input — but use subprocess (list form), not os.system.
            subprocess.run(["shutdown", "-h", "now"], check=False)



    def check_and_start_orchestrator(self):
        """Start the orchestrator if it is not already running.

        NO CONNECTIVITY GATE, deliberately. This used to run only when nmcli reported an active
        Wi-Fi association, which made every line of offline_mode.py dead code: carried out with no
        uplink, Bjorn started no orchestrator, so `run_offline_cycle` never ran and the Wi-Fi
        survey, BLE recon, handshake hunter and auto-rejoin never happened. The device logged
        "Waiting for Wi-Fi connection to start Orchestrator..." every 10s and collected nothing —
        the walk that reported "bettercap did nothing" was this, not the hunter's default.

        The orchestrator owns the offline case itself: `run_offline_cycle()` is the first thing its
        loop does, it pauses IP scanning when there is no default route, and the initial
        `network_scanner.scan()` is a logged no-op with no scannable network. A Wi-Fi check here
        was also the wrong question twice over — it says nothing about a wired/USB uplink, and
        associated-without-a-route is not online for any purpose Bjorn has.
        """
        if self.orchestrator_thread is None or not self.orchestrator_thread.is_alive():
            self.start_orchestrator()

    def start_orchestrator(self):
        """Start the orchestrator thread."""
        if self.orchestrator_thread is None or not self.orchestrator_thread.is_alive():
            logger.info("Starting Orchestrator thread...")
            self.shared_data.orchestrator_should_exit = False
            self.shared_data.manual_mode = False
            self.orchestrator = Orchestrator()
            self.orchestrator_thread = threading.Thread(target=self.orchestrator.run)
            self.orchestrator_thread.start()
            logger.info("Orchestrator thread started, automatic mode activated.")
        else:
            logger.info("Orchestrator thread is already running.")

    def stop_orchestrator(self):
        """Stop the orchestrator thread."""
        self.shared_data.manual_mode = True
        logger.info("Stop button pressed. Manual mode activated & Stopping Orchestrator...")
        if self.orchestrator_thread is not None and self.orchestrator_thread.is_alive():
            logger.info("Stopping Orchestrator thread...")
            self.shared_data.orchestrator_should_exit = True
            self.orchestrator_thread.join()
            logger.info("Orchestrator thread stopped.")
            self.shared_data.bjornorch_status = "IDLE"
            self.shared_data.bjornstatustext2 = ""
            self.shared_data.manual_mode = True
        else:
            logger.info("Orchestrator thread is not running.")

    @staticmethod
    def start_display():
        """Start the display thread"""
        display = Display(shared_data)
        display_thread = threading.Thread(target=display.run)
        display_thread.start()
        return display_thread

# Longest any single thread may hold up shutdown. systemd will SIGKILL on TimeoutStopSec anyway;
# the point of bounding each join is to reach the clean-exit log and flush, rather than being
# killed mid-write on a device whose atomic-write and watchdog design exists to avoid exactly that.
_JOIN_TIMEOUT = 10


def handle_exit(sig, frame, display_thread, bjorn_thread, web_thread):
    """Handles the termination of the main, display, and web threads."""
    shared_data.should_exit = True
    shared_data.orchestrator_should_exit = True  # Ensure orchestrator stops
    shared_data.display_should_exit = True  # Ensure display stops
    shared_data.webapp_should_exit = True  # Ensure web server stops
    handle_exit_display(sig, frame, display_thread)

    # Uvicorn only returns from serve() when server.should_exit is set, and shutdown() is the only
    # thing that sets it. Without this the join below blocked forever: webapp.py registers its own
    # SIGINT/SIGTERM handlers at import, but __main__ re-registers these ones afterwards and wins,
    # so handle_exit_web never ran. Every `systemctl stop/restart` waited out TimeoutStopSec and
    # died to SIGKILL.
    if web_thread.is_alive():
        web_thread.shutdown()

    for name, thread in (("display", display_thread), ("main", bjorn_thread), ("web", web_thread)):
        if thread.is_alive():
            thread.join(timeout=_JOIN_TIMEOUT)
            if thread.is_alive():
                logger.warning(f"{name} thread did not stop within {_JOIN_TIMEOUT}s; exiting anyway.")
    logger.info("Main loop finished. Clean exit.")
    sys.exit(0)  # Used sys.exit(0) instead of exit(0)



if __name__ == "__main__":
    logger.info("Starting threads")

    try:
        logger.info("Loading shared data config...")
        shared_data.load_config()

        logger.info("Starting display thread...")
        shared_data.display_should_exit = False  # Initialize display should_exit
        display_thread = Bjorn.start_display()

        logger.info("Starting Bjorn thread...")
        bjorn = Bjorn(shared_data)
        shared_data.bjorn_instance = bjorn  # Assigner l'instance de Bjorn à shared_data
        bjorn_thread = threading.Thread(target=bjorn.run)
        bjorn_thread.start()

        if shared_data.config["websrv"]:
            logger.info("Starting the web server...")
            web_thread.start()

        # Bettercap poller (docs/BETTERCAP_PLAN.md B2). No-op unless bettercap_enabled, which
        # defaults false — so an install that never touched the Bettercap page starts no thread
        # and makes no requests. It only buffers; the orchestrator does the netkb write.
        shared_data.bettercap_poller = bettercap_client.start_poller(shared_data)

        signal.signal(signal.SIGINT, lambda sig, frame: handle_exit(sig, frame, display_thread, bjorn_thread, web_thread))
        signal.signal(signal.SIGTERM, lambda sig, frame: handle_exit(sig, frame, display_thread, bjorn_thread, web_thread))

    except Exception as e:
        logger.error(f"An exception occurred during thread start: {e}")
        # 3 args, not 2: handle_exit_display(signum, frame, display_thread). The old
        # two-arg call raised TypeError from inside the error handler, replacing the
        # real startup failure with a confusing one.
        handle_exit_display(signal.SIGINT, None, locals().get('display_thread'))
        exit(1)
