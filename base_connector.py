"""base_connector.py — shared scaffolding for the six brute-force connectors (#12).

Each protocol module keeps its b_class/b_module/b_port globals and a thin
adapter that only implements `attempt(ip, user, password) -> bool` plus the
constants.  Everything else (queue, worker with task_done-in-finally, row→mac
fast-path, credential_candidates, thread spawn, exit-drain) lives here once.

The orchestrator discovers actions by module-level globals; it never imports
this file directly.  Per-action-class locks in the orchestrator (#8) still
serialize two hosts that share one connector singleton.
"""
from __future__ import annotations

import os
import threading
import time
from queue import Queue

from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn

from shared import (
    SharedData,
    netkb_targets,
    append_csv_rows,
    dedupe_csv,
    credential_candidates,
    record_cracked_cred,
)
import logging
from logger import Logger

logger = Logger(name="base_connector.py", level=logging.DEBUG)


class BaseConnector:
    """Subclass and set PORT / HEADER / OUTFILE_ATTR / PROGRESS_LABEL; implement attempt()."""

    PORT: int = 0
    HEADER: str = "MAC Address,IP Address,Hostname,User,Password,Port\n"
    OUTFILE_ATTR: str = ""          # attribute name on shared_data holding the results CSV path
    PROGRESS_LABEL: str = "Brute"
    # When False (SQL), queue items are (ip, user, password, port) without mac/hostname.
    QUEUE_HAS_MAC: bool = True

    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.load_scan_file()
        self.users = open(shared_data.usersfile, "r").read().splitlines()
        self.passwords = open(shared_data.passwordsfile, "r").read().splitlines()
        self.lock = threading.Lock()
        self.outfile = getattr(shared_data, self.OUTFILE_ATTR)
        if not os.path.exists(self.outfile):
            logger.info(f"File {self.outfile} does not exist. Creating...")
            with open(self.outfile, "w") as f:
                f.write(self.HEADER)
        self.results = []
        self.queue = Queue()

    def load_scan_file(self):
        self.scan = netkb_targets(self.shared_data.netkbfile, str(self.PORT))

    def attempt(self, adresse_ip, user, password):
        """Return True on successful auth. Subclasses MUST implement and carry timeout=."""
        raise NotImplementedError

    def worker(self, progress, task_id, success_flag):
        while not self.queue.empty():
            if self.shared_data.orchestrator_should_exit:
                logger.info("Orchestrator exit signal received, stopping worker thread.")
                break
            if self.QUEUE_HAS_MAC:
                adresse_ip, user, password, mac_address, hostname, port = self.queue.get()
            else:
                adresse_ip, user, password, port = self.queue.get()
                mac_address, hostname = "", ""
            # try/finally so task_done() ALWAYS runs — a raise here would otherwise
            # hang queue.join() and take the orchestrator with it.
            try:
                if self.attempt(adresse_ip, user, password):
                    with self.lock:
                        if self.QUEUE_HAS_MAC:
                            self.results.append(
                                [mac_address, adresse_ip, hostname, user, password, port]
                            )
                        else:
                            self.results.append([adresse_ip, user, password, port])
                        record_cracked_cred(self.shared_data, user, password)
                        logger.success(
                            f"Found credentials  IP: {adresse_ip} | User: {user} | Password: {password}"
                        )
                        self.save_results()
                        self.removeduplicates()
                        success_flag[0] = True
            except Exception as e:
                logger.error(f"attempt failed for {adresse_ip} as {user}: {e}")
            finally:
                self.queue.task_done()
            progress.update(task_id, advance=1)

    def run_bruteforce(self, adresse_ip, port, row=None):
        # Resolve mac/hostname BEFORE filling the queue (the RDP UnboundLocalError class).
        if self.QUEUE_HAS_MAC:
            if row is not None:
                mac_address = row.get("MAC Address", "")
                hostname = row.get("Hostnames", "")
            else:
                self.load_scan_file()
                match = next((r for r in self.scan if r.get("IPs") == adresse_ip), None)
                if match is None:
                    logger.error(f"No netkb entry for {adresse_ip}; skipping.")
                    return False, []
                mac_address = match["MAC Address"]
                hostname = match["Hostnames"]

        candidates = credential_candidates(self.shared_data, self.users, self.passwords)
        total_tasks = len(candidates)

        for user, password in candidates:
            if self.shared_data.orchestrator_should_exit:
                logger.info("Orchestrator exit signal received, stopping bruteforce task addition.")
                return False, []
            if self.QUEUE_HAS_MAC:
                self.queue.put((adresse_ip, user, password, mac_address, hostname, port))
            else:
                self.queue.put((adresse_ip, user, password, port))

        success_flag = [False]
        threads = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        ) as progress:
            task_id = progress.add_task(
                f"[cyan]Bruteforcing {self.PROGRESS_LABEL}...", total=total_tasks
            )
            for _ in range(self.shared_data.bruteforce_threads):
                t = threading.Thread(
                    target=self.worker, args=(progress, task_id, success_flag)
                )
                t.start()
                threads.append(t)

            while not self.queue.empty():
                if self.shared_data.orchestrator_should_exit:
                    logger.info("Orchestrator exit signal received, stopping bruteforce.")
                    while not self.queue.empty():
                        self.queue.get()
                        self.queue.task_done()
                    break
                time.sleep(0.2)

            self.queue.join()
            for t in threads:
                t.join()

        return success_flag[0], self.results

    def save_results(self):
        append_csv_rows(self.outfile, self.results)
        self.results = []

    def removeduplicates(self):
        dedupe_csv(self.outfile)


class BaseBruteforce:
    """Thin action-facing wrapper. Subclass, set connector_class and display name."""

    connector_class = BaseConnector
    display_name = "Bruteforce"

    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.connector = self.connector_class(shared_data)
        logger.info(f"{self.connector_class.__name__} initialized.")

    def execute(self, ip, port, row, status_key):
        logger.info(f"Executing {self.display_name} on {ip}:{port}...")
        self.shared_data.bjornorch_status = self.display_name
        success, _results = self.connector.run_bruteforce(ip, port, row)
        return "success" if success else "failed"
