#scanning.py
# This script performs a network scan to identify live hosts, their MAC addresses, and open ports.
# The results are saved to CSV files and displayed using Rich for enhanced visualization.

import os
import shutil
import subprocess
import threading
import csv
import netifaces
import time
import glob
import logging
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.progress import Progress
from getmac import get_mac_address as gma
from shared import SharedData
from logger import Logger
import ipaddress
import nmap

logger = Logger(name="scanning.py", level=logging.DEBUG)

b_class = "NetworkScanner"
b_module = "scanning"
b_status = "network_scanner"
b_port = None
b_parent = None
b_priority = 1

class NetworkScanner:
    """
    This class handles the entire network scanning process.
    """
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.logger = logger
        self.displaying_csv = shared_data.displaying_csv
        self.blacklistcheck = shared_data.blacklistcheck
        self.mac_scan_blacklist = shared_data.mac_scan_blacklist
        self.ip_scan_blacklist = shared_data.ip_scan_blacklist
        self.console = Console()
        self.lock = threading.Lock()
        self.currentdir = shared_data.currentdir
        self.nm = nmap.PortScanner()  # Initialize nmap.PortScanner()
        self.running = False

    def get_local_ips(self):
        """This device's own IPv4 addresses across all interfaces (wlan0/eth0/usb0/...).
        Recomputed each scan and added to the scan blacklist so Bjorn never targets itself —
        dynamic, so it survives DHCP address changes (unlike a fixed IP in the config)."""
        ips = set()
        try:
            for iface in netifaces.interfaces():
                for addr in netifaces.ifaddresses(iface).get(netifaces.AF_INET, []):
                    ip = addr.get('addr')
                    if ip and not ip.startswith('127.'):
                        ips.add(ip)
        except Exception as e:
            self.logger.error(f"Error getting local IPs: {e}")
        return list(ips)

    def check_if_csv_scan_file_exists(self, csv_scan_file, csv_result_file, netkbfile):
        """
        Checks and prepares the necessary CSV files for the scan.
        """
        with self.lock:
            try:
                if not os.path.exists(os.path.dirname(csv_scan_file)):
                    os.makedirs(os.path.dirname(csv_scan_file))
                if not os.path.exists(os.path.dirname(netkbfile)):
                    os.makedirs(os.path.dirname(netkbfile))
                if os.path.exists(csv_scan_file):
                    os.remove(csv_scan_file)
                if os.path.exists(csv_result_file):
                    os.remove(csv_result_file)
                if not os.path.exists(netkbfile):
                    with open(netkbfile, 'w', newline='') as file:
                        writer = csv.writer(file)
                        writer.writerow(['MAC Address', 'IPs', 'Hostnames', 'Alive', 'Ports'])
            except Exception as e:
                self.logger.error(f"Error in check_if_csv_scan_file_exists: {e}")

    def get_current_timestamp(self):
        """
        Returns the current timestamp in a specific format.
        """
        return datetime.now().strftime("%Y%m%d_%H%M%S")

    def ip_key(self, ip):
        """
        Converts an IP address to a tuple of integers for sorting.
        """
        if ip == "STANDALONE":
            return (0, 0, 0, 0)
        try:
            return tuple(map(int, ip.split('.')))
        except ValueError as e:
            self.logger.error(f"Error in ip_key: {e}")
            return (0, 0, 0, 0)

    def sort_and_write_csv(self, csv_scan_file):
        """
        Sorts the CSV file based on IP addresses and writes the sorted content back to the file.
        """
        with self.lock:
            try:
                with open(csv_scan_file, 'r') as file:
                    lines = file.readlines()
                sorted_lines = [lines[0]] + sorted(lines[1:], key=lambda x: self.ip_key(x.split(',')[0]))
                with open(csv_scan_file, 'w') as file:
                    file.writelines(sorted_lines)
            except Exception as e:
                self.logger.error(f"Error in sort_and_write_csv: {e}")

    class GetIpFromCsv:
        """
        Helper class to retrieve IP addresses, hostnames, and MAC addresses from a CSV file.
        """
        def __init__(self, outer_instance, csv_scan_file):
            self.outer_instance = outer_instance
            self.csv_scan_file = csv_scan_file
            self.ip_list = []
            self.hostname_list = []
            self.mac_list = []
            self.get_ip_from_csv()

        def get_ip_from_csv(self):
            """
            Reads IP addresses, hostnames, and MAC addresses from the CSV file.
            """
            with self.outer_instance.lock:
                try:
                    with open(self.csv_scan_file, 'r') as csv_scan_file:
                        csv_reader = csv.reader(csv_scan_file)
                        next(csv_reader)
                        for row in csv_reader:
                            if row[0] == "STANDALONE" or row[1] == "STANDALONE" or row[2] == "STANDALONE":
                                continue
                            if not self.outer_instance.blacklistcheck or (row[2] not in self.outer_instance.mac_scan_blacklist and row[0] not in self.outer_instance.ip_scan_blacklist):
                                self.ip_list.append(row[0])
                                self.hostname_list.append(row[1])
                                self.mac_list.append(row[2])
                except Exception as e:
                    self.outer_instance.logger.error(f"Error in get_ip_from_csv: {e}")

    def update_netkb(self, netkbfile, netkb_data, alive_macs):
        """
        Updates the net knowledge base (netkb) file with the scan results.
        """
        with self.lock:
            try:
                netkb_entries = {}
                existing_action_columns = []

                # Read existing CSV file
                if os.path.exists(netkbfile):
                    with open(netkbfile, 'r') as file:
                        reader = csv.DictReader(file)
                        existing_headers = reader.fieldnames
                        existing_action_columns = [header for header in existing_headers if header not in ["MAC Address", "IPs", "Hostnames", "Alive", "Ports"]]
                        for row in reader:
                            mac = row["MAC Address"]
                            ips = row["IPs"].split(';')
                            hostnames = row["Hostnames"].split(';')
                            alive = row["Alive"]
                            ports = row["Ports"].split(';')
                            netkb_entries[mac] = {
                                'IPs': set(ips) if ips[0] else set(),
                                'Hostnames': set(hostnames) if hostnames[0] else set(),
                                'Alive': alive,
                                'Ports': set(ports) if ports[0] else set()
                            }
                            for action in existing_action_columns:
                                netkb_entries[mac][action] = row.get(action, "")

                ip_to_mac = {}  # Dictionary to track IP to MAC associations

                for data in netkb_data:
                    mac, ip, hostname, ports = data
                    if not mac or mac == "STANDALONE" or ip == "STANDALONE" or hostname == "STANDALONE":
                        continue
                    
                    # Check if MAC address is "00:00:00:00:00:00"
                    if mac == "00:00:00:00:00:00":
                        continue

                    if self.blacklistcheck and (mac in self.mac_scan_blacklist or ip in self.ip_scan_blacklist):
                        continue

                    # Check if IP is already associated with a different MAC
                    if ip in ip_to_mac and ip_to_mac[ip] != mac:
                        # Mark the old MAC as not alive
                        old_mac = ip_to_mac[ip]
                        if old_mac in netkb_entries:
                            netkb_entries[old_mac]['Alive'] = '0'

                    # Update or create entry for the new MAC
                    ip_to_mac[ip] = mac
                    if mac in netkb_entries:
                        netkb_entries[mac]['IPs'].add(ip)
                        netkb_entries[mac]['Hostnames'].add(hostname)
                        netkb_entries[mac]['Alive'] = '1'
                        netkb_entries[mac]['Ports'].update(map(str, ports))
                    else:
                        netkb_entries[mac] = {
                            'IPs': {ip},
                            'Hostnames': {hostname},
                            'Alive': '1',
                            'Ports': set(map(str, ports))
                        }
                        for action in existing_action_columns:
                            netkb_entries[mac][action] = ""

                # Update all existing entries to mark missing hosts as not alive
                for mac in netkb_entries:
                    if mac not in alive_macs:
                        netkb_entries[mac]['Alive'] = '0'

                # Remove entries with multiple IP addresses for a single MAC address
                netkb_entries = {mac: data for mac, data in netkb_entries.items() if len(data['IPs']) == 1}

                sorted_netkb_entries = sorted(netkb_entries.items(), key=lambda x: self.ip_key(sorted(x[1]['IPs'])[0]))

                with open(netkbfile, 'w', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(existing_headers)  # Use existing headers
                    for mac, data in sorted_netkb_entries:
                        row = [
                            mac,
                            ';'.join(sorted(data['IPs'], key=self.ip_key)),
                            ';'.join(sorted(data['Hostnames'])),
                            data['Alive'],
                            ';'.join(sorted(data['Ports'], key=int))
                        ]
                        row.extend(data.get(action, "") for action in existing_action_columns)
                        writer.writerow(row)
            except Exception as e:
                self.logger.error(f"Error in update_netkb: {e}")

    def display_csv(self, file_path):
        """
        Displays the contents of the specified CSV file using Rich for enhanced visualization.
        """
        with self.lock:
            try:
                table = Table(title=f"Contents of {file_path}", show_lines=True)
                with open(file_path, 'r') as file:
                    reader = csv.reader(file)
                    headers = next(reader)
                    for header in headers:
                        table.add_column(header, style="cyan", no_wrap=True)
                    for row in reader:
                        formatted_row = [Text(cell, style="green bold") if cell else Text("", style="on red") for cell in row]
                        table.add_row(*formatted_row)
                self.console.print(table)
            except Exception as e:
                self.logger.error(f"Error in display_csv: {e}")

    def get_networks(self):
        """
        Retrieves the subnet of every interface that has an IPv4 address (#133).

        Bjorn used to scan only the default gateway's network; a device on more than one LAN
        (eth0 + wlan0 + usb0, etc.) never saw the others. This returns a de-duplicated list of
        IPv4Network objects, one per interface subnet, skipping loopback and link-local. The
        caller scans each and merges the results into a single netkb.
        """
        networks = {}
        try:
            for iface in netifaces.interfaces():
                for addr in netifaces.ifaddresses(iface).get(netifaces.AF_INET, []):
                    ip_address = addr.get('addr')
                    netmask = addr.get('netmask')
                    if not ip_address or not netmask:
                        continue
                    if ip_address.startswith('127.') or ip_address.startswith('169.254.'):
                        continue
                    try:
                        network = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
                    except ValueError as ve:
                        self.logger.warning(f"Skipping {iface} {ip_address}/{netmask}: {ve}")
                        continue
                    networks[str(network)] = network  # dedupe interfaces sharing a subnet
            result = list(networks.values())
            self.logger.info(f"Networks to scan: {[str(n) for n in result]}")
            return result
        except Exception as e:
            self.logger.error(f"Error in get_networks: {e}")
            return []

    def get_mac_address(self, ip, hostname):
        """
        Retrieves the MAC address for the given IP address and hostname.
        """
        try:
            mac = None
            retries = 2  # fallback path only now (nmap supplies the MAC for LAN hosts — L2); keep the worst case short
            while not mac and retries > 0:
                mac = gma(ip=ip)
                if not mac:
                    time.sleep(1)
                    retries -= 1
            if not mac:
                mac = f"{ip}_{hostname}" if hostname else f"{ip}_NoHostname"
            return mac
        except Exception as e:
            self.logger.error(f"Error in get_mac_address: {e}")
            return None

    # (Removed the socket-based PortScanner: a thread-per-port scanner throttled by a
    # 200-thread semaphore. Replaced by a single nmap port scan in ScanPorts.start() — L1.)

    @staticmethod
    def _rustscan_bin():
        """Resolve the rustscan binary, or None. `shutil.which` alone isn't enough: the systemd
        service runs as `bjorn` with a minimal PATH that omits ~/.cargo/bin (where `cargo install`
        drops it), and it may have been built under a different user (e.g. /home/gixar/.cargo/bin).
        Fall back to globbing the usual cargo/local locations so a present-but-off-PATH binary is
        still found. Returns an absolute path or None."""
        found = shutil.which("rustscan")
        if found:
            return found
        candidates = glob.glob("/home/*/.cargo/bin/rustscan") + [
            "/root/.cargo/bin/rustscan",
            "/usr/local/bin/rustscan",
            "/usr/bin/rustscan",
        ]
        return next((p for p in candidates if os.access(p, os.X_OK)), None)

    def selected_engine(self):
        """Which port-discovery engine to use: 'rustscan' only if opted in AND the binary is
        present, else 'nmap'. Warn (once per scan) when opted in but rustscan isn't installed so
        an existing install that flips the toggle without provisioning the binary isn't silent."""
        if getattr(self.shared_data, "use_rustscan", False):
            if self._rustscan_bin():
                return "rustscan"
            self.logger.warning("use_rustscan is on but the 'rustscan' binary was not found; using nmap.")
        return "nmap"

    def discover_ports(self, ip_list, ports_to_scan, engine):
        """Return {ip: [open ports]} for ip_list, using the named engine. If rustscan is asked for
        but fails at runtime, fall back to nmap so a scan is never lost to a flaky discovery pass."""
        if engine == "rustscan":
            result = self._rustscan_discovery(ip_list, ports_to_scan)
            if result is not None:
                return result
            self.logger.warning("rustscan discovery failed; falling back to nmap.")
        return self._nmap_discovery(ip_list, ports_to_scan)

    def _nmap_discovery(self, ip_list, ports_to_scan):
        """L1: a single nmap TCP-connect scan over all alive hosts. One C process, light on a Pi
        Zero. -sT needs no root; timing follows the configured nmap_scan_aggressivity."""
        open_ports = {ip: [] for ip in ip_list}
        port_arg = ','.join(str(p) for p in ports_to_scan)
        nm = self.nm
        try:
            nm.scan(
                hosts=' '.join(ip_list),
                ports=port_arg,
                arguments='-sT ' + self.shared_data.nmap_scan_aggressivity,
            )
            for ip in ip_list:
                if ip in nm.all_hosts():
                    for proto in nm[ip].all_protocols():
                        for port, info in nm[ip][proto].items():
                            if info.get('state') == 'open':
                                open_ports[ip].append(int(port))
        except Exception as e:
            # Most commonly this is nmap being killed mid-scan (service restart) — python-nmap
            # then fails to parse the truncated XML and its str(e) is a wall of raw XML. Log a
            # concise WARNING (existing port data is preserved; the next scan retries) and keep
            # the raw detail at debug only.
            self.logger.warning("nmap port scan did not complete this cycle "
                                "(interrupted or nmap parse error); keeping existing port data.")
            self.logger.debug(f"nmap port scan error detail: {str(e)[:300]}")
        return open_ports

    def _rustscan_discovery(self, ip_list, ports_to_scan):
        """Discovery-only RustScan pass over the same hosts/ports. Greppable mode (-g) prints
        'IP -> [p1,p2]' and skips RustScan's built-in nmap hand-off, so this is pure port
        discovery — service/version detail still comes from nmap later, same as the nmap path.
        Returns {ip: [open ports]}, or None so discover_ports() falls back to nmap on any failure."""
        bin_path = self._rustscan_bin()
        if not bin_path:
            return None
        batch = getattr(self.shared_data, "rustscan_batch_size", 0)
        cmd = self._rustscan_cmd(bin_path, ip_list, ports_to_scan, batch)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        except Exception as e:
            self.logger.warning(f"rustscan invocation failed: {e}")
            return None
        if proc.returncode != 0:
            self.logger.warning(f"rustscan exited {proc.returncode}: {proc.stderr.strip()[:200]}")
            return None
        return self._parse_rustscan_greppable(proc.stdout, ip_list)

    @staticmethod
    def _rustscan_cmd(bin_path, ip_list, ports_to_scan, batch_size=0):
        """Build the RustScan argv. bin_path is the resolved binary (see _rustscan_bin). batch_size
        > 0 sets `-b <n>` (RustScan's ulimit-bound socket batch); 0 leaves RustScan's own adaptive
        default. On a Pi Zero 2 W a too-large batch silently drops ports (RustScan's documented
        failure mode), so this is the on-device tuning knob — start with the default, lower it if
        the benchmark shows missed ports."""
        port_arg = ','.join(str(p) for p in ports_to_scan)
        cmd = [bin_path, "-a", ','.join(ip_list), "-p", port_arg, "-g", "--no-config"]
        if batch_size and batch_size > 0:
            cmd += ["-b", str(batch_size)]
        return cmd

    @staticmethod
    def _parse_rustscan_greppable(output, ip_list):
        """Parse RustScan greppable lines ('IP -> [80,443]') into {ip: [open ports]}. Pure/testable.
        Every ip_list host is present in the result (empty list if it had no open ports)."""
        open_ports = {ip: [] for ip in ip_list}
        wanted = set(ip_list)
        for line in output.splitlines():
            if "->" not in line:
                continue
            ip_part, _, ports_part = line.partition("->")
            ip = ip_part.strip()
            if ip not in wanted:
                continue
            for p in ports_part.strip().strip("[]").split(","):
                p = p.strip()
                if p.isdigit():
                    open_ports[ip].append(int(p))
        return open_ports

    class ScanPorts:
        """
        Helper class to manage the overall port scanning process for a network.
        """
        def __init__(self, outer_instance, network, portstart, portend, extra_ports):
            self.outer_instance = outer_instance
            self.logger = logger
            self.progress = 0
            self.network = network
            self.portstart = portstart
            self.portend = portend
            self.extra_ports = extra_ports
            self.currentdir = outer_instance.currentdir
            self.scan_results_dir = outer_instance.shared_data.scan_results_dir
            self.timestamp = outer_instance.get_current_timestamp()
            self.csv_scan_file = os.path.join(self.scan_results_dir, f'scan_{network.network_address}_{self.timestamp}.csv')
            self.csv_result_file = os.path.join(self.scan_results_dir, f'result_{network.network_address}_{self.timestamp}.csv')
            self.netkbfile = outer_instance.shared_data.netkbfile
            self.ip_data = None
            self.open_ports = {}
            self.all_ports = []
            self.ip_hostname_list = []

        def scan_network_and_write_to_csv(self):
            """
            Scans the network and writes the results to a CSV file.
            """
            self.outer_instance.check_if_csv_scan_file_exists(self.csv_scan_file, self.csv_result_file, self.netkbfile)
            with self.outer_instance.lock:
                try:
                    with open(self.csv_scan_file, 'a', newline='') as file:
                        writer = csv.writer(file)
                        writer.writerow(['IP', 'Hostname', 'MAC Address'])
                except Exception as e:
                    self.outer_instance.logger.error(f"Error in scan_network_and_write_to_csv (initial write): {e}")

            # Use nmap to scan for live hosts. On a LAN, `-sn` does an ARP sweep and already
            # resolves each host's MAC, so we read it straight from the result (L2) — no per-host
            # ARP retry loop. Iterate synchronously: with the slow MAC lookup gone there's nothing
            # to parallelise, which also removes the old thread-spawn + fixed-sleep race (P6).
            self.outer_instance.nm.scan(hosts=str(self.network), arguments='-sn')
            for host in self.outer_instance.nm.all_hosts():
                self.scan_host(host)

            self.outer_instance.sort_and_write_csv(self.csv_scan_file)

        def scan_host(self, ip):
            """
            Records a live host's hostname and MAC address (MAC taken from the nmap result).
            """
            if self.outer_instance.blacklistcheck and ip in self.outer_instance.ip_scan_blacklist:
                return
            try:
                nm = self.outer_instance.nm
                hostname = nm[ip].hostname() if nm[ip].hostname() else ''
                # L2: MAC from the nmap -sn result; fall back to the slower ARP lookup only when
                # nmap didn't provide one (e.g. this device's own IP or a non-L2 host).
                mac = nm[ip]['addresses'].get('mac', '') if 'addresses' in nm[ip] else ''
                if not mac:
                    mac = self.outer_instance.get_mac_address(ip, hostname)
                if not self.outer_instance.blacklistcheck or mac not in self.outer_instance.mac_scan_blacklist:
                    with self.outer_instance.lock:
                        with open(self.csv_scan_file, 'a', newline='') as file:
                            writer = csv.writer(file)
                            writer.writerow([ip, hostname, mac])
                            self.ip_hostname_list.append((ip, hostname, mac))
            except Exception as e:
                self.outer_instance.logger.error(f"Error getting MAC address or writing to file for IP {ip}: {e}")
            self.progress += 1

        def get_progress(self):
            """
            Returns the progress of the scanning process.
            """
            return (self.progress / self.total_ips) * 100

        def start(self):
            """
            Starts the network and port scanning process.
            """
            self.scan_network_and_write_to_csv()
            self.ip_data = self.outer_instance.GetIpFromCsv(self.outer_instance, self.csv_scan_file)
            self.open_ports = {ip: [] for ip in self.ip_data.ip_list}

            # Port discovery over all alive hosts via the selected engine (nmap -sT by default,
            # RustScan when use_rustscan is on and installed — see NetworkScanner.discover_ports).
            if self.ip_data.ip_list:
                ports_to_scan = sorted(set(list(range(self.portstart, self.portend)) + list(self.extra_ports)))
                engine = self.outer_instance.selected_engine()
                self.open_ports = self.outer_instance.discover_ports(self.ip_data.ip_list, ports_to_scan, engine)

            self.all_ports = sorted(list(set(port for ports in self.open_ports.values() for port in ports)))
            alive_ips = set(self.ip_data.ip_list)
            return self.ip_data, self.open_ports, self.all_ports, self.csv_result_file, self.netkbfile, alive_ips

    class LiveStatusUpdater:
        """
        Helper class to update the live status of hosts and clean up scan results.
        """
        def __init__(self, source_csv_path, output_csv_path):
            self.logger = logger
            self.source_csv_path = source_csv_path
            self.output_csv_path = output_csv_path

        def read_csv(self):
            """
            Reads the source CSV file into a DataFrame.
            """
            try:
                import pandas as pd  # lazy: keep pandas out of module import (P2)
                self.df = pd.read_csv(self.source_csv_path)
            except Exception as e:
                self.logger.error(f"Error in read_csv: {e}")

        def calculate_open_ports(self):
            """
            Calculates the total number of open ports for alive hosts.
            """
            try:
                alive_df = self.df[self.df['Alive'] == 1].copy()
                alive_df.loc[:, 'Ports'] = alive_df['Ports'].fillna('')
                alive_df.loc[:, 'Port Count'] = alive_df['Ports'].apply(lambda x: len(x.split(';')) if x else 0)
                self.total_open_ports = alive_df['Port Count'].sum()
            except Exception as e:
                self.logger.error(f"Error in calculate_open_ports: {e}")

        def calculate_hosts_counts(self):
            """
            Calculates the total and alive host counts.
            """
            try:
                # self.all_known_hosts_count = self.df.shape[0] 
                self.all_known_hosts_count = self.df[self.df['MAC Address'] != 'STANDALONE'].shape[0] 
                self.alive_hosts_count = self.df[self.df['Alive'] == 1].shape[0]
            except Exception as e:
                self.logger.error(f"Error in calculate_hosts_counts: {e}")

        def save_results(self):
            """
            Saves the calculated results to the output CSV file.
            """
            try:
                import pandas as pd  # lazy: keep pandas out of module import (P2)
                if os.path.exists(self.output_csv_path):
                    results_df = pd.read_csv(self.output_csv_path)
                    results_df.loc[0, 'Total Open Ports'] = self.total_open_ports
                    results_df.loc[0, 'Alive Hosts Count'] = self.alive_hosts_count
                    results_df.loc[0, 'All Known Hosts Count'] = self.all_known_hosts_count
                    results_df.to_csv(self.output_csv_path, index=False)
                else:
                    self.logger.error(f"File {self.output_csv_path} does not exist.")
            except Exception as e:
                self.logger.error(f"Error in save_results: {e}")

        def update_livestatus(self):
            """
            Updates the live status of hosts and saves the results.
            """
            try:
                self.read_csv()
                self.calculate_open_ports()
                self.calculate_hosts_counts()
                self.save_results()
                self.logger.info("Livestatus updated")
                self.logger.info(f"Results saved to {self.output_csv_path}")
            except Exception as e:
                self.logger.error(f"Error in update_livestatus: {e}")
        
        def clean_scan_results(self, scan_results_dir):
            """
            Cleans up old scan result files, keeping only the most recent ones.
            """
            try:
                files = glob.glob(scan_results_dir + '/*')
                files.sort(key=os.path.getmtime)
                for file in files[:-20]:
                    os.remove(file)
                self.logger.info("Scan results cleaned up")
            except Exception as e:
                self.logger.error(f"Error in clean_scan_results: {e}")

    def scan(self):
        """
        Initiates the network scan, updates the netkb file, and displays the results.
        """
        try:
            self.shared_data.bjornorch_status = "NetworkScanner"
            self.logger.info(f"Starting Network Scanner")
            # Rebuild the IP blacklist from config + this device's *current* IPs each scan, so
            # Bjorn never scans/attacks itself even after a DHCP address change. All the blacklist
            # checks below read self.ip_scan_blacklist, so refreshing it here covers them.
            local_ips = self.get_local_ips()
            self.ip_scan_blacklist = list(self.shared_data.ip_scan_blacklist) + local_ips
            if local_ips:
                self.logger.info(f"Excluding own IPs from scan: {local_ips}")
            networks = self.get_networks()
            if not networks:
                self.logger.error("No scannable networks found; skipping scan.")
                return
            self.shared_data.bjornstatustext2 = ", ".join(str(n) for n in networks)
            portstart = self.shared_data.portstart
            portend = self.shared_data.portend
            extra_ports = self.shared_data.portlist

            # Scan every interface subnet (#133) and merge into ONE netkb write. update_netkb marks
            # any MAC not in alive_macs as dead, so it must see the alive hosts from *all* networks
            # at once — writing per-network would make each subnet mark the others' hosts offline.
            combined_netkb_data = []
            combined_alive_macs = set()
            netkbfile = self.shared_data.netkbfile
            for network in networks:
                scanner = self.ScanPorts(self, network, portstart, portend, extra_ports)
                ip_data, open_ports, all_ports, csv_result_file, _netkbfile, alive_ips = scanner.start()

                alive_macs = set(ip_data.mac_list)
                combined_alive_macs |= alive_macs

                with self.lock:
                    with open(csv_result_file, 'w', newline='') as file:
                        writer = csv.writer(file)
                        writer.writerow(["IP", "Hostname", "Alive", "MAC Address"] + [str(port) for port in all_ports])
                        for ip, ports, hostname, mac in zip(ip_data.ip_list, open_ports.values(), ip_data.hostname_list, ip_data.mac_list):
                            if self.blacklistcheck and (mac in self.mac_scan_blacklist or ip in self.ip_scan_blacklist):
                                continue
                            alive = '1' if mac in alive_macs else '0'
                            writer.writerow([ip, hostname, alive, mac] + [str(port) if port in ports else '' for port in all_ports])

                for ip, ports, hostname, mac in zip(ip_data.ip_list, open_ports.values(), ip_data.hostname_list, ip_data.mac_list):
                    if self.blacklistcheck and (mac in self.mac_scan_blacklist or ip in self.ip_scan_blacklist):
                        continue
                    combined_netkb_data.append([mac, ip, hostname, ports])

                if self.displaying_csv:
                    self.display_csv(csv_result_file)

            self.update_netkb(netkbfile, combined_netkb_data, combined_alive_macs)

            source_csv_path = self.shared_data.netkbfile
            output_csv_path = self.shared_data.livestatusfile

            updater = self.LiveStatusUpdater(source_csv_path, output_csv_path)
            updater.update_livestatus()
            updater.clean_scan_results(self.shared_data.scan_results_dir)

            # Signal the display threads that netkb/livestatus changed (P5) so they recompute
            # counts this cycle instead of re-parsing the CSVs on every idle refresh.
            self.shared_data.data_generation += 1
        except Exception as e:
            self.logger.error(f"Error in scan: {e}")

    def benchmark_scan_engines(self):
        """Test mode: run the SAME port-discovery scan (same live hosts, same ports) through both
        nmap and RustScan back-to-back, time each, and append the result to a benchmark CSV in the
        data dir. Diagnostic only — does not touch netkb/livestatus. Skips RustScan (records a
        note) if the binary isn't installed. Returns the results dict."""
        self.shared_data.bjornorch_status = "NetworkScanner"
        self.logger.info("Starting scan-engine benchmark (nmap vs rustscan)")
        local_ips = self.get_local_ips()
        self.ip_scan_blacklist = list(self.shared_data.ip_scan_blacklist) + local_ips
        networks = self.get_networks()
        if not networks:
            self.logger.error("No scannable networks found; skipping benchmark.")
            return None

        portstart = self.shared_data.portstart
        portend = self.shared_data.portend
        extra_ports = self.shared_data.portlist
        ports_to_scan = sorted(set(list(range(portstart, portend)) + list(extra_ports)))

        # Discover the live hosts once — both engines then scan this identical target list.
        ip_list = []
        for network in networks:
            sp = self.ScanPorts(self, network, portstart, portend, extra_ports)
            sp.scan_network_and_write_to_csv()
            ip_list.extend(self.GetIpFromCsv(self, sp.csv_scan_file).ip_list)
        ip_list = sorted(set(ip_list), key=self.ip_key)
        if not ip_list:
            self.logger.error("Benchmark found no live hosts; nothing to scan.")
            return None

        results = {}  # engine -> {"seconds": float, "open_port_count": int} or {"skipped": reason}
        for engine, fn in (("nmap", self._nmap_discovery), ("rustscan", self._rustscan_discovery)):
            if engine == "rustscan" and not self._rustscan_bin():
                results[engine] = {"skipped": "binary not installed"}
                self.logger.warning("Benchmark: rustscan not installed — skipping its pass.")
                continue
            t0 = time.perf_counter()
            open_ports = fn(ip_list, ports_to_scan)
            elapsed = time.perf_counter() - t0
            if open_ports is None:  # rustscan runtime failure
                results[engine] = {"skipped": "run failed"}
                continue
            results[engine] = {
                "seconds": round(elapsed, 3),
                "open_port_count": sum(len(p) for p in open_ports.values()),
            }
            self.logger.info(f"Benchmark {engine}: {results[engine]['seconds']}s, "
                             f"{results[engine]['open_port_count']} open ports over {len(ip_list)} hosts")

        self._write_benchmark_results(len(ip_list), len(ports_to_scan), results)
        return results

    def _write_benchmark_results(self, host_count, port_count, results):
        """Append one benchmark row to data/scan_engine_benchmark.csv (created with a header on
        first run). History accumulates so repeated runs / batch tuning can be compared."""
        def cell(engine, field):
            r = results.get(engine, {})
            return r.get(field, r.get("skipped", ""))

        nmap_s = results.get("nmap", {}).get("seconds")
        rust_s = results.get("rustscan", {}).get("seconds")
        speedup = round(nmap_s / rust_s, 2) if (nmap_s and rust_s) else ""

        path = os.path.join(self.shared_data.datadir, "scan_engine_benchmark.csv")
        header = ["Timestamp", "Hosts", "Ports Scanned", "nmap Seconds", "rustscan Seconds",
                  "Speedup (nmap/rustscan)", "nmap Open Ports", "rustscan Open Ports"]
        row = [self.get_current_timestamp(), host_count, port_count,
               cell("nmap", "seconds"), cell("rustscan", "seconds"), speedup,
               cell("nmap", "open_port_count"), cell("rustscan", "open_port_count")]
        try:
            with self.lock:
                new_file = not os.path.exists(path)
                with open(path, "a", newline="") as f:
                    writer = csv.writer(f)
                    if new_file:
                        writer.writerow(header)
                    writer.writerow(row)
            self.logger.info(f"Benchmark results appended to {path}")
        except Exception as e:
            self.logger.error(f"Error writing benchmark results: {e}")

    def start(self):
        """
        Starts the scanner in a separate thread.
        """
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self.scan)
            self.thread.start()
            logger.info("NetworkScanner started.")

    def stop(self):
        """
        Stops the scanner.
        """
        if self.running:
            self.running = False
            if self.thread.is_alive():
                self.thread.join()
            logger.info("NetworkScanner stopped.")

if __name__ == "__main__":
    import sys
    shared_data = SharedData()
    scanner = NetworkScanner(shared_data)
    if "--benchmark" in sys.argv:
        scanner.benchmark_scan_engines()  # test mode: nmap vs rustscan, results in data/scan_engine_benchmark.csv
    else:
        scanner.scan()
