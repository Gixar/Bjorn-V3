# nmap_vuln_scanner.py
# This script performs vulnerability scanning using Nmap on specified IP addresses.
# It scans for vulnerabilities on various ports and saves the results and progress.

import os
import csv
import re
import json
import subprocess
import logging
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn
from shared import SharedData
from logger import Logger

logger = Logger(name="nmap_vuln_scanner.py", level=logging.INFO)

b_class = "NmapVulnScanner"
b_module = "nmap_vuln_scanner"
b_status = "vuln_scan"
b_port = None
b_parent = None

class NmapVulnScanner:
    """
    This class handles the Nmap vulnerability scanning process.
    """
    # The vuln scan runs 2 workers (ThreadPoolExecutor(max_workers=2)) that each call
    # update_summary_file — a read_csv -> concat -> drop_duplicates -> to_csv on the SAME
    # file. Class-level so it serializes across workers (and instances): without it the two
    # writes interleave and lose rows / corrupt the summary CSV (#7).
    _summary_lock = threading.Lock()

    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.scan_results = []
        self.summary_file = self.shared_data.vuln_summary_file
        self._cve_signatures = None  # lazy-loaded offline CVE DB (config/cve_signatures.json)
        self.create_summary_file()
        logger.debug("NmapVulnScanner initialized.")

    def create_summary_file(self):
        """
        Creates a summary file for vulnerabilities if it does not exist.
        """
        if not os.path.exists(self.summary_file):
            os.makedirs(self.shared_data.vulnerabilities_dir, exist_ok=True)
            with open(self.summary_file, "w", newline="", encoding="utf-8") as f:
                csv.DictWriter(
                    f,
                    fieldnames=["IP", "Hostname", "MAC Address", "Port", "Vulnerabilities"],
                ).writeheader()

    def update_summary_file(self, ip, hostname, mac, port, vulnerabilities):
        """
        Updates the summary file with the scan results.

        stdlib csv only — same semantics as the old pandas path: append the new
        row, then drop duplicates on (IP, MAC Address) keeping the *last*
        occurrence so a re-scan replaces the previous entry.
        """
        fields = ["IP", "Hostname", "MAC Address", "Port", "Vulnerabilities"]
        try:
            with self._summary_lock:  # serialize the vuln-scan workers' read-modify-write
                rows = []
                if os.path.exists(self.summary_file):
                    with open(self.summary_file, newline="", encoding="utf-8", errors="replace") as f:
                        rows = list(csv.DictReader(f))
                rows.append({
                    "IP": ip,
                    "Hostname": hostname,
                    "MAC Address": mac,
                    "Port": port,
                    "Vulnerabilities": vulnerabilities,
                })
                # Keep last occurrence per (IP, MAC).
                seen = {}
                for i, row in enumerate(rows):
                    key = (row.get("IP", ""), row.get("MAC Address", ""))
                    seen[key] = i
                keep = set(seen.values())
                rows = [r for i, r in enumerate(rows) if i in keep]

                tmp = self.summary_file + ".tmp"
                with open(tmp, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
                    writer.writeheader()
                    writer.writerows(rows)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp, self.summary_file)
        except Exception as e:
            logger.error(f"Error updating summary file: {e}")


    def scan_vulnerabilities(self, ip, hostname, mac, ports):
        combined_result = ""
        success = True  # Initialize to True, will become False if an error occurs
        try:
            self.shared_data.bjornstatustext2 = ip

            # Proceed with scanning if ports are not already scanned
            logger.info(f"Scanning {ip} on ports {','.join(ports)} for vulnerabilities with aggressivity {self.shared_data.nmap_scan_aggressivity}")
            nmap_args = ["nmap", self.shared_data.nmap_scan_aggressivity]
            if self.shared_data.vuln_scan_sv:
                nmap_args.append("-sV")
            if self.shared_data.vuln_scan_vulners:
                nmap_args += ["--script", "vulners.nse"]
            nmap_args += ["-p", ",".join(ports), ip]
            # Per-host wall-clock bound.  Without this a single slow/unresponsive
            # target blocks the whole vuln-scan pass (and the orchestrator idle branch).
            # 5 minutes is generous for -sV + vulners on a modest port list.
            result = subprocess.run(nmap_args, capture_output=True, text=True, timeout=300)
            if result.returncode != 0:
                # subprocess.run does not raise on a non-zero exit (no check=True), so without this
                # a nmap that errored — bad args, no permission for -sV, an unresolvable target —
                # returned its (often empty) stdout and execute() reported 'success', stamping
                # success_<ts> so that with retry_success off the host was never re-scanned. nmap
                # exits 0 even when every host is down, so a non-zero code is a real error: the
                # scan did not happen (#5, the status-that-cannot-fail class). A clean scan that
                # simply found no vulnerabilities still succeeds — that is the recon convention.
                err = (result.stderr or "").strip().replace("\n", " ")[:300]
                logger.error(f"nmap exited {result.returncode} for {ip}: {err or 'no stderr'}")
                return None
            combined_result += result.stdout

            vulnerabilities = self.parse_vulnerabilities(result.stdout)
            # Offline CVE enrichment: match the -sV service versions against the bundled
            # signature DB. No internet needed, so it complements the online vulners.nse and
            # still flags known-vulnerable versions when vuln_scan_vulners is off.
            if getattr(self.shared_data, "vuln_offline_cve", True):
                offline = self.enrich_offline(result.stdout)
                if offline:
                    vulnerabilities = "; ".join(v for v in (vulnerabilities, offline) if v)
            self.update_summary_file(ip, hostname, mac, ",".join(ports), vulnerabilities)
        except Exception as e:
            logger.error(f"Error scanning {ip}: {e}")
            success = False  # Mark as failed if an error occurs

        return combined_result if success else None

    def execute(self, ip, row, status_key):
        """
        Executes the vulnerability scan for a given IP and row data.
        """
        self.shared_data.bjornorch_status = "NmapVulnScanner"
        ports = row["Ports"].split(";")
        scan_result = self.scan_vulnerabilities(ip, row["Hostnames"], row["MAC Address"], ports)

        if scan_result is not None:
            self.scan_results.append((ip, row["Hostnames"], row["MAC Address"]))
            self.save_results(row["MAC Address"], ip, scan_result)
            return 'success'
        else:
            # 'skipped', not 'success'. scan_vulnerabilities() returns None only when it raised, so
            # this branch is "the scan did not happen". Reporting it as success wrote
            # success_<ts> into netkb, counted a success in the run report, and — with
            # retry_success_actions off — meant the host was never scanned again. The original
            # intent ("only scan once") is preserved by 'skipped': it leaves no netkb mark and no
            # run-report entry, so the host is retried, but nothing claims work that did not happen.
            # This is the defect class the codebase keeps rediscovering: a status that cannot fail.
            logger.warning(f"Vulnerability scan did not complete for {ip}; reporting skipped.")
            return 'skipped'

    def parse_vulnerabilities(self, scan_result):
        """
        Parses the Nmap scan result to extract vulnerabilities.
        """
        vulnerabilities = set()
        capture = False
        for line in scan_result.splitlines():
            if "VULNERABLE" in line or "CVE-" in line or "*EXPLOIT*" in line:
                capture = True
            if capture:
                if line.strip() and not line.startswith('|_'):
                    vulnerabilities.add(line.strip())
                else:
                    capture = False
        return "; ".join(vulnerabilities)

    # --- Offline CVE enrichment (bundled config/cve_signatures.json) -------------------
    def _load_cve_signatures(self):
        """Load the bundled offline CVE signature DB. Missing/broken file → [] (feature no-ops)."""
        path = os.path.join(self.shared_data.configdir, "cve_signatures.json")
        try:
            with open(path) as f:
                return json.load(f).get("signatures", [])
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.warning(f"Offline CVE signatures unavailable ({path}): {e}")
            return []

    def enrich_offline(self, scan_output):
        """Match the service versions nmap -sV reported (via CPE) against the signature DB.
        Returns a '; '-joined string of matched CVEs (empty if none / no signatures)."""
        if self._cve_signatures is None:
            self._cve_signatures = self._load_cve_signatures()
        if not self._cve_signatures:
            return ""
        pairs = self._parse_service_versions(scan_output)
        return "; ".join(sorted(self._match_signatures(pairs, self._cve_signatures)))

    @staticmethod
    def _parse_service_versions(scan_output):
        """Extract (product, version) pairs from nmap -sV output. Primary source is the structured
        CPE lines (cpe:/a:vendor:product:version). Fallback for services nmap couldn't CPE-identify
        (common on consumer gear like routers): take the first two tokens of the -sV version detail
        (`PORT open SERVICE <product> <version> …`) as (product, version). product lowercased,
        deduped. Garbage products from the fallback simply match no signature, so it only adds hits,
        never false positives."""
        pairs, seen = [], set()

        def add(product, version):
            key = (product.lower(), version)
            if key not in seen:
                seen.add(key)
                pairs.append(key)

        for m in re.finditer(r'cpe:/[aoh]:[^:\s]+:([^:\s]+):([^:\s]+)', scan_output):
            add(m.group(1), m.group(2))
        # service-line fallback (multiline: ^ at each line start)
        for m in re.finditer(r'(?m)^\d+/\w+\s+open\s+\S+\s+(\S+)\s+(\S+)', scan_output):
            add(m.group(1), m.group(2))
        return pairs

    @staticmethod
    def _match_signatures(pairs, signatures):
        """Set of 'CVE-… (product version) [severity]' strings for every (product, version) that
        matches a signature. Pure/testable."""
        findings = set()
        for product, version in pairs:
            for sig in signatures:
                if sig.get("product", "").lower() == product and \
                        NmapVulnScanner._version_matches(version, sig):
                    findings.add(f"{sig['cve']} ({product} {version}) [{sig.get('severity', '?')}]")
        return findings

    @staticmethod
    def _version_matches(version, sig):
        if "version" in sig:
            return version == sig["version"]
        if "version_contains" in sig:
            return sig["version_contains"] in version
        if "version_lt" in sig:
            # ponytail: naive numeric-tuple compare (8.4p1 -> (8,4,1)); fine for the seed CVEs.
            # Swap for packaging.version if real range matching is ever needed.
            return NmapVulnScanner._ver_tuple(version) < NmapVulnScanner._ver_tuple(sig["version_lt"])
        return False

    @staticmethod
    def _ver_tuple(v):
        return tuple(int(n) for n in re.findall(r'\d+', v))

    def save_results(self, mac_address, ip, scan_result):
        """
        Saves the detailed scan results to a file.
        """
        try:
            sanitized_mac_address = mac_address.replace(":", "")
            result_dir = self.shared_data.vulnerabilities_dir
            os.makedirs(result_dir, exist_ok=True)
            result_file = os.path.join(result_dir, f"{sanitized_mac_address}_{ip}_vuln_scan.txt")
            
            # Open the file in write mode to clear its contents if it exists, then close it
            if os.path.exists(result_file):
                open(result_file, 'w').close()
            
            # Write the new scan result to the file
            with open(result_file, 'w') as file:
                file.write(scan_result)
            
            logger.info(f"Results saved to {result_file}")
        except Exception as e:
            logger.error(f"Error saving scan results for {ip}: {e}")


    def save_summary(self):
        """
        Saves a summary of all scanned vulnerabilities to a final summary file.

        Groups by (IP, Hostname, MAC Address) and unions the Vulnerabilities
        field (semicolon-separated, de-duplicated) — same result as the old
        pandas groupby/apply, without loading pandas.
        """
        try:
            final_summary_file = os.path.join(
                self.shared_data.vulnerabilities_dir, "final_vulnerability_summary.csv"
            )
            groups = {}  # (ip, hostname, mac) -> set of vuln tokens
            if os.path.exists(self.summary_file):
                with open(self.summary_file, newline="", encoding="utf-8", errors="replace") as f:
                    for row in csv.DictReader(f):
                        key = (
                            row.get("IP", ""),
                            row.get("Hostname", ""),
                            row.get("MAC Address", ""),
                        )
                        bucket = groups.setdefault(key, set())
                        for token in (row.get("Vulnerabilities") or "").split(";"):
                            token = token.strip()
                            if token:
                                bucket.add(token)

            fields = ["IP", "Hostname", "MAC Address", "Vulnerabilities"]
            tmp = final_summary_file + ".tmp"
            os.makedirs(self.shared_data.vulnerabilities_dir, exist_ok=True)
            with open(tmp, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fields)
                writer.writeheader()
                for (ip, hostname, mac), vulns in groups.items():
                    writer.writerow({
                        "IP": ip,
                        "Hostname": hostname,
                        "MAC Address": mac,
                        "Vulnerabilities": "; ".join(sorted(vulns)),
                    })
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, final_summary_file)
            logger.info(f"Summary saved to {final_summary_file}")
        except Exception as e:
            logger.error(f"Error saving summary: {e}")

if __name__ == "__main__":
    shared_data = SharedData()
    try:
        nmap_vuln_scanner = NmapVulnScanner(shared_data)
        logger.info("Starting vulnerability scans...")

        # Load the netkbfile and get the IPs to scan
        ips_to_scan = shared_data.read_data()  # Use your existing method to read the data

        # Execute the scan on each IP with concurrency
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            "[progress.percentage]{task.percentage:>3.1f}%",
            console=Console()
        ) as progress:
            task = progress.add_task("Scanning vulnerabilities...", total=len(ips_to_scan))
            futures = []
            with ThreadPoolExecutor(max_workers=2) as executor:  # Adjust the number of workers for RPi Zero
                for row in ips_to_scan:
                    if row["Alive"] == '1':  # Check if the host is alive
                        ip = row["IPs"]
                        futures.append(executor.submit(nmap_vuln_scanner.execute, ip, row, b_status))

                for future in as_completed(futures):
                    progress.update(task, advance=1)

        nmap_vuln_scanner.save_summary()
        logger.info(f"Total scans performed: {len(nmap_vuln_scanner.scan_results)}")
        exit(len(nmap_vuln_scanner.scan_results))
    except Exception as e:
        logger.error(f"Error: {e}")
