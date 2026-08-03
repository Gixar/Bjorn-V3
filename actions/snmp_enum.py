"""snmp_enum.py - SNMP enumeration (backlog Wave 2).

A standalone action (not port-gated): SNMP is UDP/161, which the TCP scanner never discovers, so
this iterates the alive hosts in netkb itself and probes 161 with the configured community strings
via `snmpget` (net-snmp). On a hit it records sysDescr + sysName to
data/output/scan_results/snmp_enum.csv. No-op (logged) if `snmpget` isn't installed — same graceful
external-tool pattern as RustScan.
"""
import os
import csv
import shutil
import logging
import subprocess
from shared import SharedData
from logger import Logger
from csv_safe import sanitize_row

logger = Logger(name="snmp_enum.py", level=logging.INFO)

b_class = "SNMPEnum"
b_module = "snmp_enum"
b_status = "snmp_enum"
b_port = 0  # standalone action (SNMP is UDP/161, not TCP-discoverable)
b_parent = None

OID_SYSDESCR = "1.3.6.1.2.1.1.1.0"
OID_SYSNAME = "1.3.6.1.2.1.1.5.0"


class SNMPEnum:
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self._probed = set()  # IPs tried this run (avoid re-probing SNMP-closed hosts every cycle)
        self.outfile = os.path.join(shared_data.scan_results_dir, "snmp_enum.csv")
        logger.info("SNMPEnum initialized.")

    def execute(self):
        try:
            binp = shutil.which("snmpget")
            if not binp:
                logger.info("snmpget not found (install the 'snmp' package); skipping SNMP enum.")
                return 'success'
            communities = getattr(self.shared_data, "snmp_communities", ["public"]) or ["public"]
            known = self._known_ips()
            found = 0
            for row in self.shared_data.read_data():
                if row.get("Alive") != '1':
                    continue
                ip = row["IPs"]
                if ip in self._probed or ip in known:
                    continue
                self._probed.add(ip)
                for community in communities:
                    descr = self._snmpget(binp, community, ip, OID_SYSDESCR)
                    if descr:
                        name = self._snmpget(binp, community, ip, OID_SYSNAME)
                        self._record(ip, row.get("Hostnames", ""), community, descr, name)
                        logger.success(f"SNMP open on {ip} (community '{community}'): {descr[:60]}")
                        found += 1
                        break
            if found:
                logger.success(f"SNMP enum: {found} new host(s) responded.")
            return 'success'
        except Exception as e:
            logger.error(f"Error in SNMP enum: {e}")
            return 'failed'

    def _snmpget(self, binp, community, ip, oid):
        try:
            proc = subprocess.run(self._snmpget_cmd(binp, community, ip, oid),
                                  capture_output=True, text=True, timeout=8)
        except Exception:
            return ""
        return self._clean_value(proc.stdout) if proc.returncode == 0 else ""

    @staticmethod
    def _snmpget_cmd(binp, community, ip, oid):
        # -v2c -c <community> -t 1 -r 0 (1s timeout, no retries) -Ovq (value only, no type/quotes)
        return [binp, "-v2c", "-c", community, "-t", "1", "-r", "0", "-Ovq", ip, oid]

    @staticmethod
    def _clean_value(s):
        return s.strip().strip('"').strip()

    def _known_ips(self):
        known = set()
        try:
            with open(self.outfile, newline='') as f:
                r = csv.reader(f)
                next(r, None)
                for row in r:
                    if row:
                        known.add(row[0])
        except FileNotFoundError:
            pass
        return known

    def _record(self, ip, hostname, community, descr, name):
        os.makedirs(os.path.dirname(self.outfile), exist_ok=True)
        new_file = not os.path.exists(self.outfile)
        with open(self.outfile, "a", newline="") as f:
            w = csv.writer(f)
            if new_file:
                w.writerow(["IP", "Hostname", "Community", "sysDescr", "sysName"])
            w.writerow(sanitize_row([ip, hostname, community, descr, name]))


if __name__ == "__main__":
    SNMPEnum(SharedData()).execute()
