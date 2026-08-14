"""The five brute-force connectors that had no tests at all.

`test_ssh_connector.py` already covered SSH; FTP, SMB, Telnet, SQL and RDP — the rest of the
offensive core — had none, because four of them could not even be imported under test until
`smb`/`pymysql`/`sqlalchemy`/`telnetlib` were stubbed.

Each connector's `<proto>_connect` is the security-critical decision in the whole tool: it decides
whether a credential is reported as valid. The property that matters is the same for all of them —
**a failure of any kind must return False, never a truthy value** — because a connector that
reports success on an exception writes a false credential into the cracked-password pool, which
`credential_reuse` then replays against every other host on the network.
"""
import socket
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _stubs  # noqa: E402
_stubs.install()


def _bare(module_name, class_name):
    """Instantiate without __init__ — it reads wordlists and CSVs we do not need here."""
    import importlib
    mod = importlib.import_module(f"actions.{module_name}")
    return mod, getattr(mod, class_name).__new__(getattr(mod, class_name))


# --- FTP -------------------------------------------------------------------

def test_ftp_connect_true_on_login_and_false_on_any_failure(monkeypatch):
    mod, conn = _bare("ftp_connector", "FTPConnector")

    class OkFTP:
        def connect(self, *a, **k): pass
        def login(self, *a, **k): pass
        def quit(self): pass

    monkeypatch.setattr(mod, "FTP", OkFTP)
    assert conn.attempt("10.0.0.5", "root", "toor") is True

    for boom in (socket.error("refused"), OSError("no route"), Exception("530 denied")):
        class BadFTP:
            def __init__(self, _e=boom): self._e = _e
            def connect(self, *a, **k): raise self._e
            def login(self, *a, **k): pass
            def quit(self): pass
        monkeypatch.setattr(mod, "FTP", BadFTP)
        assert conn.attempt("10.0.0.5", "root", "wrong") is False, boom


# --- Telnet ----------------------------------------------------------------

def test_telnet_connect_only_succeeds_on_a_shell_prompt(monkeypatch):
    """expect() index 2/3 are the `$ ` and `# ` prompts; 0 is 'Login incorrect'. Anything else,
    including a re-prompt for a password, is a failed login."""
    mod, conn = _bare("telnet_connector", "TelnetConnector")
    monkeypatch.setattr(mod.time, "sleep", lambda *_a: None)

    def telnet_returning(index):
        class T:
            def __init__(self, *a, **k): pass
            def read_until(self, *a, **k): return b""
            def write(self, *a, **k): pass
            def expect(self, *a, **k): return (index, None, b"")
            def close(self): pass
        return T

    for shell_index in (2, 3):
        monkeypatch.setattr(mod.telnetlib, "Telnet", telnet_returning(shell_index))
        assert conn.attempt("10.0.0.5", "root", "toor") is True, shell_index

    for reject_index in (0, 1, -1):
        monkeypatch.setattr(mod.telnetlib, "Telnet", telnet_returning(reject_index))
        assert conn.attempt("10.0.0.5", "root", "toor") is False, reject_index


def test_telnet_connect_survives_a_non_ascii_password(monkeypatch):
    """`user.encode('ascii')` raises on non-ASCII wordlist entries. That must read as a failed
    login, not crash the worker thread."""
    mod, conn = _bare("telnet_connector", "TelnetConnector")
    monkeypatch.setattr(mod.time, "sleep", lambda *_a: None)

    class T:
        def __init__(self, *a, **k): pass
        def read_until(self, *a, **k): return b""
        def write(self, *a, **k): pass
        def expect(self, *a, **k): return (2, None, b"")
        def close(self): pass

    monkeypatch.setattr(mod.telnetlib, "Telnet", T)
    assert conn.attempt("10.0.0.5", "rööt", "pass") is False


# --- SQL -------------------------------------------------------------------

def _sql_returning(mod, monkeypatch, databases):
    class Cursor:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def execute(self, *a): pass
        def fetchall(self): return [(d,) for d in databases]

    class Conn:
        def cursor(self): return Cursor()
        def close(self): pass

    monkeypatch.setattr(mod.pymysql, "connect", lambda **k: Conn())


def test_sql_connect_returns_databases_on_success(monkeypatch):
    mod, conn = _bare("sql_connector", "SQLConnector")
    _sql_returning(mod, monkeypatch, ["information_schema", "payroll"])
    assert conn.attempt("10.0.0.5", "root", "toor") == ["information_schema", "payroll"]


def test_sql_attempt_stays_truthy_when_no_databases_are_visible(monkeypatch):
    """#12 asymmetry, and the reason attempt() returns `databases or True`. For SQL the *login* is
    the win, and the pre-#12 worker recorded the cracked credential even when the database list came
    back empty. Returning the bare list would turn that into a silent failed login — losing a valid
    credential. SMB is the opposite case (see below), so the two must not be unified."""
    mod, conn = _bare("sql_connector", "SQLConnector")
    _sql_returning(mod, monkeypatch, [])
    assert conn.attempt("10.0.0.5", "root", "toor") is True


def test_sql_connect_reports_failure_not_a_truthy_tuple(monkeypatch):
    """The dangerous shape: a falsy return on error is fine, but anything truthy would mark a wrong
    password as cracked and feed it to credential reuse."""
    mod, conn = _bare("sql_connector", "SQLConnector")

    def refuse(**_k):
        raise mod.pymysql.Error("access denied")

    monkeypatch.setattr(mod.pymysql, "connect", refuse)
    assert not conn.attempt("10.0.0.5", "root", "wrong")


def test_sql_result_rows_are_one_per_database():
    """5-column schema, no MAC/Hostname — and a truthy-but-listless outcome writes no rows at all
    while still counting as a success upstream."""
    _mod, conn = _bare("sql_connector", "SQLConnector")
    rows = conn.result_rows(["information_schema", "payroll"],
                            "10.0.0.5", "root", "toor", "", "", 3306)
    assert rows == [["10.0.0.5", "root", "toor", 3306, "information_schema"],
                    ["10.0.0.5", "root", "toor", 3306, "payroll"]]
    assert conn.result_rows(True, "10.0.0.5", "root", "toor", "", "", 3306) == []


# --- RDP -------------------------------------------------------------------

def test_rdp_connect_maps_exit_code_to_result(monkeypatch):
    mod, conn = _bare("rdp_connector", "RDPConnector")

    def popen_returning(code):
        class P:
            returncode = code
            def communicate(self, timeout=None): return (b"", b"")
        return lambda *a, **k: P()

    monkeypatch.setattr(mod.subprocess, "Popen", popen_returning(0))
    assert conn.attempt("10.0.0.5", "root", "toor") is True

    monkeypatch.setattr(mod.subprocess, "Popen", popen_returning(1))
    assert conn.attempt("10.0.0.5", "root", "wrong") is False


def test_rdp_connect_false_when_xfreerdp_is_missing(monkeypatch):
    """A box without xfreerdp must report 'no' rather than raising out of the worker thread."""
    mod, conn = _bare("rdp_connector", "RDPConnector")

    def missing(*_a, **_k):
        raise FileNotFoundError("xfreerdp")

    monkeypatch.setattr(mod.subprocess, "Popen", missing)
    assert conn.attempt("10.0.0.5", "root", "toor") is False


# --- SMB -------------------------------------------------------------------

def test_smb_connect_false_when_the_server_refuses(monkeypatch):
    mod, conn = _bare("smb_connector", "SMBConnector")

    class Refusing:
        def __init__(self, *a, **k): pass
        def connect(self, *a, **k): raise ConnectionRefusedError("refused")

    monkeypatch.setattr(mod, "SMBConnection", Refusing)
    assert not conn.attempt("10.0.0.5", "root", "wrong")


def test_smb_result_rows_are_one_per_share_and_drop_admin_shares():
    """The mirror of the SQL case: for SMB an empty share list is correctly falsy — credentials
    that open a session but read nothing are not a usable finding — so no `or True` here. 7-column
    schema, one row per readable share."""
    _mod, conn = _bare("smb_connector", "SMBConnector")
    rows = conn.result_rows(["public", "ADMIN$", "backups"],
                            "10.0.0.5", "root", "toor", "AA:BB", "host", 445)
    assert [r[3] for r in rows] == ["public", "backups"]
    assert rows[0] == ["AA:BB", "10.0.0.5", "host", "public", "root", "toor", 445]


def test_smbclient_l_parses_nothing_out_of_a_failed_run(monkeypatch):
    mod, conn = _bare("smb_connector", "SMBConnector")

    class P:
        returncode = 1
        def communicate(self): return (b"session setup failed: NT_STATUS_LOGON_FAILURE", b"")

    monkeypatch.setattr(mod, "Popen", lambda *a, **k: P())
    assert conn.smbclient_l("10.0.0.5", "root", "wrong") == []


# --- the worker must never leave the queue undrained --------------------------

import queue as _queue  # noqa: E402
import threading  # noqa: E402

WORKERS = [
    # #12 complete: all six now delegate worker/run_bruteforce to base_connector.BaseConnector,
    # so the method the worker calls is `attempt` everywhere. The arity column stays because the
    # queue item shape still differs — SQL carries no mac/hostname (QUEUE_HAS_MAC = False).
    ("ssh_connector", "SSHConnector", "attempt", 6),
    ("ftp_connector", "FTPConnector", "attempt", 6),
    ("smb_connector", "SMBConnector", "attempt", 6),
    ("telnet_connector", "TelnetConnector", "attempt", 6),
    ("sql_connector", "SQLConnector", "attempt", 4),
    ("rdp_connector", "RDPConnector", "attempt", 6),
]


def test_a_raising_connect_still_drains_the_queue(monkeypatch):
    """The hang the RDP fix uncovered, pinned for all six. If <proto>_connect raises, the worker
    used to die before task_done() and queue.join() then blocked forever, hanging the orchestrator.
    task_done() must run regardless, so queue.join() returns."""
    for module_name, class_name, connect_name, arity in WORKERS:
        mod, obj = _bare(module_name, class_name)
        obj.queue = _queue.Queue()
        obj.lock = threading.Lock()
        obj.results = []
        obj.shared_data = SimpleNamespace(orchestrator_should_exit=False)

        def boom(*_a, **_k):
            raise RuntimeError("binary missing / protocol blew up")

        monkeypatch.setattr(obj, connect_name, boom)
        # queue item shape differs: SQL has no mac/hostname column
        item = ("10.0.0.5", "root", "toor", 22) if arity == 4 \
            else ("10.0.0.5", "root", "toor", "AA:BB", "host", 22)
        obj.queue.put(item)

        progress = SimpleNamespace(update=lambda *a, **k: None)
        type(obj).worker(obj, progress, task_id=0, success_flag=[False])

        # If task_done() did not run, this join would hang the test rather than return.
        done = threading.Event()
        threading.Thread(target=lambda: (obj.queue.join(), done.set()), daemon=True).start()
        assert done.wait(timeout=2.0), f"{module_name}: queue.join() blocked — task_done() was skipped"


# --- #4: every external-network call must carry a wall-clock bound ------------

import ast  # noqa: E402

# (file, callee, {acceptable timeout kwargs}). Matched by the attribute/name being called,
# so a multiline call is fine (AST, not a line regex). Every establish/exec site below is a
# hang class the audit named: without a bound, one black-holed host wedges the single-threaded
# orchestrator — the "start scan freezes the Pi" symptom. This test fails if any of them loses
# its timeout in a refactor, which is exactly how the RDP path silently died once.
_TIMEOUT_SITES = [
    ("ssh_connector.py",       "connect",       {"timeout"}),
    ("smb_connector.py",       "connect",       {"timeout"}),
    ("telnet_connector.py",    "Telnet",        {"timeout"}),
    ("ftp_connector.py",       "connect",       {"timeout"}),
    ("sql_connector.py",       "connect",       {"connect_timeout"}),
    ("nmap_vuln_scanner.py",   "run",           {"timeout"}),
    ("steal_files_ssh.py",     "connect",       {"timeout"}),
    ("steal_files_smb.py",     "connect",       {"timeout"}),
    ("steal_files_ftp.py",     "connect",       {"timeout"}),
    ("steal_files_telnet.py",  "Telnet",        {"timeout"}),
    ("steal_data_sql.py",      "create_engine", {"connect_args"}),
]


def _callee(call):
    f = call.func
    if isinstance(f, ast.Attribute):
        return f.attr
    if isinstance(f, ast.Name):
        return f.id
    return None


def test_every_connect_path_carries_a_timeout():
    root = Path(__file__).resolve().parent.parent / "actions"
    for fname, callee, kwargs in _TIMEOUT_SITES:
        tree = ast.parse((root / fname).read_text(encoding="utf-8"))
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and _callee(n) == callee]
        assert calls, f"{fname}: no {callee}(...) call found — did the code move?"
        for c in calls:
            assert any(k.arg in kwargs for k in c.keywords), \
                f"{fname}: a {callee}(...) call is missing a {kwargs} bound"


def test_rdp_run_bruteforce_completes_on_a_real_run(monkeypatch):
    """RDP regression. run_bruteforce referenced mac_address/hostname in the queue-fill loop before
    they were assigned (they were resolved lower down, inside the `with Progress` block), so a real
    attack — orchestrator_should_exit=False — raised UnboundLocalError on the first candidate and
    the orchestrator marked every RDP host failed: the brute force never tried a credential. The
    connect tests all set orchestrator_should_exit=True and return before that line, which is why
    CI never saw it. This drives run_bruteforce end to end with a stubbed connect and asserts it
    returns cleanly instead of raising."""
    import base_connector
    _mod, conn = _bare("rdp_connector", "RDPConnector")
    conn.queue = _queue.Queue()
    conn.lock = threading.Lock()
    conn.results = []
    conn.shared_data = SimpleNamespace(orchestrator_should_exit=False, bruteforce_threads=1)
    conn.users, conn.passwords = ["root"], ["toor"]

    class _DummyProgress:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def add_task(self, *a, **k): return 0
        def update(self, *a, **k): pass

    # #12: run_bruteforce now lives in base_connector, so Progress/credential_candidates are
    # resolved there rather than in the protocol module.
    monkeypatch.setattr(base_connector, "Progress", lambda *a, **k: _DummyProgress())
    monkeypatch.setattr(base_connector, "credential_candidates",
                        lambda *a, **k: [("root", "toor"), ("admin", "admin")])
    monkeypatch.setattr(conn, "attempt", lambda *a, **k: False)

    row = {"MAC Address": "AA:BB:CC:DD:EE:FF", "Hostnames": "target"}
    success, results = conn.run_bruteforce("10.0.0.5", 3389, row=row)
    assert success is False and results == []


if __name__ == "__main__":
    import inspect
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn) and not inspect.signature(fn).parameters:
            fn()
    print("ok (fixture-free subset; run pytest for all)")
