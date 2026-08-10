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
    assert conn.ftp_connect("10.0.0.5", "root", "toor") is True

    for boom in (socket.error("refused"), OSError("no route"), Exception("530 denied")):
        class BadFTP:
            def __init__(self, _e=boom): self._e = _e
            def connect(self, *a, **k): raise self._e
            def login(self, *a, **k): pass
            def quit(self): pass
        monkeypatch.setattr(mod, "FTP", BadFTP)
        assert conn.ftp_connect("10.0.0.5", "root", "wrong") is False, boom


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
        assert conn.telnet_connect("10.0.0.5", "root", "toor") is True, shell_index

    for reject_index in (0, 1, -1):
        monkeypatch.setattr(mod.telnetlib, "Telnet", telnet_returning(reject_index))
        assert conn.telnet_connect("10.0.0.5", "root", "toor") is False, reject_index


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
    assert conn.telnet_connect("10.0.0.5", "rööt", "pass") is False


# --- SQL -------------------------------------------------------------------

def test_sql_connect_returns_databases_on_success(monkeypatch):
    mod, conn = _bare("sql_connector", "SQLConnector")

    class Cursor:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def execute(self, *a): pass
        def fetchall(self): return [("information_schema",), ("payroll",)]

    class Conn:
        def cursor(self): return Cursor()
        def close(self): pass

    monkeypatch.setattr(mod.pymysql, "connect", lambda **k: Conn())
    ok, databases = conn.sql_connect("10.0.0.5", "root", "toor")
    assert ok is True and databases == ["information_schema", "payroll"]


def test_sql_connect_reports_failure_not_a_truthy_tuple(monkeypatch):
    """The dangerous shape: returning `(False, [])` is fine, but any truthy first element on an
    error would mark a wrong password as cracked and feed it to credential reuse."""
    mod, conn = _bare("sql_connector", "SQLConnector")

    def refuse(**_k):
        raise mod.pymysql.Error("access denied")

    monkeypatch.setattr(mod.pymysql, "connect", refuse)
    result = conn.sql_connect("10.0.0.5", "root", "wrong")
    ok = result[0] if isinstance(result, tuple) else result
    assert not ok


# --- RDP -------------------------------------------------------------------

def test_rdp_connect_maps_exit_code_to_result(monkeypatch):
    mod, conn = _bare("rdp_connector", "RDPConnector")

    def popen_returning(code):
        class P:
            returncode = code
            def communicate(self): return (b"", b"")
        return lambda *a, **k: P()

    monkeypatch.setattr(mod.subprocess, "Popen", popen_returning(0))
    assert conn.rdp_connect("10.0.0.5", "root", "toor") is True

    monkeypatch.setattr(mod.subprocess, "Popen", popen_returning(1))
    assert conn.rdp_connect("10.0.0.5", "root", "wrong") is False


def test_rdp_connect_false_when_xfreerdp_is_missing(monkeypatch):
    """A box without xfreerdp must report 'no' rather than raising out of the worker thread."""
    mod, conn = _bare("rdp_connector", "RDPConnector")

    def missing(*_a, **_k):
        raise FileNotFoundError("xfreerdp")

    monkeypatch.setattr(mod.subprocess, "Popen", missing)
    assert conn.rdp_connect("10.0.0.5", "root", "toor") is False


# --- SMB -------------------------------------------------------------------

def test_smb_connect_false_when_the_server_refuses(monkeypatch):
    mod, conn = _bare("smb_connector", "SMBConnector")

    class Refusing:
        def __init__(self, *a, **k): pass
        def connect(self, *a, **k): raise ConnectionRefusedError("refused")

    monkeypatch.setattr(mod, "SMBConnection", Refusing)
    assert not conn.smb_connect("10.0.0.5", "root", "wrong")


def test_smbclient_l_parses_nothing_out_of_a_failed_run(monkeypatch):
    mod, conn = _bare("smb_connector", "SMBConnector")

    class P:
        returncode = 1
        def communicate(self): return (b"session setup failed: NT_STATUS_LOGON_FAILURE", b"")

    monkeypatch.setattr(mod, "Popen", lambda *a, **k: P())
    assert conn.smbclient_l("10.0.0.5", "root", "wrong") == []


if __name__ == "__main__":
    import inspect
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn) and not inspect.signature(fn).parameters:
            fn()
    print("ok (fixture-free subset; run pytest for all)")
