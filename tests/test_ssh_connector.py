"""Test one connector path with a mocked service (PRD §9 step 5 / P1-4): SSHConnector.attempt
returns True on a successful paramiko connect and False on auth/socket/SSH errors.

ssh_connector imports pandas/paramiko/rich/shared(->PIL) at module load, so _stubs.install()
fakes those before import. Runs under pytest and as `python tests/test_ssh_connector.py`.
"""
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _stubs  # noqa: E402

paramiko = _stubs.install()
from actions.ssh_connector import SSHConnector  # noqa: E402


def _connector():
    # Bypass __init__ (it reads CSV/dictionary files); attempt only touches paramiko.
    return SSHConnector.__new__(SSHConnector)


def test_successful_connect_returns_true():
    paramiko._connect_raises = None
    assert _connector().attempt("10.0.0.5", "root", "toor") is True


def test_auth_failure_returns_false():
    paramiko._connect_raises = paramiko.AuthenticationException("bad creds")
    assert _connector().attempt("10.0.0.5", "root", "wrong") is False


def test_socket_error_returns_false():
    paramiko._connect_raises = socket.error("host unreachable")
    assert _connector().attempt("10.0.0.5", "root", "toor") is False


def test_ssh_exception_returns_false():
    paramiko._connect_raises = paramiko.SSHException("protocol error")
    assert _connector().attempt("10.0.0.5", "root", "toor") is False


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
