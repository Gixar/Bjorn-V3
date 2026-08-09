"""Inject fake heavy/hardware modules into sys.modules so import-coupled modules
(e.g. actions/ssh_connector.py) can be imported and their pure logic unit-tested on a
box without pandas / paramiko / rich / PIL installed. Import-time only — call install()
before importing the module under test.
"""
import socket
import sys
import types


class _FakeLogger:
    def __init__(self, *a, **k):
        pass

    def __getattr__(self, _name):
        return lambda *a, **k: None


def install():
    """Idempotently install stubs. Returns the fake paramiko module so tests can drive it."""
    if "pandas" not in sys.modules:
        pandas = types.ModuleType("pandas")
        pandas.read_csv = lambda *a, **k: None
        pandas.DataFrame = lambda *a, **k: None
        sys.modules["pandas"] = pandas

    if "rich" not in sys.modules:
        rich = types.ModuleType("rich")
        console = types.ModuleType("rich.console")
        console.Console = type("Console", (), {"__init__": lambda self, *a, **k: None})
        progress = types.ModuleType("rich.progress")
        for cls in ("Progress", "BarColumn", "TextColumn", "SpinnerColumn"):
            setattr(progress, cls, type(cls, (), {"__init__": lambda self, *a, **k: None}))
        table = types.ModuleType("rich.table")
        table.Table = type("Table", (), {"__init__": lambda self, *a, **k: None})
        text = types.ModuleType("rich.text")
        text.Text = type("Text", (), {"__init__": lambda self, *a, **k: None})
        rich.console = console
        rich.progress = progress
        rich.table = table
        rich.text = text
        sys.modules["rich"] = rich
        sys.modules["rich.console"] = console
        sys.modules["rich.progress"] = progress
        sys.modules["rich.table"] = table
        sys.modules["rich.text"] = text

    if "netifaces" not in sys.modules:
        netifaces = types.ModuleType("netifaces")
        netifaces.AF_INET = 2
        netifaces.interfaces = lambda: []
        netifaces.ifaddresses = lambda _iface: {}
        sys.modules["netifaces"] = netifaces

    if "PIL" not in sys.modules:
        # Only needs to satisfy `from PIL import Image, ImageFont` at import time — tests that
        # import shared.py for its config/CSV logic never draw anything.
        pil = types.ModuleType("PIL")
        for name in ("Image", "ImageFont", "ImageDraw"):
            sub = types.ModuleType(f"PIL.{name}")
            setattr(pil, name, sub)
            sys.modules[f"PIL.{name}"] = sub
        sys.modules["PIL"] = pil

    if "getmac" not in sys.modules:
        getmac = types.ModuleType("getmac")
        getmac.get_mac_address = lambda *a, **k: None
        sys.modules["getmac"] = getmac

    if "nmap" not in sys.modules:
        nmap = types.ModuleType("nmap")
        nmap.PortScanner = type("PortScanner", (), {"__init__": lambda self, *a, **k: None})
        sys.modules["nmap"] = nmap

    if "shared" not in sys.modules:
        shared = types.ModuleType("shared")
        shared.SharedData = type("SharedData", (), {})
        # Module-level helpers the connectors import from `shared`. The credential-pool ones are
        # pure/importable, so re-export the real functions; the CSV helpers live in shared.py (which
        # pulls in PIL) so stub them — tests that exercise a connector's pure logic don't call them.
        from credential_pool import credential_candidates, record_cracked_cred, known_cred_pairs
        shared.credential_candidates = credential_candidates
        shared.record_cracked_cred = record_cracked_cred
        shared.known_cred_pairs = known_cred_pairs
        shared.netkb_targets = lambda *a, **k: []
        shared.append_csv_rows = lambda *a, **k: None
        shared.dedupe_csv = lambda *a, **k: None
        sys.modules["shared"] = shared

    if "logger" not in sys.modules:
        logger_mod = types.ModuleType("logger")
        logger_mod.Logger = _FakeLogger
        sys.modules["logger"] = logger_mod

    if "paramiko" not in sys.modules:
        paramiko = types.ModuleType("paramiko")

        class AuthenticationException(Exception):
            pass

        class SSHException(Exception):
            pass

        class AutoAddPolicy:
            pass

        class SSHClient:
            def set_missing_host_key_policy(self, policy):
                pass

            def connect(self, *a, **k):
                behavior = sys.modules["paramiko"]._connect_raises
                if behavior is not None:
                    raise behavior
                return True

            def close(self):
                pass

        paramiko.AuthenticationException = AuthenticationException
        paramiko.SSHException = SSHException
        paramiko.AutoAddPolicy = AutoAddPolicy
        paramiko.SSHClient = SSHClient
        paramiko._connect_raises = None  # test sets this to an exception instance to simulate failure
        paramiko.socket_error = socket.error
        sys.modules["paramiko"] = paramiko

    return sys.modules["paramiko"]
