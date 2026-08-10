"""The six brute-force connectors must not re-read netkb.csv for data they were handed.

`run_bruteforce` opened and fully parsed `netkb.csv` on every call, to recover `MAC Address` and
`Hostnames` — two fields the orchestrator had *already* read that cycle and passed in as `row`
(`orchestrator.py:221`). With four host actions per cycle that was four full CSV parses per cycle
for nothing, on a device where the SD card is the bottleneck. `sql_connector` and `rdp_connector`
were worse: they parsed the file and then never looked at the result.

`row=None` still falls back to the old lookup, so the standalone `python actions/x_connector.py`
entry points keep working.
"""
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _stubs  # noqa: E402
_stubs.install()

CONNECTORS = [
    ("ssh_connector", "SSHConnector"),
    ("ftp_connector", "FTPConnector"),
    ("smb_connector", "SMBConnector"),
    ("telnet_connector", "TelnetConnector"),
    ("sql_connector", "SQLConnector"),
    ("rdp_connector", "RDPConnector"),
]

ROW = {"MAC Address": "AA:BB:CC:DD:EE:01", "IPs": "10.0.0.5", "Hostnames": "nas.local",
       "Ports": "22;445"}


def _connector(module_name, class_name, monkeypatch, reads):
    """A connector with __init__ bypassed and netkb reads counted."""
    import importlib
    mod = importlib.import_module(f"actions.{module_name}")
    obj = getattr(mod, class_name).__new__(getattr(mod, class_name))

    def counting_load(*_a, **_k):
        reads.append(module_name)
        obj.scan = []

    obj.load_scan_file = counting_load
    obj.shared_data = SimpleNamespace(orchestrator_should_exit=True, bruteforce_threads=1)
    obj.users, obj.passwords = ["root"], ["toor"]
    return mod, obj


def test_no_connector_reads_netkb_when_given_the_row(monkeypatch):
    """The property that matters: `row` supplied means zero CSV parses."""
    for module_name, class_name in CONNECTORS:
        reads = []
        mod, obj = _connector(module_name, class_name, monkeypatch, reads)
        # orchestrator_should_exit is True, so run_bruteforce bails right after the lookup —
        # enough to prove which path the lookup took without running a real attack.
        try:
            mod_cls = type(obj)
            mod_cls.run_bruteforce(obj, "10.0.0.5", 22, ROW)
        except Exception:
            pass  # the attack machinery is not what is under test here
        assert reads == [], f"{module_name} still re-read netkb despite being handed the row"


def test_every_connector_accepts_the_row_argument():
    """A signature guard: if one connector is missed, the orchestrator's call would TypeError at
    runtime on that protocol only — the kind of gap that shows up on hardware, not in review."""
    import importlib
    import inspect
    for module_name, class_name in CONNECTORS:
        mod = importlib.import_module(f"actions.{module_name}")
        sig = inspect.signature(getattr(mod, class_name).run_bruteforce)
        assert "row" in sig.parameters, f"{module_name}.run_bruteforce has no row parameter"
        assert sig.parameters["row"].default is None, f"{module_name} must keep row optional"

        # ...and the two wrappers above it must pass it down, or the fast path never triggers.
        src = (Path(__file__).resolve().parent.parent / "actions" / f"{module_name}.py").read_text(
            encoding="utf-8")
        proto = module_name.replace("_connector", "")
        assert f"self.bruteforce_{proto}(ip, port, row)" in src, f"{module_name}: execute drops row"
        assert f"run_bruteforce(ip, port, row)" in src, f"{module_name}: wrapper drops row"


def test_the_fallback_still_works_for_the_standalone_entry_points(monkeypatch):
    """`python actions/ssh_connector.py` calls run_bruteforce with no row; that path must still
    look the host up in netkb rather than silently attacking with empty identifiers."""
    reads = []
    mod, obj = _connector("ssh_connector", "SSHConnector", monkeypatch, reads)
    try:
        type(obj).run_bruteforce(obj, "10.0.0.5", 22)
    except Exception:
        pass
    assert reads == ["ssh_connector"], "the row=None path must still consult netkb"


if __name__ == "__main__":
    import inspect
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn) and not inspect.signature(fn).parameters:
            fn()
    print("ok (fixture-free subset; run pytest for all)")
