"""The five steal_files_* / steal_data_sql modules — Stage 1 behaviour, locked in.

These are long-lived singletons the orchestrator builds once. Two fixes from the correctness pass
need regression cover, because both are the kind that pass a casual read and fail only after the
device has been running a while:

  - execute() resets self.stop_execution at the top. It used to latch: once the 240s timeout fired
    for ANY host, every later steal on every host returned 'failed' until restart.
  - a not-yet-successful parent returns 'failed' (steal_files_ftp previously fell off the end
    returning None; the orchestrator wrote failed_<ts> only by accident).
"""
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _stubs  # noqa: E402
_stubs.install()

MODULES = [
    ("steal_files_ssh", "StealFilesSSH", "SSHBruteforce", "connect_ssh"),
    ("steal_files_smb", "StealFilesSMB", "SMBBruteforce", "connect_smb"),
    ("steal_files_ftp", "StealFilesFTP", "FTPBruteforce", "connect_ftp"),
    ("steal_files_rdp", "StealFilesRDP", "RDPBruteforce", "connect_rdp"),
    ("steal_files_telnet", "StealFilesTelnet", "TelnetBruteforce", "connect_telnet"),
    ("steal_data_sql", "StealDataSQL", "SQLBruteforce", "connect_sql"),
]


def _steal(module_name, class_name, monkeypatch):
    import importlib
    mod = importlib.import_module(f"actions.{module_name}")
    # every module imports settle_for_display from shared; skip its ~2s sleep
    if hasattr(mod, "settle_for_display"):
        monkeypatch.setattr(mod, "settle_for_display", lambda *_a, **_k: None)
    obj = getattr(mod, class_name).__new__(getattr(mod, class_name))
    obj.b_parent_action = None  # set per-test
    return mod, obj


def test_a_not_yet_successful_parent_returns_failed(monkeypatch):
    """No module may fall off the end returning None on the parent check — that was the ftp bug,
    right by accident because the orchestrator writes failed_<ts> for a None return. And all five
    must agree: steal_data_sql used to return 'skipped', the odd one out."""
    for module_name, class_name, parent, _connect in MODULES:
        _mod, obj = _steal(module_name, class_name, monkeypatch)
        obj.b_parent_action = parent
        row = {parent: "", "IPs": "10.0.0.5", "MAC Address": "AA:BB"}  # parent never succeeded
        result = obj.execute("10.0.0.5", 22, row, "status")
        assert result == 'failed', f"{module_name} returned {result!r} for an unsuccessful parent"


def test_execute_resets_the_latch(monkeypatch, tmp_path):
    """stop_execution must be cleared at the top of execute(). Simulate a prior run having latched
    it True, then run against a host with no cracked credentials: the reset happens, then it exits
    'failed' for lack of creds — proving the reset ran without needing a live steal."""
    for module_name, class_name, parent, connect in MODULES:
        mod, obj = _steal(module_name, class_name, monkeypatch)
        obj.b_parent_action = parent
        obj.stop_execution = True  # latched by an earlier host's timeout

        # Keep the anonymous-access fallback (ftp/smb) off the network: without this the test made
        # a real connect to 10.0.0.5 and waited out the TCP timeout.
        monkeypatch.setattr(obj, connect, lambda *_a, **_k: None, raising=False)

        # point every cracked-creds file at an empty path so execute() exits early, after the reset
        obj.shared_data = SimpleNamespace(
            bjornorch_status="", orchestrator_should_exit=False,
            sshfile=str(tmp_path / "none.csv"), smbfile=str(tmp_path / "none.csv"),
            ftpfile=str(tmp_path / "none.csv"), rdpfile=str(tmp_path / "none.csv"),
            telnetfile=str(tmp_path / "none.csv"), sqlfile=str(tmp_path / "none.csv"))
        row = {parent: "success_20260101_000000", "IPs": "10.0.0.5", "MAC Address": "AA:BB"}
        obj.execute("10.0.0.5", 22, row, "status")
        assert obj.stop_execution is False, f"{module_name} did not reset stop_execution"


def test_the_reset_is_present_in_source_for_every_module():
    """Belt-and-braces on the behavioural test above: the reset line must sit inside execute(),
    so a refactor that drops it is caught even if the early-exit path changes."""
    root = Path(__file__).resolve().parent.parent / "actions"
    for module_name, _class, _parent, _connect in MODULES:
        src = (root / f"{module_name}.py").read_text(encoding="utf-8")
        exec_body = src.split("def execute(")[1]
        assert "self.stop_execution = False" in exec_body, f"{module_name}: no reset in execute()"


class _FakeTelnet:
    """Minimal login-shell simulator for the telnet transfer path.

    A real shell echoes the command line back verbatim *before* running it — that echo
    contains the split `__BJORN''_B64_...` markers, which is exactly what broke the naive
    read_until (it matched the echo, not the output). This fake reproduces that ordering
    so the echo-proofing is actually under test, and encodes real bytes with base64 so the
    binary-safe / `$`-in-content fix is exercised too.
    """
    def __init__(self, files):
        self.files = files          # {remote_path: bytes}
        self.buf = b""

    def write(self, data):
        import re, base64 as _b64
        line = data.decode('ascii')
        self.buf += data.replace(b"\n", b"\r\n")   # the shell echoes the command line
        payload = b""
        m = re.search(r"base64 '([^']*)'", line)
        if m:
            payload = _b64.b64encode(self.files.get(m.group(1), b"")) + b"\n"
        # output of: echo BEGIN; base64 ...; echo END   (contiguous markers, then a prompt)
        self.buf += b"__BJORN_B64_BEGIN__\r\n" + payload + b"__BJORN_B64_END__\r\n$ "

    def read_until(self, marker, timeout=None):
        idx = self.buf.find(marker)
        if idx == -1:
            out, self.buf = self.buf, b""
            return out
        end = idx + len(marker)
        out, self.buf = self.buf[:end], self.buf[end:]
        return out


def test_telnet_download_is_binary_safe_and_echo_proof(tmp_path, monkeypatch):
    """The held bug: `cat file` + read_until(b"$") truncated at the first `$` and corrupted
    binaries. The base64+marker transfer must round-trip every byte, survive `$` in the
    payload, and not latch onto the marker echoed in the command line."""
    _mod, obj = _steal("steal_files_telnet", "StealFilesTelnet", monkeypatch)
    obj.shared_data = SimpleNamespace(orchestrator_should_exit=False)
    content = bytes(range(256)) + b"\ncontains a $ and $HOME and a trailing prompt $ "
    remote = "/etc/shadow.bin"
    tn = _FakeTelnet({remote: content})
    obj.steal_file(tn, remote, str(tmp_path))
    written = (tmp_path / "etc" / "shadow.bin").read_bytes()
    assert written == content, "telnet download did not round-trip the file bytes"


class _LoopingSMB:
    """A share where every directory contains exactly one subdirectory — an infinite tree.
    Without the depth cap, find_files recurses forever and wedges the worker (#6)."""
    def __init__(self):
        self.calls = 0

    def listPath(self, share, path):
        self.calls += 1
        return [SimpleNamespace(isDirectory=True, filename="loop")]


def test_smb_find_files_bounds_an_infinite_tree(monkeypatch):
    """#6: cyclic/deep directory trees must not recurse forever. The depth cap is the backstop
    (a symlink loop grows the path each level, so the visited-set alone won't catch it)."""
    mod, obj = _steal("steal_files_smb", "StealFilesSMB", monkeypatch)
    obj.shared_data = SimpleNamespace(orchestrator_should_exit=False,
                                      steal_file_extensions=[], steal_file_names=[])
    conn = _LoopingSMB()
    files = obj.find_files(conn, "share", "/")  # must RETURN, not hang
    assert files == []
    # depth 0..MAX_DEPTH each list once, then depth MAX_DEPTH+1 returns before listing
    assert conn.calls == mod.MAX_DEPTH + 1, f"recursion not bounded: {conn.calls} listPath calls"


if __name__ == "__main__":
    import inspect
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn) and not inspect.signature(fn).parameters:
            fn()
    print("ok (fixture-free subset; run pytest for all)")
