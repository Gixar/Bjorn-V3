"""The panel-settle pause that seven attack actions take before doing work.

Each of them used to hardcode `time.sleep(5)` with the comment "too fast to see the status
change". Five seconds was never measured: the display loop renders, refreshes the panel twice and
sleeps `screen_delay` (default 1s), so two iterations — about 2-3s — is the actual requirement.
At four host actions per cycle the old number spent 20s of every working cycle asleep, which on a
Pi Zero is throughput rather than comfort.

These tests pin the two properties that matter: it tracks the display's cadence, and it can never
be made worse than the number it replaced.
"""
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _stubs  # noqa: E402
_stubs.install()

from shared import status_settle_seconds  # noqa: E402


def test_default_config_is_faster_than_the_five_seconds_it_replaced():
    """screen_delay defaults to 1, so the wait is 2s — the panel has time for two full refresh
    iterations, and the action starts 3s sooner than it used to."""
    assert status_settle_seconds(SimpleNamespace(screen_delay=1)) == 2.0


def test_it_tracks_the_display_cadence():
    """A slower panel needs a longer pause, or the sleep stops doing the one job it has."""
    assert status_settle_seconds(SimpleNamespace(screen_delay=2)) == 4.0
    assert status_settle_seconds(SimpleNamespace(screen_delay=0.5)) == 1.0


def test_it_can_never_be_worse_than_the_old_hardcoded_five():
    """Capped: a large screen_delay must not turn every action into a minute of waiting."""
    assert status_settle_seconds(SimpleNamespace(screen_delay=30)) == 5.0


def test_it_never_becomes_zero():
    """Floored: a 0 or missing screen_delay would remove the pause entirely and the status would
    flick past unread — losing the behaviour these sleeps exist for."""
    assert status_settle_seconds(SimpleNamespace(screen_delay=0)) == 1.0
    assert status_settle_seconds(SimpleNamespace()) == 2.0
    assert status_settle_seconds(SimpleNamespace(screen_delay=None)) == 2.0


def test_every_action_that_paused_still_pauses():
    """The point was to make the wait right, not to delete it. If a future edit drops the call
    from one of these files, the status it sets becomes unreadable on the panel."""
    import re
    repo = Path(__file__).resolve().parent.parent
    # #12: a connector that delegates to BaseBruteforce settles in the base's execute(), not its
    # own file. Verify the base carries the call once, then skip the per-file check for delegators.
    for base_name in ("base_connector.py", "base_stealer.py"):
        base = (repo / base_name).read_text(encoding="utf-8")
        assert "settle_for_display(self.shared_data)" in base, f"{base_name} no longer settles"
    expected = ["ftp_connector", "steal_data_sql", "steal_files_ftp", "steal_files_rdp",
                "steal_files_smb", "steal_files_ssh", "steal_files_telnet"]
    root = repo / "actions"
    for name in expected:
        src = (root / f"{name}.py").read_text(encoding="utf-8")
        if "from base_connector import" in src or "from base_stealer import" in src:
            continue  # delegates — settle verified on the base above
        assert "settle_for_display(self.shared_data)" in src, f"{name} no longer settles"
        assert re.search(r"from shared import [^\n]*settle_for_display", src), f"{name} missing import"
        assert "time.sleep(5)" not in src, f"{name} still has the hardcoded sleep"


def test_a_status_without_artwork_is_not_logged_as_a_warning():
    """Most actions have no e-paper artwork and never will, so falling back to the IDLE image is
    the designed behaviour, not a fault. It was logged as a problem twice over: once per frame at
    lookup time (throttled to once per key, but still WARNING), and once per missing .bmp at load
    time — eight lines every boot. Neither is actionable.

    load_image() is shared with the static chrome (bjorn1.bmp, wifi.bmp, ...), where a missing file
    really does break the UI, so the level is the caller's decision rather than a blanket lowering.

    Read from source rather than imported: _stubs replaces the whole `shared` module with a fake,
    because the real one pulls in PIL and the e-Paper stack."""
    src = (Path(__file__).resolve().parent.parent / "shared.py").read_text(encoding="utf-8")

    def method_body(name):
        body = src[src.index("    def " + name):]
        return body[:body.index("    def ", 5)]

    note = method_body("_note_missing_image_once(self")
    assert "logger.info(" in note, "the note must still be logged, just not as a problem"
    assert "logger.warning(" not in note, \
        "a status with no artwork is normal; warning about it is noise nobody can action"
    assert "_status_image_warned" in note, "the once-per-key throttle must stay"

    loader = method_body("load_image(self, image_path")   # not load_images(), the plural one
    # Asserted on the code, not the prose: an earlier version of this test was satisfied by the
    # word "optional" appearing in the docstring, and passed with the switch itself deleted.
    assert "def load_image(self, image_path, optional=False)" in src,         "the caller needs a way to say this artwork is optional"
    assert "logger.info if optional else logger.warning" in loader,         "the level is the caller's decision: optional artwork notes, missing chrome warns"
    assert "self.load_image(image_path, optional=True)" in src, \
        "the per-action status artwork is the optional caller"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
