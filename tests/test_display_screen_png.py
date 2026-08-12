"""The display must not write screen.png when nothing changed.

The render loop PNG-encoded the frame and `fsync()`d it to the SD card on every iteration — once a
second by default, ~86,000 forced writes a day, whether or not a single pixel differed. On a Pi
Zero the SD card is the component that dies first, and this was the largest single source of wear
in the process.

No PIL here: `_stubs` fakes it, and `_write_screen_png` only ever calls `image.save(buf, format=)`,
so a fake image exercises the encode/compare/skip logic exactly as a real one would.
"""
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _stubs  # noqa: E402
_stubs.install()

import display as display_mod  # noqa: E402


class FakeImage:
    """Encodes to whatever bytes it was given — the payload is what the code compares."""

    def __init__(self, payload):
        self.payload = payload

    def save(self, fp, format=None):  # noqa: A002 - matches PIL's signature
        fp.write(self.payload)


def _display(tmp_path):
    obj = display_mod.Display.__new__(display_mod.Display)
    obj.shared_data = SimpleNamespace(webdir=str(tmp_path))
    obj._last_screen_png = None
    return obj


def _stamp(path):
    st = path.stat()
    return st.st_mtime_ns, st.st_size


def test_an_unchanged_frame_costs_no_write(tmp_path):
    obj = _display(tmp_path)
    png = tmp_path / "screen.png"

    obj._write_screen_png(FakeImage(b"frame-one"))
    assert png.exists(), "the first frame must be written"
    before = _stamp(png)

    obj._write_screen_png(FakeImage(b"frame-one"))
    assert _stamp(png) == before, "an identical frame was written again — the SD wear is back"


def test_a_changed_frame_is_written(tmp_path):
    obj = _display(tmp_path)
    png = tmp_path / "screen.png"
    obj._write_screen_png(FakeImage(b"frame-one"))
    obj._write_screen_png(FakeImage(b"frame-two"))
    assert png.read_bytes() == b"frame-two", "a changed frame must reach the disk"


def test_it_alternates_correctly_rather_than_latching(tmp_path):
    """Guards the obvious wrong fix — writing once and never again."""
    obj = _display(tmp_path)
    png = tmp_path / "screen.png"
    for payload in (b"a", b"a", b"b", b"b", b"a"):
        obj._write_screen_png(FakeImage(payload))
    assert png.read_bytes() == b"a"


def test_the_web_ui_gets_a_file_on_the_very_first_frame(tmp_path):
    """Skipping writes must not mean /screen.png 404s until something changes."""
    obj = _display(tmp_path)
    obj._write_screen_png(FakeImage(b"first"))
    assert (tmp_path / "screen.png").read_bytes() == b"first"


# --- #10: the EPD panel write must be change-gated, drawn once, and refreshed periodically ---

class _FrameImage:
    """A frame whose identity is its bytes — what _display_frame compares via tobytes()."""

    def __init__(self, payload):
        self.payload = payload

    def tobytes(self):
        return self.payload


class _RecordingEPD:
    """Counts panel calls so a test can prove the double-write is gone and skips happen."""

    def __init__(self):
        self.partial = self.full = self.init_partial = self.init_full = 0

    def init_partial_update(self):
        self.init_partial += 1

    def init_full_update(self):
        self.init_full += 1

    def display_partial(self, image):
        self.partial += 1

    def display_full(self, image):
        self.full += 1


def _frame_display():
    obj = display_mod.Display.__new__(display_mod.Display)
    obj.epd_helper = _RecordingEPD()
    obj._last_epd_frame = None
    obj._frame_count = 0
    return obj


def test_identical_frames_cost_one_full_refresh_then_no_panel_writes():
    """The old loop wrote the panel twice every tick regardless of change. Now: frame 0 is the
    anti-ghosting full refresh, and identical frames after it must skip the panel entirely."""
    obj = _frame_display()
    for _ in range(5):
        obj._display_frame(_FrameImage(b"same"))
    assert obj.epd_helper.full == 1, "frame 0 must be the full refresh"
    assert obj.epd_helper.partial == 0, "identical frames must skip the panel write"


def test_a_changed_frame_triggers_exactly_one_partial_write():
    """Once, not twice (the duplicate display_partial is gone), and partial mode is re-inited."""
    obj = _frame_display()
    obj._display_frame(_FrameImage(b"a"))   # frame 0 -> full refresh
    obj._display_frame(_FrameImage(b"b"))   # frame 1 -> changed -> one partial write
    assert obj.epd_helper.full == 1 and obj.epd_helper.partial == 1
    assert obj.epd_helper.init_partial == 1, "a partial write must re-init partial mode"


def test_periodic_full_refresh_fires_even_on_an_unchanged_frame():
    """Ghosting must be cleared on a cadence even when the frame never changes."""
    obj = _frame_display()
    n = display_mod.FULL_REFRESH_EVERY_FRAMES
    for _ in range(n + 1):
        obj._display_frame(_FrameImage(b"same"))
    assert obj.epd_helper.full == 2, "a full refresh must fire every N frames (frame 0 and frame N)"
    assert obj.epd_helper.partial == 0


if __name__ == "__main__":
    import inspect
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn) and not inspect.signature(fn).parameters:
            fn()
    print("ok (fixture-free subset; run pytest for all)")
