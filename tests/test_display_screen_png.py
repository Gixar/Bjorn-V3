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


if __name__ == "__main__":
    import inspect
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn) and not inspect.signature(fn).parameters:
            fn()
    print("ok (fixture-free subset; run pytest for all)")
