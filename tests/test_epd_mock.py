"""Tests for the mock e-Paper backend + EPDHelper wiring (PRD §9 step 3 / P1-3).
EPDHelper imports only stdlib, so this runs with zero heavy deps — under pytest and as
`python tests/test_epd_mock.py`.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from epd_helper import EPDHelper  # noqa: E402


class _SaveLessImage:
    """Stand-in for a device buffer with no .save(), so display() takes the no-op path
    (no file written)."""


def test_mock_lifecycle_no_exceptions():
    epd = EPDHelper("epdmock")
    epd.init_full_update()
    epd.init_partial_update()
    epd.clear()
    epd.display_partial(_SaveLessImage())  # getbuffer -> displayPartial -> display (no-op)
    assert epd.epd.width == 122
    assert epd.epd.height == 250


def test_mock_getbuffer_passthrough():
    epd = EPDHelper("epdmock")
    sentinel = _SaveLessImage()
    assert epd.epd.getbuffer(sentinel) is sentinel


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
