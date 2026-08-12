"""#13: the unauthenticated web UI must not read or write files outside its intended dirs.

Three live holes this locks down:
  - download_file / download_backup os.path.join'd a user path onto a base dir with no
    containment check → `?path=../../etc/passwd` (or an absolute path) escaped and read
    arbitrary files.
  - restore's extractall() honoured `..`/absolute zip members → zip-slip wrote anywhere.

path_safety is stdlib-only and standalone (utils.py needs starlette/fastapi and can't import in
the zero-install test env), so these run under pytest and as `python tests/test_path_safety.py`.
"""
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from path_safety import safe_under, zip_escapes  # noqa: E402


def test_safe_under_allows_a_real_child():
    with tempfile.TemporaryDirectory() as base:
        child = os.path.join(base, "loot", "a.txt")
        os.makedirs(os.path.dirname(child), exist_ok=True)
        open(child, "w").close()
        assert safe_under(base, "loot/a.txt") == os.path.realpath(child)


def test_safe_under_blocks_dotdot_traversal():
    with tempfile.TemporaryDirectory() as base:
        assert safe_under(base, "../../etc/passwd") is None
        assert safe_under(base, "loot/../../../../etc/passwd") is None


def test_safe_under_blocks_absolute_path_escape():
    """os.path.join drops the base when the second arg is absolute — the classic bypass."""
    with tempfile.TemporaryDirectory() as base:
        outside = os.path.abspath(os.sep + "etc")
        assert safe_under(base, outside) is None


def test_zip_escapes_passes_safe_members():
    with tempfile.TemporaryDirectory() as dest:
        assert zip_escapes(["config/shared_config.json", "data/netkb.csv"], dest) is None


def test_zip_escapes_flags_dotdot_and_absolute_members():
    with tempfile.TemporaryDirectory() as dest:
        assert zip_escapes(["../evil"], dest) == "../evil"
        assert zip_escapes(["ok.txt", "sub/../../evil"], dest) == "sub/../../evil"
        assert zip_escapes(["good/a", os.sep + "etc/passwd"], dest) is not None


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
