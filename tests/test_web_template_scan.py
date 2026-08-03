"""Tests for nuclei-style web template matching (backlog Wave 2): the pure `_matches` logic
(status any-of + body_contains any-of, both required when specified). No network. Heavy imports
stubbed via _stubs.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _stubs  # noqa: E402
_stubs.install()

from actions.web_template_scan import WebTemplateScan  # noqa: E402

m = WebTemplateScan._matches


def test_status_and_body_both_required():
    matchers = {"status": [200], "body_contains": ["[core]"]}
    assert m(matchers, 200, "...[core]...") is True
    assert m(matchers, 404, "[core]") is False       # wrong status
    assert m(matchers, 200, "no marker") is False     # body missing


def test_body_contains_is_any_of():
    matchers = {"body_contains": ["APP_", "DB_", "SECRET"]}
    assert m(matchers, 200, "DB_HOST=x") is True       # one of them is enough
    assert m(matchers, 200, "nothing here") is False


def test_status_is_any_of():
    assert m({"status": [200, 204, 301]}, 301, "") is True
    assert m({"status": [200]}, 500, "") is False


def test_no_matchers_is_vacuously_true():
    assert m({}, 200, "") is True


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
