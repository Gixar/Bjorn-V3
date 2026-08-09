"""Tests for the shared credential-reuse pool (backlog Wave 1 #2): record/read round-trip,
dedupe, candidate ordering (pool first), and the credential_reuse=False bypass. Uses a temp
crackedpwd dir + a tiny fake shared_data — no connectors, no network.
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from credential_pool import credential_candidates, record_cracked_cred, known_cred_pairs  # noqa: E402


class FakeSD:
    def __init__(self, crackedpwddir, reuse=True):
        self.crackedpwddir = crackedpwddir
        self.credential_reuse = reuse


def test_record_read_and_dedupe():
    with tempfile.TemporaryDirectory() as d:
        sd = FakeSD(d)
        assert known_cred_pairs(sd) == []
        record_cracked_cred(sd, "root", "toor")
        record_cracked_cred(sd, "root", "toor")   # duplicate — ignored
        record_cracked_cred(sd, "admin", "1234")
        assert known_cred_pairs(sd) == [("root", "toor"), ("admin", "1234")]


def test_candidates_pool_first_and_deduped():
    with tempfile.TemporaryDirectory() as d:
        sd = FakeSD(d)
        record_cracked_cred(sd, "root", "toor")
        record_cracked_cred(sd, "admin", "1234")
        cands = credential_candidates(sd, ["admin", "x"], ["1234", "y"])
        # cracked pool tried first, in order
        assert cands[:2] == [("root", "toor"), ("admin", "1234")]
        # ("admin","1234") also appears in the product but is not duplicated
        assert cands.count(("admin", "1234")) == 1
        # the rest of the product is still present
        assert ("x", "y") in cands and ("admin", "y") in cands


def test_disabled_returns_plain_product_and_records_nothing():
    with tempfile.TemporaryDirectory() as d:
        off = FakeSD(d, reuse=False)
        assert credential_candidates(off, ["a"], ["b1", "b2"]) == [("a", "b1"), ("a", "b2")]
        record_cracked_cred(off, "z", "z")            # no-op when disabled
        assert known_cred_pairs(FakeSD(d)) == []


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
