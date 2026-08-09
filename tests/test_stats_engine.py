"""Tests for the coins/stats engine (backlog Wave 1 #3): monotonic high-water marks (score never
drops), persistence across "restarts", the rising level curve, and first-run seeding. Pure stdlib
module — no SharedData, no PIL. Runs under pytest and as `python tests/test_stats_engine.py`.
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import stats_engine as se  # noqa: E402


def _counts(hosts=0, creds=0, data=0, zombies=0, attacks=0, vulns=0):
    return {"hosts": hosts, "creds": creds, "data": data,
            "zombies": zombies, "attacks": attacks, "vulns": vulns}


def test_coins_never_drop_when_counts_fall():
    with tempfile.TemporaryDirectory() as d:
        p = str(Path(d) / "stats.json")
        r1 = se.update(p, _counts(hosts=9, creds=2))          # 9*1 + 2*25 = 59
        assert r1["coins"] == 59
        r2 = se.update(p, _counts(hosts=0, creds=0))          # counts cleared...
        assert r2["coins"] == 59                              # ...score holds (monotonic)


def test_persists_across_restart():
    with tempfile.TemporaryDirectory() as d:
        p = str(Path(d) / "stats.json")
        se.update(p, _counts(creds=3, data=1))                # 3*25 + 1*15 = 90
        # fresh process would just call update again with whatever counts; the stored total is read back
        r = se.update(p, _counts())
        assert r["coins"] == 90
        assert r["hwm"]["creds"] == 3 and r["hwm"]["data"] == 1


def test_monotonic_rises_with_new_wins():
    with tempfile.TemporaryDirectory() as d:
        p = str(Path(d) / "stats.json")
        assert se.update(p, _counts(creds=1))["coins"] == 25
        assert se.update(p, _counts(creds=1, data=2))["coins"] == 25 + 30  # 55


def test_level_curve_rises():
    # level = floor(sqrt(coins/25)): needs more coins for each successive level
    assert se.level_for(0) == 0
    assert se.level_for(24) == 0
    assert se.level_for(25) == 1
    assert se.level_for(100) == 2
    assert se.level_for(225) == 3
    # thresholds widen (RPG curve): gap 1->2 is 75, 2->3 is 125
    assert (100 - 25) < (225 - 100)


def test_first_run_seeds_from_current_counts_not_zero():
    with tempfile.TemporaryDirectory() as d:
        p = str(Path(d) / "stats.json")
        # existing install already has creds cracked; first overhaul run must reflect them, not reset to 0
        r = se.update(p, _counts(creds=4))
        assert r["coins"] == 100 and r["level"] == 2


def test_breakdown_shape():
    with tempfile.TemporaryDirectory() as d:
        p = str(Path(d) / "stats.json")
        bd = se.update(p, _counts(creds=2))["breakdown"]
        assert bd["creds"] == {"count": 2, "weight": 25, "coins": 50}
        assert set(bd.keys()) == set(se.CATEGORIES)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")


def test_handshakes_earn_coins_and_never_lose_them():
    """Handshakes are priced below a cracked credential (already usable) and above an attack: a
    handshake is a network you can own *after* cracking it. And like every other category it is a
    high-water mark — deleting the PCAPs must not claw back the score."""
    import tempfile, os
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "stats.json")
        first = se.update(path, {"hosts": 0, "handshakes": 2})
        assert first["hwm"]["handshakes"] == 2
        assert first["coins"] == 2 * se.WEIGHTS["handshakes"]

        # the loot directory is wiped; the score must not drop
        after = se.update(path, {"hosts": 0, "handshakes": 0})
        assert after["hwm"]["handshakes"] == 2 and after["coins"] == first["coins"]


def test_handshake_is_worth_less_than_a_credential_and_more_than_an_attack():
    w = se.WEIGHTS
    assert w["attacks"] < w["handshakes"] < w["creds"]
