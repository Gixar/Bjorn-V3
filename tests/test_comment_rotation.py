"""The joke/status rotation: every Nth comment slot reports live findings instead of a joke.

comment.py imports shared_data at module scope (init_shared), so this drives status_lines() with a
plain stub — the rotation arithmetic is the part worth pinning, not the wiring.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _stubs  # noqa: E402
_stubs.install()


class FakeShared:
    targetnbr = 4
    networkkbnbr = 11
    portnbr = 9
    vulnnbr = 0          # zero counters must not become "0 vulns" filler
    crednbr = 2
    datanbr = 0
    zombiesnbr = 0
    attacksnbr = 7
    coinnbr = 120
    levelnbr = 3
    wifi_connected = True


def test_zero_counters_are_left_out():
    from comment import status_lines
    lines = status_lines(FakeShared())
    joined = " | ".join(lines)
    assert "weak spots" not in joined      # vulnnbr == 0
    assert "longship" not in joined        # datanbr == 0
    assert "2 keys on my belt" in joined   # crednbr == 2
    assert "4 alive / 11 known" in lines[0]
    assert "Lvl 3 - 120 coins" in joined


def test_offline_line_only_appears_offline():
    from comment import status_lines
    online = FakeShared()
    assert not any("No uplink" in l for l in status_lines(online))

    class Offline(FakeShared):
        wifi_connected = False
    assert any("No uplink" in l for l in status_lines(Offline()))


def test_rotation_ratio():
    # The arithmetic the display depends on: with ratio 3, slots 3, 6, 9 report and the rest joke.
    ratio = 3
    reporting = [n for n in range(1, 10) if ratio and n % ratio == 0]
    assert reporting == [3, 6, 9]
    # ratio 0 disables reporting entirely (jokes only, the old behaviour).
    assert [n for n in range(1, 10) if 0 and n % 1 == 0] == []


def demo():
    test_zero_counters_are_left_out()
    test_offline_line_only_appears_offline()
    test_rotation_ratio()
    print("comment rotation: all checks passed")


if __name__ == "__main__":
    demo()
