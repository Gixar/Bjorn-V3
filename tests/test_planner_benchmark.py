"""Locks the deterministic benchmark fixture and its before/after comparison."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from planner_benchmark import compare  # noqa: E402


def test_smart_planner_improves_useful_yield_on_the_fixed_fixture():
    report = compare(host_count=50, budget_seconds=1800)
    assert report["legacy"]["budget_seconds"] == report["smart"]["budget_seconds"]
    assert report["smart"]["useful_points_per_hour"] \
        > report["legacy"]["useful_points_per_hour"]
    # This is a regression threshold for the synthetic fixture, not a promise for real networks.
    assert report["useful_yield_improvement_percent"] >= 30
