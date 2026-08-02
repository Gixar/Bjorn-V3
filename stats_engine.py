# stats_engine.py
# Coins / stats overhaul (backlog Wave 1 #3 — see docs/COINS_STATS_PLAN.md).
#
# The old shared.py::update_stats() recomputed coins/level as a flat linear function of the
# *current* counts every refresh, so the score was a live gauge that could DROP (netkb cleaned,
# hosts offline) and reset to 0 on restart. This replaces it with a monotonic high-water-mark
# accumulator: each category's mark only ever rises, coins = sum(mark * weight), and everything is
# persisted to data/stats.json. Kept dependency-free and separate from shared.py so it can be
# unit-tested without constructing SharedData (which pulls in PIL / the e-Paper stack).
import os
import json
import tempfile

# Rebalanced award weights: rare achievements pay far more than common ones (a host merely
# appearing is cheap; a cracked credential or stolen file is the real win).
WEIGHTS = {"hosts": 1, "creds": 25, "data": 15, "zombies": 15, "attacks": 5, "vulns": 8}
CATEGORIES = tuple(WEIGHTS.keys())
LEVEL_DIVISOR = 25  # level = floor(sqrt(coins / LEVEL_DIVISOR)) -> rising thresholds (RPG curve)


def level_for(coins):
    """Rising-threshold curve: each level needs more coins than the last."""
    return int((coins / LEVEL_DIVISOR) ** 0.5) if coins > 0 else 0


def coins_for(hwm):
    return int(sum(int(hwm.get(c, 0)) * WEIGHTS[c] for c in CATEGORIES))


def breakdown_for(hwm):
    """Per-category {count, weight, coins} for the web UI."""
    return {c: {"count": int(hwm.get(c, 0)), "weight": WEIGHTS[c],
                "coins": int(hwm.get(c, 0)) * WEIGHTS[c]} for c in CATEGORIES}


def _merge_hwm(prev, counts):
    """High-water mark: each category is max(stored, current) — only ever rises. Seeds from the
    current counts on first run (prev empty), so an existing install doesn't reset to 0."""
    return {c: max(int(prev.get(c, 0)), int(counts.get(c, 0) or 0)) for c in CATEGORIES}


def load(path):
    try:
        with open(path) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _atomic_write(path, data):
    """temp -> fsync -> os.replace, so a power loss mid-write can't corrupt stats.json (PG-2)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def update(path, counts):
    """Merge counts into the stored high-water marks (never decreasing), recompute coins/level,
    persist if changed, and return {version, hwm, coins, level, breakdown}. Single-writer: call
    only from the display thread (matches the P5 counter discipline), so it stays lockless."""
    prev = load(path)
    hwm = _merge_hwm(prev.get("hwm", {}), counts)
    coins = coins_for(hwm)
    record = {"version": 1, "hwm": hwm, "coins": coins, "level": level_for(coins)}
    if record != prev:  # only touch the SD card when something actually changed
        _atomic_write(path, record)
    return {**record, "breakdown": breakdown_for(hwm)}
