#!/usr/bin/env python3
"""Print a redacted summary of Bjorn's local planner history."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def build_rows(data):
    """Convert telemetry JSON into stable, human-readable action rows."""
    rows = []
    for name, summary in sorted((data.get("actions") or {}).items()):
        attempts = max(0, int(summary.get("attempts", 0) or 0))
        successes = min(attempts, max(0, int(summary.get("successes", 0) or 0)))
        # Match the planner's Beta(1,1) estimate rather than showing false certainty.
        probability = (successes + 1.0) / (attempts + 2.0)
        rows.append({
            "action": name,
            "attempts": attempts,
            "successes": successes,
            "estimated_success": probability,
            "duration_ewma_s": float(summary.get("duration_ewma_s", 0.0) or 0.0),
            "last_outcome": str(summary.get("last_outcome", "-")),
        })
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--path", default="data/action_telemetry.json",
        help="telemetry path relative to the current directory")
    parser.add_argument("--json", action="store_true", help="emit machine-readable rows")
    args = parser.parse_args()

    path = Path(args.path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"No planner history yet: {path}")
        return 0
    except (json.JSONDecodeError, OSError) as exc:
        print(f"Cannot read planner history {path}: {exc}")
        return 2

    rows = build_rows(data)
    if args.json:
        print(json.dumps(rows, indent=2, sort_keys=True))
        return 0
    if not rows:
        print("Planner history exists but has no completed actions yet.")
        return 0

    print("ACTION                  TRY   OK   P(OK)   EWMA(s)   LAST")
    print("-" * 68)
    for row in rows:
        print(
            f"{row['action'][:22]:22} "
            f"{row['attempts']:4d} "
            f"{row['successes']:4d} "
            f"{row['estimated_success']:7.2f} "
            f"{row['duration_ewma_s']:9.1f}   "
            f"{row['last_outcome']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
