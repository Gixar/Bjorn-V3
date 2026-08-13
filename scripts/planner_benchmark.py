#!/usr/bin/env python3
"""Deterministic before/after benchmark for Bjorn's work-selection policy.

This is a scheduling simulation, not a claim about a real network. Both planners
receive the same hosts and precomputed outcomes. It answers one narrow question:
within a fixed time budget, does measured yield/duration ordering complete more
useful work than static ordering?
"""
from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path

# Permit ``python scripts/planner_benchmark.py`` from the repository root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from action_outcome import ActionOutcome, OutcomeCode  # noqa: E402
from action_planner import ACTION_VALUE, Planner  # noqa: E402
from action_telemetry import ActionTelemetry  # noqa: E402


PROFILES = {
    # success_percent and duration model a mixed lab, not any specific target.
    "SSHBruteforce": {"port": 22, "success_percent": 22, "duration_s": 95},
    "SMBBruteforce": {"port": 445, "success_percent": 30, "duration_s": 80},
    "RDPBruteforce": {"port": 3389, "success_percent": 12, "duration_s": 125},
    "HTTPFingerprint": {"port": 80, "success_percent": 78, "duration_s": 7},
}


class SyntheticAction:
    """The minimal action contract consumed by action_planner."""

    def __init__(self, name, port):
        self.action_name = name
        self.port = port
        self.b_parent_action = None


def _hosts(count):
    ports = ";".join(str(profile["port"]) for profile in PROFILES.values())
    return [{
        "MAC Address": f"02:00:00:00:00:{index:02x}",
        "IPs": f"10.20.0.{index + 2}",
        "Hostnames": f"synthetic-{index}",
        "Alive": "1",
        "Ports": ports,
    } for index in range(count)]


def _precomputed_result(action_name, host_index):
    """Return a stable result independent of planner order."""
    profile = PROFILES[action_name]
    # Different co-prime multipliers avoid giving every protocol the same winning hosts.
    multiplier = {"SSHBruteforce": 37, "SMBBruteforce": 53,
                  "RDPBruteforce": 71, "HTTPFingerprint": 29}[action_name]
    bucket = (host_index * multiplier + len(action_name) * 11) % 100
    success = bucket < profile["success_percent"]
    # Small deterministic jitter prevents equal-duration artifacts.
    duration = profile["duration_s"] * (0.85 + ((host_index * 7) % 31) / 100)
    code = OutcomeCode.SUCCESS if success else OutcomeCode.FAILED
    return ActionOutcome(code, reason="synthetic_fixture", duration_s=duration)


def simulate(*, smart_enabled, host_count=50, budget_seconds=1800):
    """Run one policy against the fixed fixture and return comparable metrics."""
    rows = _hosts(host_count)
    actions = [SyntheticAction(name, profile["port"])
               for name, profile in PROFILES.items()]
    telemetry = ActionTelemetry()
    planner = Planner(
        telemetry=telemetry,
        smart_enabled=smart_enabled,
        max_host_actions=1,
        standalone_every=9999,
        failed_retry_delay=0,
        retry_success_actions=False,
    )
    elapsed = 0.0
    useful = 0
    useful_points = 0
    attempts = 0
    selected = []

    while elapsed < budget_seconds:
        candidates = planner.collect(actions, [], rows)
        work = planner.select(candidates)
        if not work:
            break
        candidate = work[0]
        host_index = int(candidate.ip.rsplit(".", 1)[1]) - 2
        outcome = _precomputed_result(candidate.action_name, host_index)
        if elapsed + outcome.duration_s > budget_seconds:
            break

        elapsed += outcome.duration_s
        attempts += 1
        if outcome.succeeded:
            useful += 1
            useful_points += ACTION_VALUE[candidate.action_name]
        telemetry.record(candidate.action_name, candidate.ip, outcome,
                         planner_score=candidate.score,
                         planner_reason=candidate.reason)
        selected.append(candidate.action_name)

        # Mark this synthetic job consumed regardless of result. This is a benchmark queue marker,
        # not the netkb failure representation used by the live orchestrator.
        candidate.row[candidate.action_name] = "success_20000101_000000"

    hours = max(elapsed / 3600.0, 1 / 3600.0)
    return {
        "mode": "smart" if smart_enabled else "legacy",
        "budget_seconds": budget_seconds,
        "elapsed_seconds": round(elapsed, 2),
        "attempts": attempts,
        "useful_results": useful,
        "useful_points": useful_points,
        "useful_results_per_hour": round(useful / hours, 2),
        "useful_points_per_hour": round(useful_points / hours, 2),
        "selection_counts": {name: selected.count(name) for name in PROFILES},
    }


def compare(host_count=50, budget_seconds=1800):
    """Return legacy/smart results and the smart useful-yield improvement."""
    legacy = simulate(
        smart_enabled=False, host_count=host_count, budget_seconds=budget_seconds)
    smart = simulate(
        smart_enabled=True, host_count=host_count, budget_seconds=budget_seconds)
    baseline = max(legacy["useful_points_per_hour"], 0.01)
    improvement = ((smart["useful_points_per_hour"] / baseline) - 1.0) * 100.0
    return {"fixture": "mixed_lab_v1", "legacy": legacy, "smart": smart,
            "useful_yield_improvement_percent": round(improvement, 2)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hosts", type=int, default=50)
    parser.add_argument("--budget-seconds", type=int, default=1800)
    parser.add_argument(
        "--require-improvement", type=float, default=0.0,
        help="exit nonzero if useful-points/hour improvement is below this percent")
    args = parser.parse_args()
    report = compare(host_count=max(1, args.hosts),
                     budget_seconds=max(1, args.budget_seconds))
    print(json.dumps(report, indent=2, sort_keys=True))
    if report["useful_yield_improvement_percent"] < args.require_improvement:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
