"""Small, local and SD-card-conscious history for Bjorn's deterministic planner.

The store keeps aggregated counts and exponentially weighted duration estimates.
It never stores credentials, loot, command output or network banners. Updates are
held in memory during a cycle and atomically flushed once the cycle completes.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from typing import Dict, Optional

from action_outcome import ActionOutcome, OutcomeCode


STORE_VERSION = 1
EWMA_ALPHA = 0.30
MAX_TARGET_RECORDS = 512
MAX_BACKOFF_SECONDS = 6 * 60 * 60


class ActionTelemetry:
    """Thread-safe action summaries and per-target retry memory."""

    def __init__(self, path: Optional[str] = None, *, now_fn=time.time,
                 max_targets: int = MAX_TARGET_RECORDS):
        self.path = path
        self._now = now_fn
        self.max_targets = max(16, int(max_targets))
        self._lock = threading.RLock()
        self._dirty = False
        self._data = {"version": STORE_VERSION, "actions": {}, "targets": {}}
        self._load()

    def _load(self) -> None:
        if not self.path:
            return
        try:
            with open(self.path, encoding="utf-8") as handle:
                loaded = json.load(handle)
            if isinstance(loaded, dict) and loaded.get("version") == STORE_VERSION:
                self._data["actions"] = dict(loaded.get("actions") or {})
                self._data["targets"] = dict(loaded.get("targets") or {})
        except (FileNotFoundError, json.JSONDecodeError, OSError, TypeError, ValueError):
            # Missing/corrupt telemetry must never prevent Bjorn from starting.
            self._data = {"version": STORE_VERSION, "actions": {}, "targets": {}}

    @staticmethod
    def _target_key(action_name: str, target: str) -> str:
        return f"{action_name}|{target or 'STANDALONE'}"

    def record(self, action_name: str, target: str, outcome: ActionOutcome,
               *, planner_score: Optional[float] = None,
               planner_reason: str = "") -> None:
        """Record one attempt in memory; call ``flush`` once after the cycle."""
        if outcome.code is OutcomeCode.SKIPPED:
            return
        now = float(self._now())
        with self._lock:
            actions = self._data["actions"]
            summary = actions.setdefault(action_name, {
                "attempts": 0,
                "successes": 0,
                "duration_samples": 0,
                "duration_ewma_s": 0.0,
                "outcomes": {},
            })
            # Resource pressure is a scheduling deferral, not evidence that the
            # action itself is unreliable or slow.
            if outcome.code is not OutcomeCode.RESOURCE_BUSY:
                summary["attempts"] = int(summary.get("attempts", 0)) + 1
                if outcome.succeeded:
                    summary["successes"] = int(summary.get("successes", 0)) + 1
                if outcome.duration_s > 0:
                    samples = int(summary.get("duration_samples", 0))
                    previous = float(summary.get("duration_ewma_s", 0.0) or 0.0)
                    summary["duration_ewma_s"] = round(
                        outcome.duration_s if samples == 0
                        else (EWMA_ALPHA * outcome.duration_s) + ((1 - EWMA_ALPHA) * previous),
                        3,
                    )
                    summary["duration_samples"] = samples + 1
            outcomes = summary.setdefault("outcomes", {})
            outcomes[outcome.code.value] = int(outcomes.get(outcome.code.value, 0)) + 1
            summary["last_at"] = now
            summary["last_outcome"] = outcome.code.value

            key = self._target_key(action_name, target)
            previous_target = self._data["targets"].get(key, {})
            previous_failures = int(previous_target.get("consecutive_failures", 0))
            if outcome.succeeded:
                failures = 0
            elif outcome.code in (OutcomeCode.SKIPPED, OutcomeCode.RESOURCE_BUSY):
                failures = previous_failures
            else:
                failures = previous_failures + 1
            self._data["targets"][key] = {
                "last_at": now,
                "last_outcome": outcome.code.value,
                "consecutive_failures": failures,
                "last_duration_s": round(outcome.duration_s, 3),
                # Keep the selected reason bounded and free from raw action data.
                "planner_score": round(float(planner_score), 2)
                if planner_score is not None else None,
                "planner_reason": str(planner_reason or "")[:180],
            }
            self._trim_targets()
            self._dirty = True

    def _trim_targets(self) -> None:
        targets = self._data["targets"]
        overflow = len(targets) - self.max_targets
        if overflow <= 0:
            return
        # Oldest records are least useful for near-term backoff and learning.
        oldest = sorted(targets, key=lambda key: float(targets[key].get("last_at", 0)))
        for key in oldest[:overflow]:
            targets.pop(key, None)

    def estimate(self, action_name: str, default_duration_s: float) -> Dict[str, float]:
        """Return Bayesian success probability and observed duration.

        Beta(1, 1) smoothing prevents one early success or failure from producing
        a certainty of 100% or 0%.
        """
        with self._lock:
            summary = dict(self._data["actions"].get(action_name) or {})
        attempts = max(0, int(summary.get("attempts", 0)))
        successes = min(attempts, max(0, int(summary.get("successes", 0))))
        probability = (successes + 1.0) / (attempts + 2.0)
        observed = float(summary.get("duration_ewma_s", 0.0) or 0.0)
        duration = observed if observed > 0 else max(1.0, float(default_duration_s))
        return {
            "attempts": attempts,
            "successes": successes,
            "probability": probability,
            "duration_s": duration,
            "confidence": attempts / (attempts + 4.0),
        }

    def retry_delay(self, action_name: str, target: str, base_delay: int) -> int:
        """Return cause/streak-aware delay for one target-action pair."""
        with self._lock:
            record = dict(self._data["targets"].get(
                self._target_key(action_name, target), {}) or {})
        if not record:
            return max(0, int(base_delay))
        code = str(record.get("last_outcome", ""))
        streak = max(1, int(record.get("consecutive_failures", 0) or 0))
        base = max(0, int(base_delay))
        if code == OutcomeCode.RESOURCE_BUSY.value:
            return 30
        if code == OutcomeCode.UNAVAILABLE.value:
            return max(3600, base)
        if code == OutcomeCode.AUTH_FAILED.value:
            return min(MAX_BACKOFF_SECONDS, max(base, 1) * 4)
        if code == OutcomeCode.NO_FINDINGS.value:
            return min(MAX_BACKOFF_SECONDS, max(base, 1) * 3)
        if code in {OutcomeCode.FAILED.value, OutcomeCode.TIMEOUT.value,
                    OutcomeCode.ERROR.value}:
            multiplier = min(8, 2 ** (streak - 1))
            return min(MAX_BACKOFF_SECONDS, max(base, 1) * multiplier)
        return base

    def remaining_backoff(self, action_name: str, target: str, base_delay: int) -> int:
        """Seconds remaining for telemetry-only deferrals such as RESOURCE_BUSY."""
        with self._lock:
            record = dict(self._data["targets"].get(
                self._target_key(action_name, target), {}) or {})
        if not record:
            return 0
        code = str(record.get("last_outcome", ""))
        if code not in {
            OutcomeCode.RESOURCE_BUSY.value,
            OutcomeCode.UNAVAILABLE.value,
            OutcomeCode.AUTH_FAILED.value,
            OutcomeCode.NO_FINDINGS.value,
            OutcomeCode.FAILED.value,
            OutcomeCode.TIMEOUT.value,
            OutcomeCode.ERROR.value,
        }:
            return 0
        delay = self.retry_delay(action_name, target, base_delay)
        elapsed = max(0.0, float(self._now()) - float(record.get("last_at", 0)))
        return max(0, int(round(delay - elapsed)))

    def snapshot(self) -> dict:
        """Return a detached copy suitable for tests or redacted diagnostics."""
        with self._lock:
            return json.loads(json.dumps(self._data))

    def flush(self) -> bool:
        """Atomically persist dirty state; return True only when bytes were written."""
        if not self.path:
            return False
        with self._lock:
            if not self._dirty:
                return False
            parent = os.path.dirname(self.path) or "."
            os.makedirs(parent, exist_ok=True)
            fd, temporary = tempfile.mkstemp(dir=parent, suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(self._data, handle, indent=2, sort_keys=True)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, self.path)
                self._dirty = False
                return True
            except BaseException:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass
                raise
