"""Typed action outcomes with backwards compatibility for Bjorn action modules.

Existing modules return ``'success'``, ``'failed'`` or ``'skipped'``.  The
orchestrator normalises those strings here, while new or gradually migrated
modules can return :class:`ActionOutcome` with a precise reason immediately.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
import subprocess
from typing import Any, Mapping, Optional


class OutcomeCode(str, Enum):
    """Stable outcome codes consumed by telemetry, retry policy and reports."""

    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    TIMEOUT = "timeout"
    NO_FINDINGS = "no_findings"
    RESOURCE_BUSY = "resource_busy"
    UNAVAILABLE = "unavailable"
    AUTH_FAILED = "auth_failed"
    ERROR = "error"


_ALIASES = {
    "ok": OutcomeCode.SUCCESS,
    "complete": OutcomeCode.SUCCESS,
    "completed": OutcomeCode.SUCCESS,
    "failure": OutcomeCode.FAILED,
    "no-results": OutcomeCode.NO_FINDINGS,
    "no_results": OutcomeCode.NO_FINDINGS,
    "busy": OutcomeCode.RESOURCE_BUSY,
    "missing": OutcomeCode.UNAVAILABLE,
}


@dataclass(frozen=True)
class ActionOutcome:
    """One completed action attempt, without credentials or captured data.

    ``evidence_count`` is intentionally numeric.  The telemetry file records
    whether useful evidence was produced but never stores secrets, loot or raw
    scan output.
    """

    code: OutcomeCode
    reason: str = ""
    evidence_count: int = 0
    duration_s: float = 0.0

    @property
    def succeeded(self) -> bool:
        return self.code is OutcomeCode.SUCCESS

    @property
    def skipped(self) -> bool:
        return self.code in (OutcomeCode.SKIPPED, OutcomeCode.RESOURCE_BUSY)

    @property
    def should_stamp_failure(self) -> bool:
        """Whether legacy netkb should receive a ``failed_<timestamp>`` value."""
        return self.code in {
            OutcomeCode.FAILED,
            OutcomeCode.TIMEOUT,
            OutcomeCode.NO_FINDINGS,
            OutcomeCode.UNAVAILABLE,
            OutcomeCode.AUTH_FAILED,
            OutcomeCode.ERROR,
        }


def _code_from(value: Any) -> OutcomeCode:
    if isinstance(value, OutcomeCode):
        return value
    text = str(value or "failed").strip().lower()
    if text in _ALIASES:
        return _ALIASES[text]
    try:
        return OutcomeCode(text)
    except ValueError:
        return OutcomeCode.FAILED


def normalize_outcome(
    result: Any = None,
    *,
    duration_s: float = 0.0,
    error: Optional[BaseException] = None,
) -> ActionOutcome:
    """Convert legacy strings, mappings or exceptions into ``ActionOutcome``.

    This function is deliberately dependency-free so every action can adopt it
    later without importing the orchestrator or hardware libraries.
    """
    duration_s = max(0.0, float(duration_s or 0.0))
    if error is not None:
        if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)):
            code = OutcomeCode.TIMEOUT
        elif isinstance(error, FileNotFoundError):
            code = OutcomeCode.UNAVAILABLE
        else:
            code = OutcomeCode.ERROR
        return ActionOutcome(code, reason=type(error).__name__, duration_s=duration_s)

    if isinstance(result, ActionOutcome):
        # The orchestrator is the authoritative clock for wall duration.
        return replace(result, duration_s=duration_s or result.duration_s)

    if isinstance(result, Mapping):
        code = _code_from(result.get("code", result.get("status", "failed")))
        reason = str(result.get("reason", ""))[:160]
        try:
            evidence = max(0, int(result.get("evidence_count", 0) or 0))
        except (TypeError, ValueError):
            evidence = 0
        return ActionOutcome(code, reason=reason, evidence_count=evidence,
                             duration_s=duration_s)

    code = _code_from(result)
    # Legacy actions do not report evidence counts, so success itself remains
    # the useful signal until each module is migrated to the richer contract.
    reason = f"legacy_{code.value}"
    return ActionOutcome(code, reason=reason, duration_s=duration_s)
