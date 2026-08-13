"""Typed outcome compatibility tests; no hardware or third-party packages required."""
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from action_outcome import ActionOutcome, OutcomeCode, normalize_outcome  # noqa: E402


def test_legacy_strings_keep_the_existing_contract():
    assert normalize_outcome("success", duration_s=2).succeeded
    assert normalize_outcome("failed").should_stamp_failure
    assert normalize_outcome("skipped").skipped


def test_typed_outcome_keeps_reason_and_uses_orchestrator_duration():
    original = ActionOutcome(OutcomeCode.NO_FINDINGS, reason="empty scan", duration_s=99)
    normalised = normalize_outcome(original, duration_s=3.5)
    assert normalised.code is OutcomeCode.NO_FINDINGS
    assert normalised.reason == "empty scan"
    assert normalised.duration_s == 3.5


def test_mapping_is_a_gradual_migration_path_for_actions():
    outcome = normalize_outcome({
        "status": "success",
        "reason": "two files",
        "evidence_count": 2,
    }, duration_s=1.25)
    assert outcome == ActionOutcome(
        OutcomeCode.SUCCESS, reason="two files", evidence_count=2, duration_s=1.25)


def test_exception_types_produce_actionable_codes():
    assert normalize_outcome(error=FileNotFoundError("tool")).code is OutcomeCode.UNAVAILABLE
    timeout = subprocess.TimeoutExpired(cmd="tool", timeout=5)
    assert normalize_outcome(error=timeout).code is OutcomeCode.TIMEOUT
    assert normalize_outcome(error=RuntimeError("boom")).code is OutcomeCode.ERROR


def test_unknown_legacy_value_fails_closed():
    assert normalize_outcome(None).code is OutcomeCode.FAILED
    assert normalize_outcome("surprising-new-value").code is OutcomeCode.FAILED
