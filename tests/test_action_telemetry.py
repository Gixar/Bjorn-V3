"""Persistent planner-memory tests; uses only temporary files and a fake clock."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from action_outcome import ActionOutcome, OutcomeCode  # noqa: E402
from action_telemetry import ActionTelemetry  # noqa: E402


class FakeClock:
    def __init__(self, value=1_000.0):
        self.value = float(value)

    def __call__(self):
        return self.value


def _outcome(code, duration=10):
    return ActionOutcome(code, reason="test", duration_s=duration)


def test_estimate_uses_beta_smoothing_and_ewma_duration():
    clock = FakeClock()
    store = ActionTelemetry(now_fn=clock)
    store.record("Fast", "10.0.0.1", _outcome(OutcomeCode.SUCCESS, 10))
    store.record("Fast", "10.0.0.2", _outcome(OutcomeCode.FAILED, 20))

    estimate = store.estimate("Fast", default_duration_s=99)
    assert estimate["attempts"] == 2 and estimate["successes"] == 1
    assert estimate["probability"] == 0.5, "Beta(1,1) keeps small samples conservative"
    assert 10 < estimate["duration_s"] < 20, "duration must be an EWMA, not the last value"


def test_failures_back_off_per_target_and_success_resets_the_streak():
    clock = FakeClock()
    store = ActionTelemetry(now_fn=clock)
    store.record("SSH", "10.0.0.1", _outcome(OutcomeCode.FAILED))
    assert store.retry_delay("SSH", "10.0.0.1", 600) == 600

    clock.value += 601
    store.record("SSH", "10.0.0.1", _outcome(OutcomeCode.FAILED))
    assert store.retry_delay("SSH", "10.0.0.1", 600) == 1200
    assert store.retry_delay("SSH", "10.0.0.2", 600) == 600, "other hosts are independent"

    clock.value += 1201
    store.record("SSH", "10.0.0.1", _outcome(OutcomeCode.SUCCESS))
    assert store.retry_delay("SSH", "10.0.0.1", 600) == 600
    assert store.remaining_backoff("SSH", "10.0.0.1", 600) == 0


def test_resource_busy_retries_soon_without_poisoning_success_rate():
    clock = FakeClock()
    store = ActionTelemetry(now_fn=clock)
    store.record("WiFiScan", "STANDALONE", _outcome(OutcomeCode.RESOURCE_BUSY, 0))
    assert store.estimate("WiFiScan", 30)["attempts"] == 0
    assert 0 < store.remaining_backoff("WiFiScan", "STANDALONE", 600) <= 30


def test_unavailable_tool_has_a_long_cooldown():
    clock = FakeClock()
    store = ActionTelemetry(now_fn=clock)
    store.record("RDP", "10.0.0.4", _outcome(OutcomeCode.UNAVAILABLE, 0.1))
    assert store.retry_delay("RDP", "10.0.0.4", 600) == 3600


def test_flush_is_atomic_reloadable_and_only_writes_when_dirty(tmp_path):
    path = tmp_path / "action_telemetry.json"
    store = ActionTelemetry(str(path), now_fn=FakeClock())
    store.record("HTTP", "10.0.0.8", _outcome(OutcomeCode.SUCCESS, 4))
    assert store.flush() is True
    assert store.flush() is False, "an unchanged cycle must not write the SD card again"

    loaded = ActionTelemetry(str(path), now_fn=FakeClock())
    assert loaded.estimate("HTTP", 20)["attempts"] == 1
    assert not list(tmp_path.glob("*.tmp")), "atomic temporary files must be cleaned"


def test_corrupt_history_never_blocks_startup(tmp_path):
    path = tmp_path / "action_telemetry.json"
    path.write_text("{not-json", encoding="utf-8")
    store = ActionTelemetry(str(path), now_fn=FakeClock())
    assert store.estimate("SSH", 90)["attempts"] == 0


def test_target_history_is_bounded(tmp_path):
    store = ActionTelemetry(str(tmp_path / "history.json"), now_fn=FakeClock(), max_targets=16)
    for index in range(40):
        store.record("Probe", f"10.0.0.{index}", _outcome(OutcomeCode.FAILED, 1))
    assert len(store.snapshot()["targets"]) == 16


def test_saved_history_contains_no_outcome_reason_or_action_data(tmp_path):
    path = tmp_path / "history.json"
    store = ActionTelemetry(str(path), now_fn=FakeClock())
    secret = "password=hunter2"
    store.record(
        "SSH", "10.0.0.1",
        ActionOutcome(OutcomeCode.AUTH_FAILED, reason=secret, duration_s=2),
        planner_reason="SSH selected from port evidence",
    )
    store.flush()
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert secret not in json.dumps(saved), "telemetry must never retain action secrets"
