"""Hardware-free integration checks for typed outcomes at the execution boundary."""
import ast
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _stubs  # noqa: E402
_stubs.install()

from action_outcome import ActionOutcome, OutcomeCode  # noqa: E402
from orchestrator import Orchestrator  # noqa: E402


class FakeHostAction:
    action_name = "Probe"
    port = 22
    b_parent_action = None

    def __init__(self, result):
        self.result = result

    def execute(self, *_args):
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


def _fake_orchestrator():
    recorded = []
    fake = types.SimpleNamespace(
        shared_data=types.SimpleNamespace(
            retry_success_actions=False,
            success_retry_delay=900,
            failed_retry_delay=600,
            bjornstatustext2="",
        ),
        _record_execution=lambda name, target, outcome, **meta:
            recorded.append((name, target, outcome, meta)),
    )
    return fake, recorded


def test_typed_success_updates_legacy_netkb_and_rich_history():
    fake, recorded = _fake_orchestrator()
    row = {"Probe": ""}
    action = FakeHostAction(ActionOutcome(
        OutcomeCode.SUCCESS, reason="one finding", evidence_count=1))
    ok = Orchestrator.execute_action(
        fake, action, "10.0.0.1", ["22"], row, "Probe", [row],
        planner_score=123, planner_reason="measured yield")

    assert ok is True and row["Probe"].startswith("success_")
    assert recorded[0][2].code is OutcomeCode.SUCCESS
    assert recorded[0][3]["planner_score"] == 123


def test_resource_busy_defers_without_a_failed_netkb_mark():
    fake, recorded = _fake_orchestrator()
    row = {"Probe": ""}
    action = FakeHostAction(ActionOutcome(OutcomeCode.RESOURCE_BUSY, reason="radio"))
    ok = Orchestrator.execute_action(
        fake, action, "10.0.0.1", ["22"], row, "Probe", [row])

    assert ok is False and row["Probe"] == ""
    assert recorded[0][2].code is OutcomeCode.RESOURCE_BUSY


def test_uncaught_timeout_becomes_a_typed_failure():
    fake, recorded = _fake_orchestrator()
    row = {"Probe": ""}
    ok = Orchestrator.execute_action(
        fake, FakeHostAction(TimeoutError("slow")),
        "10.0.0.1", ["22"], row, "Probe", [row])

    assert ok is False and row["Probe"].startswith("failed_")
    assert recorded[0][2].code is OutcomeCode.TIMEOUT


def test_telemetry_write_failure_does_not_stop_the_orchestrator():
    class BrokenStore:
        def flush(self):
            raise OSError("read-only filesystem")

    fake = types.SimpleNamespace(action_telemetry=BrokenStore())
    # Optional planner memory must degrade cleanly when the SD card cannot be written.
    assert Orchestrator._flush_action_telemetry(fake) is None


def test_main_block_blocks_so_the_orchestrator_pools_stay_usable():
    """`_vuln_pool` and the per-host pool are ThreadPoolExecutors built hours into a run, and both
    raise "cannot schedule new futures after interpreter shutdown" the moment Bjorn.py's __main__
    returns: threading._shutdown() runs concurrent.futures' atexit hook *before* joining the
    non-daemon threads that keep the process alive. So the last thing __main__ does must block on
    them. Source-parsed rather than imported — Bjorn.py pulls in the display stack and uvicorn.
    """
    source = (Path(__file__).resolve().parent.parent / "Bjorn.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    main = next(n for n in tree.body if isinstance(n, ast.If)
                and ast.get_source_segment(source, n.test) == '__name__ == "__main__"')
    last = ast.get_source_segment(source, main.body[-1])

    assert ".join()" in last, f"__main__ ends without joining anything:\n{last}"
    for name in ("bjorn_thread", "display_thread", "web_thread"):
        assert name in last, f"__main__ ends without waiting on {name}:\n{last}"
