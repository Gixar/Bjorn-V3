"""#5: AST guards on what an action's ``execute()`` is allowed to return.

The plan asked for "a lint rejecting an unconditional ``return 'success'``".  Read against the
actual modules, that rule is wrong and would have to be suppressed immediately:
``web_template_scan`` returns success unconditionally *on purpose* ("scan completed; don't hammer
the host every cycle"), and for a recon action "ran, found nothing" is a success, not a failure —
marking it failed would put a healthy host into retry backoff.

The defect class those incidents actually share is narrower: **an action reporting an outcome the
orchestrator cannot act on correctly.**  `WiFiScan: success=4` for an action that had never
completed a capture, `release()` logging success on a radio it had not restored, a status line
that could not fail, a lint gate that could not fail.  Two mechanical halves of that are checkable
here; the third (verifying the side effect actually happened) is per-module work and is what
remains open on #5.

Both guards discover their targets from ``actions/*.py`` rather than naming modules, so a new
action is covered the day it lands.  Neither imports the modules — pure ``ast``, so the hardware
and starlette import walls do not apply.
"""
import ast
from pathlib import Path

from action_outcome import _ALIASES, OutcomeCode

ACTIONS = Path(__file__).resolve().parent.parent / "actions"

# The orchestrator funnels every legacy return through action_outcome._code_from, so the set of
# strings that survive is exactly this.  Derived from the source of truth, not restated, or the
# guard would drift the moment a new code is added.
KNOWN_OUTCOMES = {c.value for c in OutcomeCode} | set(_ALIASES)


def _execute_bodies():
    """Yield (filename, execute-node) for every action module that defines one."""
    for path in sorted(ACTIONS.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "execute":
                yield path.name, node
                break


def _returned_strings(fn):
    return {n.value.value for n in ast.walk(fn)
            if isinstance(n, ast.Return) and isinstance(n.value, ast.Constant)
            and isinstance(n.value.value, str)}


def _reads_a_gate(fn):
    """True if execute() consults an enable flag or a throttle interval.

    Written as ``getattr(self.shared_data, "ble_scan_enabled", False)`` throughout, so the setting
    name is a string argument, not an attribute — an ast.Attribute scan finds nothing here and
    would make this guard silently vacuous.
    """
    for node in ast.walk(fn):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "getattr" and len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant)
                and isinstance(node.args[1].value, str)
                and node.args[1].value.endswith(("_enabled", "_interval"))):
            return True
    return False


def test_execute_returns_only_the_known_outcome_vocabulary():
    """An unrecognised string is not rejected anywhere at runtime — it is silently downgraded.

    action_outcome._code_from falls through to OutcomeCode.FAILED for anything it does not know,
    and FAILED is in should_stamp_failure, so a typo ('sucess', 'done', 'ok!') makes a working
    action write failed_<timestamp> into netkb and enter retry backoff.  Nothing logs, nothing
    raises, and the run report reads as a real failure.  Same silent-lie family as the rest of #5,
    just pointing the other way: claiming failure instead of claiming success.
    """
    seen = 0
    for fname, fn in _execute_bodies():
        for value in _returned_strings(fn):
            seen += 1
            assert value in KNOWN_OUTCOMES, (
                f"{fname}: execute() returns {value!r}, which action_outcome._code_from does not "
                f"recognise — it becomes FAILED and stamps the netkb row. Use one of "
                f"{sorted(KNOWN_OUTCOMES)}, or return an ActionOutcome.")
    assert seen, "no string returns found in any action execute() — did the contract change?"


def test_gated_actions_have_a_skipped_path():
    """An action that can decline to run must say 'skipped', never 'success'.

    This is the WiFiScan bug generalised: every disabled/throttled path returned 'success', so the
    diagnostic reported `WiFiScan: success=4` for a feature that had never completed a capture —
    a dead feature that reads as a working one, which is worse than no diagnostic.  'skipped'
    leaves no netkb mark and does not count as work for the cycle.

    tests/test_standalone_actions.py::test_no_op_paths_in_the_action_modules_return_skipped pins
    the same property for four named modules plus one historical regression; this one finds the
    gated modules itself, so nobody has to remember to extend a list.
    """
    gated = [(fname, fn) for fname, fn in _execute_bodies() if _reads_a_gate(fn)]
    assert gated, "no gated action found — the getattr(_enabled/_interval) pattern must have moved"
    for fname, fn in gated:
        assert "skipped" in _returned_strings(fn), (
            f"{fname}: execute() gates on an enable flag or a throttle but never returns "
            f"'skipped' — its no-op paths report as real work")
