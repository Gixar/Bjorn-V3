"""Tests for the CSV formula-injection guard (CWE-1236, csv_safe.py). Pure stdlib module."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from csv_safe import (sanitize_cell, sanitize_row,  # noqa: E402
                      unsanitize_cell, unsanitize_dict)


def test_formula_triggers_get_apostrophe():
    for bad in ("=cmd|'/c calc'!A0", "+1+1", "-2+3", "@SUM(A1)", "\tTAB", "\rCR"):
        out = sanitize_cell(bad)
        assert out == "'" + bad, out


def test_normal_values_untouched():
    for ok in ("Linux router 5.4", "public", "OpenSSH 7.6p1", "192.168.1.6", "80;443"):
        assert sanitize_cell(ok) == ok


def test_none_and_numbers():
    assert sanitize_cell(None) == ""
    assert sanitize_cell(200) == "200"          # coerced to str, no leading trigger
    assert sanitize_cell("") == ""


def test_sanitize_row_maps_each_cell():
    assert sanitize_row(["=evil", "ok", None, "@x"]) == ["'=evil", "ok", "", "'@x"]


# --- the inverse: Bjorn reads these CSVs back ------------------------------

def test_unsanitize_is_the_exact_inverse_of_sanitize():
    """Round-trip, because the guard has to come back off wherever Bjorn parses its own output."""
    for original in ("-67", "=cmd", "+1+1", "@SUM(A1)", "\tTAB", "\rCR",
                     "Linux router 5.4", "", "192.168.1.6"):
        assert unsanitize_cell(sanitize_cell(original)) == original, original


def test_a_guarded_dbm_reads_back_as_an_int():
    """The 2026-08-17 bug in one line: Power is always negative, so it is always guarded, and the
    hunter's int() always threw. min_rssi stopped excluding anything and the proximity score went
    to zero for every AP."""
    assert int(unsanitize_cell(sanitize_cell("-67"))) == -67


def test_an_apostrophe_the_user_typed_survives():
    """Lossless is the whole point: sanitize_cell never prefixed these, so nothing may be trimmed.
    Stripping any leading apostrophe would quietly rename every AP called "'Round Midnight"."""
    for untouched in ("'Round Midnight", "'", "'hello", "''"):
        assert sanitize_cell(untouched) == untouched
        assert unsanitize_cell(untouched) == untouched


def test_sanitize_is_idempotent_so_there_is_only_ever_one_guard_to_remove():
    """Load-bearing for every reader that copies a value through without parsing it. "'" is not
    itself a trigger, so a guarded cell that goes through a read-modify-write cycle comes out
    unchanged rather than gaining an apostrophe each pass."""
    value = "-67"
    for _ in range(5):
        value = sanitize_cell(value)
    assert value == "'-67"
    assert unsanitize_cell(value) == "-67"


def test_only_a_real_guard_comes_off():
    """Losslessness wins over repair: "''-67" is indistinguishable from an ESSID a user really
    typed as "'-67", so peeling it would be a guess. Nothing writes that shape anyway — see the
    idempotence test above — so the guess would buy nothing and could corrupt a real name."""
    assert unsanitize_cell("''-67") == "''-67"


def test_unsanitize_dict_leaves_the_restkey_list_alone():
    """csv.DictReader puts the overflow of a too-long row in a list. str()-ing that corrupts it."""
    out = unsanitize_dict({"Power": "'-67", "ESSID": "Home", None: ["extra", "cells"]})
    assert out == {"Power": "-67", "ESSID": "Home", None: ["extra", "cells"]}


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
