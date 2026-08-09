"""Self-check for scripts/analyze_reports.py's report-selection logic.
Run directly: python tests/test_analyze_reports.py
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from analyze_reports import load_reports  # noqa: E402


def demo():
    with tempfile.TemporaryDirectory() as tmp:
        reports_dir = Path(tmp)
        (reports_dir / "clean1.json").write_text(json.dumps({"actions": {"scan": {"success": 3, "failed": 0}}}))
        (reports_dir / "failing1.json").write_text(json.dumps({"actions": {"ssh": {"success": 1, "failed": 2}}}))
        (reports_dir / "clean2.json").write_text(json.dumps({"actions": {"scan": {"success": 3, "failed": 0}}}))

        result = load_reports(reports_dir, limit=30)
        assert len(result) == 3, "expected all reports back under the limit"
        assert result[0]["actions"]["ssh"]["failed"] == 2, "failing report must be prioritized first"

        result_limited = load_reports(reports_dir, limit=1)
        assert len(result_limited) == 1
        assert result_limited[0]["actions"]["ssh"]["failed"] == 2, "limit=1 must keep the failing report, not a clean one"

    print("ok")


if __name__ == "__main__":
    demo()
