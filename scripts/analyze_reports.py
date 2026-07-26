#!/usr/bin/env python3
"""Summarize Bjorn's run reports with Claude (docs/PRD.md §4a, DEV-3).

Run on a dev machine, after pulling data/output/run_reports/ off the Pi
(scripts/export_reports.sh or scp/rsync). Never send raw scan/loot data —
run reports already contain only counts and exception text (see DEV-1 in
orchestrator.py). Requires `pip install anthropic` and an ANTHROPIC_API_KEY
(or `ant auth login`).

Usage: python scripts/analyze_reports.py [--limit N] [--reports-dir DIR]
"""
import argparse
import json
from datetime import datetime
from pathlib import Path

SYSTEM = """You analyze operational run reports from Bjorn, an authorized \
network-security scanning tool for a home lab. Each report is JSON: version, \
per-action success/fail counts with truncated exception text, and a \
timestamp. No credentials, loot, or raw scan data are included.

Summarize recurring failures and friction worth fixing in the next dev \
pass. For each finding: what's failing, how often (across how many \
reports), and a one-line fix direction. Ignore one-off blips. Close with \
a short prioritized list, most impactful first."""


def load_reports(reports_dir: Path, limit: int) -> list[dict]:
    files = sorted(reports_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    reports = [json.loads(f.read_text()) for f in files]
    # focus on reports that actually had a failure; keep a handful of clean
    # ones as a baseline so "everything is fine" is also a visible outcome
    failing = [r for r in reports if any(a.get("failed") for a in r.get("actions", {}).values())]
    clean = [r for r in reports if r not in failing]
    return (failing + clean[:5])[:limit]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reports-dir", type=Path, default=Path("data/output/run_reports"))
    parser.add_argument("--limit", type=int, default=30, help="max reports to send")
    parser.add_argument("--out-dir", type=Path, default=Path("data/output/improvement_notes"))
    args = parser.parse_args()

    reports = load_reports(args.reports_dir, args.limit)
    if not reports:
        print(f"No run reports found in {args.reports_dir}")
        return

    import anthropic  # deferred: keeps --help and the report-selection logic usable without the SDK installed

    client = anthropic.Anthropic()
    response = client.messages.create(
        model="claude-opus-5",
        max_tokens=4096,
        system=SYSTEM,
        messages=[{"role": "user", "content": json.dumps(reports, indent=2)}],
    )
    summary = next(b.text for b in response.content if b.type == "text")

    args.out_dir.mkdir(parents=True, exist_ok=True)
    out_path = args.out_dir / f"{datetime.now():%Y%m%d-%H%M%S}.md"
    out_path.write_text(summary)
    print(f"Analyzed {len(reports)} report(s) -> {out_path}")


if __name__ == "__main__":
    main()
