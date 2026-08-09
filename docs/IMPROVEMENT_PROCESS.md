# Bjorn Improvement Process (offline, human-in-the-loop)

This is the "collect on the Pi → improve off-device → flash a new version" loop from
`docs/PRD.md` §4a (P-DEV). It is deliberately **not** a live, on-device agent: Bjorn runs an
offensive tool and ingests untrusted strings from scanned hosts, so nothing here lets an LLM
execute code on the Pi or read raw scan/loot data. Only redacted counts leave the device, and
a human applies every change.

## What Bjorn already produces

- **Run reports** — `data/output/run_reports/<run_id>.json`, written by
  `Orchestrator.write_run_report()` at each idle checkpoint. Version + per-action success/fail
  counts + up to 5 truncated exception strings. **No credentials, loot, or raw scanned strings.**
  This is the sanitization boundary.
- **Rotating logs** — `data/logs/` (from `logger.py`).

## The loop

1. **Export the bundle (on the Pi).**
   ```bash
   ./scripts/export_reports.sh          # -> bjorn_reports_<stamp>.tar.gz
   ```
   Pull it to a dev machine with the `scp` line the script prints. Nothing here phones home.

2. **Summarize the friction (dev machine).**
   ```bash
   pip install -r scripts/requirements.txt   # anthropic SDK (dev-only, not on the Pi)
   export ANTHROPIC_API_KEY=...              # or: ant auth login
   tar xzf bjorn_reports_<stamp>.tar.gz
   python scripts/analyze_reports.py         # -> data/output/improvement_notes/<stamp>.md
   ```
   `analyze_reports.py` sends only the redacted run-report JSON (failing runs prioritized) to
   Claude and writes a plain-English summary of recurring failures with a fix direction each.

3. **Turn friction into a patch (dev machine, Claude Code).**
   Open a Claude Code session with the improvement note + the repo, and ask it to:
   - read the friction summary and locate the responsible code;
   - **check upstream `infinition/Bjorn` and known forks** for existing fixes to the same
     friction — Bjorn is MIT-licensed, so reuse is clean; record borrowed changes with
     attribution in `CHANGELOG.md`;
   - propose a patch.

4. **Review + verify (human).**
   - Read the diff; you own the decision, same authorization posture as §3 of the PRD.
   - Run the checks: `pytest tests/` (CI mirrors this), and a mock-display smoke test —
     set `epd_type: "mock"` in `config/shared_config.json` and boot far enough to confirm no
     regression.
   - Merge, bump `version.txt`, update `CHANGELOG.md`.

5. **Flash.** Build the image and reflash the Pi once the new version is stable.

## Cadence

Run this when friction actually accumulates in the reports — not on a fixed schedule. A few
run reports aren't worth a pass; a recurring failure across many is.

## Explicitly out of scope

- No on-device execution of LLM-proposed changes.
- No feeding raw scan strings (attacker-influenced) into any LLM session — only the redacted
  DEV-1 counts.
- No auto-merge. A human is the gate at step 4.
