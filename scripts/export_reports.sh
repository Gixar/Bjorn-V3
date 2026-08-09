#!/bin/bash
# export_reports.sh (PRD §4a DEV-2)
# Bundle Bjorn's logs + run reports into a single tarball for pulling off the Pi
# (scp/rsync to a dev machine, then feed to scripts/analyze_reports.py). No dependencies,
# no network calls — just tar. Run from the Bjorn repo root or anywhere; paths resolve
# relative to this script.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
cd "$REPO_DIR"

STAMP="$(date +%Y%m%d_%H%M%S)"
OUT="bjorn_reports_${STAMP}.tar.gz"

PATHS=()
[ -d "data/logs" ] && PATHS+=("data/logs")
[ -d "data/output/run_reports" ] && PATHS+=("data/output/run_reports")

if [ "${#PATHS[@]}" -eq 0 ]; then
    echo "Nothing to export: data/logs and data/output/run_reports both missing." >&2
    exit 1
fi

tar -czf "$OUT" "${PATHS[@]}"
echo "Wrote $OUT ($(du -h "$OUT" | cut -f1))"
echo "Pull it with:  scp bjorn@<pi-host>:$REPO_DIR/$OUT ."
