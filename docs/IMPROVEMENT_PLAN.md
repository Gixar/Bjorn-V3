# Improvement Plan — what is left to build

> Baseline audited: **v3.0.1-beta**. This file tracks only work that **needs code**. Items that
> were merely awaiting an on-hardware run were dropped on 2026-08-14 (they only grew the count);
> confirm on the device when convenient via `bjorn_verify.py --save` and `BACKLOG.md`, but they
> are not tracked here as open work.
>
> **Closed:** **#1** RDP brute-force · **#4** timeouts on every network op · **#7** atomic config +
> serialized writers · **#12 connectors** (verified on-Pi, `0fc93ea`) · **#12 stealers** (all six
> on `BaseStealer`), **#6** steal caps, and **#2** RDP loot — the four remaining adapters converted
> in `9b6906d` (2026-08-15) · **#14** real CI — the gate first, then the arm-emulation job + the
> 3.11/3.12 version matrix (`9b6906d`) · **#5** outcome contract — the two AST guards, the
> `_last_error` panel, and per-action side-effect verification across every action where the gap
> was real (WiFiScan, the six stealers, BLE, SNMP, the vuln scanner). `CHANGELOG.md` and git
> history hold them.
>
> Suite: **367 passing** (`9b6906d`). The RDP-steal FAIL from the last on-Pi sweep `0fc93ea`
> (37 PASS / 1 FAIL) is fixed in code — RDP now carries the #6 caps via `BaseStealer` — pending
> the next on-device sweep to confirm Section 9 reads 6/6.

## Index — what needs a diff

| # | Item | What is left |
|---|---|---|
| 9 | Vuln scan off critical path | non-blocking, planner-scheduled sweep |
| 15 | On-device LLM triage | not started |

**#12, #6, #2 and #14 are closed** — the steal adapters converged on RDP (`9b6906d`), and the same
commit landed #14's arm + version-matrix jobs.

**Out of the index (kept in §2 for reference, but not a repo diff):** **#11** dependency re-pin is
Pi-only ops — a runbook, no code change. **#13 is closed**: path safety shipped, and web UI auth
is a settled *no*.

---

# § 2 — Partial: landed, but a piece is missing

**These need a diff.** Each shipped something real and stopped short; the named remainder is what
is left, with where to start. Ordered so the earlier ones unblock the later ones.

### #12 · #6 · #2 — closed (`9b6906d`, 2026-08-15)

All six steal modules now sit on `base_stealer.BaseStealer`. SSH and Telnet landed first
(2026-08-14); the last four — SMB, FTP, SQL, RDP — converted in `9b6906d`, each a thin adapter
setting class constants and implementing `open_session` / `find_files` / `steal_file`, with
`b_*` globals unchanged so the orchestrator needed no edit. SMB and SQL kept their asymmetry
(SMB `harvest` iterates shares; SQL's login-is-the-win returns success on zero tables); FTP/SMB
try anonymous/guest first.

- **#6 (steal caps):** RDP was the last uncapped module. The caps live once on the base
  (`check_budget` / `fits_budget` / `note_bytes`), so all six are covered; `bjorn_verify`
  Section 9 should now read 6/6 on the next on-device sweep.
- **#2 (RDP loot):** RDP-steal verifies the credential (`+auth-only`, no more `/drive:shared`
  local-disk copy) and hands file collection to the SMB stealer on the same IP — the single
  adapter method the sequencing was waiting for. `_looks_like_local_root` stays as a backstop.

Still deferred (cheap now that it's once on the base, not six times): atomic temp+rename per
stolen file, and an inode-keyed rather than path-keyed visited-set. Detail in git history.

### #5 — the outcome contract *(closed — all three parts done, kept as the migration reference)*

**Landed.** `action_outcome.py` defines `ActionOutcome` / `OutcomeCode` / `normalize_outcome()`,
and the orchestrator wraps **every** `execute()` — legacy strings, mappings, an `ActionOutcome`,
or a raised exception all normalise to one typed outcome, with `should_stamp_failure` /
`skipped` deciding the netkb mark (a timeout or `FileNotFoundError` becomes `TIMEOUT` /
`UNAVAILABLE`, never a silent success). `test_smart_orchestrator.py` covers the boundary.
Separately, `BettercapPoller.poll_once` logs its first failure, backs off (30s → 30m cap),
records `_last_error`, and logs a recovery line — a wrong password used to mean **8,640 silent
failed polls a day** with nothing on screen.

**Missing, three pieces — start with the cheapest:**

1. ~~**A lint rejecting an unconditional `return 'success'`.**~~ ✅ **done 2026-08-14**
   (`tests/test_action_outcomes.py`), but **not as specified — the specified rule was wrong**, and
   the audit's list of offenders was stale. Reading the modules first: `web_template_scan` returns
   success unconditionally *on purpose* (*"scan completed; don't hammer the host every cycle"*),
   and for a recon action "ran, found nothing" is a success — marking it failed puts a healthy
   host into retry backoff. Of the four named, only `http_fingerprint` lacks a `'skipped'` path,
   and it guards its success on having rows. A literal lint would have been suppressed on day one.
   What shipped instead are two AST guards over `actions/*.py`, both discovering their targets
   rather than naming modules, so a new action is covered the day it lands:
   **(a)** every string an `execute()` returns must be in the vocabulary `_code_from` actually
   recognises — anything else silently becomes `FAILED`, stamps `failed_<timestamp>` and enters
   backoff, so a typo makes a *working* action report failure; **(b)** any `execute()` that gates
   on a `*_enabled`/`*_interval` setting must have a `'skipped'` return — the `WiFiScan: success=4`
   bug generalised off its hardcoded four-module list. Both were verified to **fail** on a planted
   break, not just pass on clean code — the #14 lesson.
2. ~~**`_last_error` on the web panel.**~~ ✅ **done `9b6906d` (2026-08-15).**
   `utils.get_stats_snapshot` exposes `bettercap_last_error` (from
   `bettercap_poller._last_error`); the bettercap panel shows it in red when non-null.
3. **Per-action side-effect verification.** The real work. Modules still self-report: success
   should mean the capture *wrote rows*, the radio *is* `managed`. **This defect class has now
   bitten four times** — `WiFiScan: success=4` for an action that never completed a capture,
   `release()` logging success on a radio it had not restored, "the status line that cannot
   fail", and #14's lint gate that could not fail. Self-reporting is the single common cause, and
   every instance was found by a human noticing, never by a test.

   **Started — WiFiScan is the first module migrated (the `success=4` action itself).** It now
   returns an `ActionOutcome` on the success path: it *honours `monitor_mode.release()`'s verified
   True/False* (which it previously discarded), returning `ERROR "radio not restored"` when the
   radio is stranded in monitor mode despite a good capture, and `SUCCESS` with an
   `evidence_count` otherwise. A planted-break test (`test_wifi_scan.py`) confirms a stranded
   radio no longer reads as success — the check the four humans had to be. Pattern for the rest:
   tie the success path to the observable side effect and return `ActionOutcome`; the `skipped` /
   `failed` string returns stay as-is (`normalize_outcome` accepts both).

   **Stealers migrated (`base_stealer`).** The default `harvest` returned `True` on files
   *found* (`len(remote_files)`), so a run that located five files and failed every transfer
   still logged `success` + `stolen 5 file(s)` with nothing on disk. `note_bytes` (called once
   per file a `steal_file` actually writes) now doubles as a per-run stolen counter, and both
   the default harvest and SMB's override tie success to that delta — no loot, no success. The
   SQL and RDP login-is-the-win overrides are untouched (they legitimately return `True` with
   zero files — the asymmetry §12 warned about). Guarded by a planted-break test.

   **Connectors need no change — a YAGNI call, stated.** `BaseBruteforce`/`BaseConnector` already
   set `success_flag` *after* `record_cracked_cred` + `save_results()` inside the worker's
   try/except, so a failed write blocks success. There's no discarded failure signal like
   WiFiScan's dropped `release()` bool, and SQL's zero-row login-is-the-win means a "row must be
   on disk" re-read would false-negative a real success. The gap is already closed; adding a
   re-read would cost IO and risk breaking a working contract.

   **BLE + SNMP done.** `ble_scan` reported `success` every cycle on a Pi with no Bluetooth
   controller (it swallowed all three `bluetoothctl` results); `_scan` now returns `None` on
   `No default controller available` and execute skips — a scan that cannot run is not a success.
   `snmp_enum` recorded a host as a found SNMP service when `snmpget -Ovq` exited 0 while printing
   `No Such Object available…` for an unserved OID; `_clean_value` now filters those net-snmp
   non-answers, so a recorded hit is a real value. Both have planted-break tests, and both keep
   "ran, found nothing" as `success` (the recon convention #5's AST-guard work established — a
   healthy host with nothing to show must not enter failed-retry backoff).

   **nmap_vuln_scanner done.** `scan_vulnerabilities` keyed success on nmap not *raising*, but
   `subprocess.run` doesn't raise on a non-zero exit — so a nmap that errored (bad args, no
   permission for `-sV`, an unresolvable target) returned its stdout and execute stamped
   `success_<ts>`, and with `retry_success` off the host was never re-scanned. It now returns
   `None` (→ the existing `'skipped'` path) on a non-zero exit, surfacing nmap's stderr. nmap
   exits 0 even when hosts are down, so a clean scan that found no vulns still succeeds. Planted-
   break test.

   **Effectively complete.** The remaining candidate, `http_fingerprint`, already returns
   `'failed'` unless it built rows *and* `_save`'d them (it guards `if not rows: return 'failed'`
   before writing), so it has no self-report gap to close. #5's side-effect verification is done
   across every action where the gap was real: WiFiScan, the six stealers, BLE, SNMP, and the vuln
   scanner; the connectors and http_fingerprint were examined and already tie success to their
   writes.

Migration is opt-in per module (return an `ActionOutcome`), so this is incremental, not a rewrite.

### #9 — the vuln sweep still blocks the idle branch

**Landed.** `orchestrator._run_vuln_scans` replaced the serial idle-branch loop with a bounded
`ThreadPoolExecutor(max_workers=2)` — 2, not #8's budget, because nmap is CPU-heavy rather than
I/O-bound. It keeps #4's per-host `subprocess.run(timeout=300)` and the success/failed
retry-delay skip gates, and it fixed a latent silent lie: `skipped` now leaves **no** netkb mark,
matching `NmapVulnScanner.execute()`'s own contract, where the old loop wrongly stamped it
`failed_`. Covered by `test_vuln_scan_submits_only_eligible_hosts_and_stamps_results`.

**Missing.** It still runs *inside* the idle branch and blocks it until done, rather than being a
planner-scheduled standalone. A true non-blocking background sweep means a long-lived worker
outside the cycle, which raises netkb write ordering against #7's locks — a larger, riskier
change, deliberately deferred.

### #11 — the dependency re-pin *(out of the index — Pi-only ops, no repo diff)*

**Landed.** pandas is gone end to end: `2579fc3` moved the last three modules to stdlib `csv`,
the `pandas==2.2.3` pin was dropped from `requirements.txt` on 2026-08-14 (with its row in
`bjorn_diag.sh`'s dependency probe, or a fresh install would report the absent package as
`NOT IMPORTABLE`), and it is **verified by absence** on hardware — uninstalled from the Pi,
`import pandas` → `ModuleNotFoundError`, Bjorn boots `active` with `NRestarts=0`. `numpy` stays;
the Waveshare driver needs it.

**Missing.** The stale 2024 pins in the rest of `requirements.txt`. Pi-only work.

**Do it wheels-only, one package per restart:**

```bash
pip3 install --break-system-packages --upgrade --only-binary=:all: <one-package>
sudo systemctl restart bjorn && systemctl is-active bjorn
```

A bulk `--upgrade` of all 14 pins **took the device down** on 2026-08-14. Two compounding
failures worth knowing before repeating it:

1. **piwheels metadata casing** (`expected 'Pillow', metadata has 'pillow'`) makes modern pip
   **discard the prebuilt wheel** and fall back to a source build. With no `libfreetype6-dev` on
   the Pi, Pillow 12.3.0 then built **without `_imagingft`**, `ImageFont.truetype` raised
   `ImportError` at `shared.py:641`, and Bjorn crash-looped. The same discard hit pymysql and
   sqlalchemy, but those are pure-Python so it was harmless there.
   **If pip says `Downloading <pkg>.tar.gz`, abort** — `--only-binary=:all:` makes it fail loudly
   instead of silently building.
2. **Rolling back with `-r requirements.txt` restored the app but not the service** — that was
   the heartbeat watchdog bug (`8ea517a`, since fixed by `ExecStartPre=/bin/rm -f
   /run/bjorn_heartbeat`). Existing installs predating that fix need a drop-in at
   `/etc/systemd/system/bjorn.service.d/heartbeat.conf`; the installer only writes the unit at
   install time.

There is no venv here (PEP 668 forces `--break-system-packages`), so every install is
system-wide and shared, and **removing a pin never uninstalls what is already there**.

Recovery if it happens again:

```bash
systemctl stop bjorn; rm -f /run/bjorn_heartbeat; systemctl reset-failed bjorn
cd /home/bjorn/Bjorn && python3 Bjorn.py
```

The foreground run is what separates "app broken" from "watchdog killing a healthy app".

### #13 — closed. Path safety shipped; web auth is **dropped, do not reopen**

**Landed.** The two remotely-exploitable file holes are closed by `path_safety.py` — a
dependency-free, unit-tested module in the same standalone shape as `retry_policy` and
`config_validation`. `safe_under` does a realpath + commonpath containment check, wired into
`download_file` and `download_backup` (404 on escape); `zip_escapes` validates every member
before `restore` extracts a byte, and the upload's own filename is `basename()`d — a
`../evil.zip` name used to write the archive outside `upload_dir`. Tests in
`tests/test_path_safety.py` cover traversal, absolute-path bypass and zip-slip.

**Web UI auth / bind: decided against, twice (2026-08-05 and again 2026-08-15).** Bjorn is a
single-user device whose operator controls access to it. This is a settled product decision, not
an open risk to re-raise: **do not put it back in the backlog, the index, a status report, or a
review.** No further code is owed on #13.

### #14 — closed (`9b6906d`, 2026-08-15)

The deferred CI jobs landed. The `test` job runs a **3.11/3.12 matrix**, and a new **`test-arm`**
job runs the suite on **armv7 via QEMU** (`uraimo/run-on-arch-action`, pinned to a commit SHA)
with the same `requirements-ci.txt` filter and `tests/_stubs.py` — the job that catches a Pi-only
import or an armv7 wheel problem before a device does. Not yet observed green on a real run; watch
the first push.

---

# § 3 — Not started

### #15 — the bold bet: on-device, out-of-band LLM triage

**No code exists.** The PRD's entire **P-AI** section is scoped but deferred, and roughly half
the groundwork already exists offline in `scripts/analyze_reports.py`, which summarizes
run-reports via Claude.

**The shape, within the PRD's own guardrails.** Between cycles — **never in the hot loop** — hand
the redacted netKB to **Claude Haiku** to:

- **re-rank the next targets** with a rationale short enough for the e-Paper to show;
- **write the P2 defensive audit report** — per-finding severity plus remediation.

**Non-negotiables carried over from the PRD:** it degrades to today's heuristic planner with no
key or no network; there is a per-run token budget; and findings expose Bjorn's actions as
**typed, authorization-gated tools** — the harness decides what may run, not the model. It
reasons over Bjorn's *own findings* for triage and remediation, **not** novel exploit generation.

**Why it is last.** Smart Planner V2 already does deterministic local re-ranking with no
dependency and no network, so #15's ordering half must beat a working baseline.

---

## Sequencing

1. ~~**Finish #12's adapters:** SMB, FTP, SQL, then RDP — RDP closes #6 and #2.~~ ✅ `9b6906d`.
2. ~~**#14's arm-emulation + version-matrix jobs.**~~ ✅ `9b6906d` (watch the first armv7 run).
3. ~~**#5's side-effect verification.**~~ ✅ across WiFiScan, the stealers, BLE, SNMP, the vuln scanner.
4. **#9's non-blocking sweep.** Out of band: re-pin #11 on the Pi.
5. **#15 last.**
