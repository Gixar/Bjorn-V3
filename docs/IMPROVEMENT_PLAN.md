# Improvement Plan — what is left to build

> Baseline audited: **v3.0.1-beta**. This file tracks only work that **needs code**. Items that
> were merely awaiting an on-hardware run were dropped on 2026-08-14 (they only grew the count);
> confirm on the device when convenient via `bjorn_verify.py --save` and `BACKLOG.md`, but they
> are not tracked here as open work.
>
> **Closed:** **#1** RDP brute-force · **#4** timeouts on every network op · **#7** atomic config +
> serialized writers · **#14 CI gate** and **#12 connectors** (verified on-Pi, `0fc93ea`).
> `CHANGELOG.md` and git history hold them.
>
> Suite: **367 passing**. Last on-Pi sweep `0fc93ea` (2026-08-14): 37 PASS / 1 FAIL — the FAIL is
> #6 below (RDP steal uncapped).

## Index — what needs a diff

| # | Item | What is left |
|---|---|---|
| 12 | Base + adapters | convert SMB, FTP, RDP, SQL steal modules (SSH + Telnet done) |
| 6 | Steal caps | RDP steal uncapped — lands when its adapter converts |
| 2 | RDP loot | RDP remote transport — lands as one adapter method |
| 5 | Outcome contract | `_last_error` web panel · per-action side-effect verification |
| 9 | Vuln scan off critical path | non-blocking, planner-scheduled sweep |
| 11 | Dependency re-pin | refresh the stale 2024 pins (Pi-only, wheels-only) |
| 13 | Web hardening | the auth / bind decision (needs a human call) |
| 14 | Real CI | arm-emulation job · Python version matrix |
| 15 | On-device LLM triage | not started |

**#12, #6 and #2 converge on the RDP adapter** — one conversion closes all three.

---

# § 2 — Partial: landed, but a piece is missing

**These need a diff.** Each shipped something real and stopped short; the named remainder is what
is left, with where to start. Ordered so the earlier ones unblock the later ones.

### #12 — `BaseStealer` (all six steal modules are still copy-paste)

**Landed.** The connector half. `base_connector.py` owns the scaffolding once and all six
connectors are adapters on it — SSH and FTP first (`15f7811`, `84d048b`; FTP went 187 → ~35
lines), then SMB, Telnet, RDP and SQL (`98780d4`, −528 net lines).

**Landed 2026-08-14: `base_stealer.py` + the SSH adapter.** The shared flow — parent gate, latch
reset, credential load, run-token watchdog, credential loop, outcome contract, and the #6 budget
helpers — exists once. `steal_files_ssh.py` went **192 → 108 lines** and is the proof the shape
fits. Three decisions recorded in the module docstring so they are not re-litigated: the connect
hook is **`open_session`, not `connect`** (a method named `connect` collides with the #4 timeout
AST guard's callee match and would fail it for a rule that does not apply); each adapter keeps its
own `LOGGER` so the flow still lands in `data/logs/steal_files_<proto>.py.log` where every runbook
looks; and the latch reset stays inside `execute()`.

Both source-parsing tests were taught to follow delegation — `test_status_settle.py` and
`test_steal_modules.py::test_the_reset_is_present_in_source_for_every_module` — exactly as
`bjorn_verify` Section 9 was for the connectors. Verified by planting a break in the base: both
fired. 365 passing.

**Telnet converted (`68e61db`+):** `steal_files_telnet.py` 257 → 185 lines. Less dramatic than
SSH because the base64/marker transport is genuinely Telnet-specific and stays; the shared flow
still moved to the base, and it gained the #6 caps it never had (with a `wc -c` size probe before
the in-memory base64 transfer).

**Missing.** Four adapters: SMB, FTP, RDP, SQL. SMB and SQL need one extra seam each (SMB
iterates shares, SQL iterates tables/schemas, and both plus FTP have an anonymous-access
fallback), so expect the base to grow one hook that defaults to current behaviour — the same way
`base_connector` grew `result_rows`/`after_queue`.

**Do this first.** It is the unblocker:

- RDP-steal's remote transport (#2 below) lands as **one adapter method** instead of a seventh
  copy;
- #6's two deferred minors land once instead of six times — an atomic temp+rename per stolen file
  (today a crash leaves an incomplete loot file; the error path already unlinks partials, so this
  is tidiness, not correctness) and an **inode-keyed** rather than path-keyed visited-set;
- the caps stop being six sets of constants that can drift — `steal_data_sql.py` already shipped
  once *referencing* four of them without defining them, a guaranteed `NameError`.

**Where the shape is already decided.** Follow `base_connector.py`: subclass sets class
constants, implements the one protocol-specific method, `b_*` globals unchanged so the
orchestrator needs no edit. Teach the source-parsing verifiers the same delegation trick if they
grow to cover steal modules.

**Do not "simplify" this on the way past.** In `base_connector`, `attempt()` is
truthy-not-`True`, and SMB and SQL **deliberately disagree** about the empty list: for SMB, no
readable share is no win, so `[]` is correctly falsy; for SQL the login *is* the win — the
pre-#12 worker recorded the cracked credential with zero databases visible — so it returns
`databases or True`. Unifying them silently drops a valid credential. Both directions are pinned
by tests. Expect the same asymmetry class in the stealers.

### #6 — reopened: caps were missing on three of six, RDP is the last

**This was marked ✅ DONE and deleted from this file.** The claim was *"every steal enforces a
free-space precheck, a per-file cap and a per-run budget"*. Actual state, with the closing gaps:

| Module | byte caps | free-space check |
|---|---|---|
| `steal_files_ftp` · `steal_files_smb` · `steal_data_sql` | ✅ | ✅ |
| `steal_files_ssh` | ✅ *(2026-08-14 via `base_stealer`)* | ✅ |
| `steal_files_telnet` | ✅ *(2026-08-14 via `base_stealer`)* | ✅ |
| `steal_files_rdp` | ❌ **none** | ❌ **none** |

The earlier fix was not wrong — it covered the three modules its author-supplied patch set
touched, and the completion was recorded as universal. **RDP is the one module left**, and it
lands free the moment that adapter converts.

**Missing.** RDP only. The caps live on `BaseStealer` as `check_budget` / `fits_budget` /
`note_bytes`, so the adapter cannot forget what it does not have to remember. **Do not patch it in
place** — that recreates the sixth copy this refactor is deleting.

**Now machine-checked.** `bjorn_verify` Section 9 counts caps per module and fails naming the
gaps; after the Telnet conversion it reads `steal byte/space caps  5/6 capped: SSH, SMB, FTP,
Telnet, SQL` with the FAIL narrowed to RDP. This item cannot silently be recorded as done again —
the same sweep that once read 32 PASS / 0 FAIL was clean only because nothing asked.

Still deferred from the original item, and now cheap to do once on the base rather than six times:
an atomic temp+rename per stolen file, and an inode-keyed rather than path-keyed visited-set.

### #2 — RDP loot has no remote transport

**Landed.** The RDP steal module is hardened and safe: a 30s `xfreerdp` connect timeout, and a
`_looks_like_local_root` guard that refuses to run when `/mnt/shared` looks like the Pi's own
filesystem — the original bug was that `find_files` did `os.walk("/mnt/shared")` **locally**, so
it copied Bjorn's own disk and reported success.

**Missing.** It still cannot pull remote files at all. `/drive` redirection plus `+auth-only`
fundamentally cannot — the redirect exposes the *Pi's* directory *to* the session, not the
reverse. This needs a different transport: SMB against the same host (most likely — the SMB
stealer already exists and the credential pool may already hold a working cred), or a staged
remote command.

**Sequenced deliberately after `BaseStealer`** so the transport is written once, as an adapter
method. The deferral is documented in the module's own docstring.

### #5 — the outcome contract is two-thirds done

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
2. **`_last_error` on the web panel.** The poller records it; nothing surfaces it. One field in
   the stats snapshot and one line in the bettercap panel.
3. **Per-action side-effect verification.** The real work. Modules still self-report: success
   should mean the capture *wrote rows*, the radio *is* `managed`. **This defect class has now
   bitten four times** — `WiFiScan: success=4` for an action that never completed a capture,
   `release()` logging success on a radio it had not restored, "the status line that cannot
   fail", and #14's lint gate that could not fail. Self-reporting is the single common cause, and
   every instance was found by a human noticing, never by a test.

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

### #11 — the dependency re-pin

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

### #13 — the auth / bind decision

**Landed.** The two remotely-exploitable file holes are closed by `path_safety.py` — a
dependency-free, unit-tested module in the same standalone shape as `retry_policy` and
`config_validation`. `safe_under` does a realpath + commonpath containment check, wired into
`download_file` and `download_backup` (404 on escape); `zip_escapes` validates every member
before `restore` extracts a byte, and the upload's own filename is `basename()`d — a
`../evil.zip` name used to write the archive outside `upload_dir`. Tests in
`tests/test_path_safety.py` cover traversal, absolute-path bypass and zip-slip.

**Missing — and it is a decision, not a patch.** The web UI is unauthenticated on `0.0.0.0:8000`:
`/load_config` returns `telegram_bot_token` / `smtp_password` / `wpasec_api_key` to anyone who
can reach the port, and `/reboot`, `/shutdown` and `/execute_manual_attack` are open, alongside
pages listing cracked credentials and stolen loot outright.

The "no auth — the operator controls the network" call was made on 2026-08-05 and was correct
**for a stationary device**. **V3's headline feature is carrying it onto networks it does not
control**, so the premise the decision rested on no longer holds. The 2026-08-05 entry in
`BACKLOG.md` still says *"do not revisit unless that deployment assumption changes"* — it has
changed; that is precisely why this is open.

Two options, and picking one is the blocker:

- **Bind `127.0.0.1` by default**, with an opt-in token for LAN access. Safest; the real cost is
  that it changes how the operator reaches the dashboard remotely.
- **A shared-secret gate on the destructive and secret-serving endpoints only.** Smaller change,
  leaves the read-only pages open — and masking one endpoint while the rest still list loot is
  the exact half-measure the original decision rejected.

Needs a human call before any code.

### #14 — the deferred CI jobs

**Landed.** The `test` + `lint` split, the installable-subset trick for the three Pi-only pins,
core modules under lint for the first time, and a gate that can actually fail.

**Missing, deferred by choice rather than blocked:** an **arm-emulation job** matching the Pi
target — the one that would catch a Pi-only import or an armv7 wheel problem before a device does
— and a **Python version matrix**. Both are additive workflow changes with no code impact.

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

1. **Finish #12's adapters:** SMB, FTP, SQL, then **RDP** — RDP closes #6 (caps) and #2 (remote
   transport) in the same conversion.
2. **#5's `_last_error` panel**, then its side-effect verification.
3. **Decide #13** (a human call, not a diff), then #9's non-blocking sweep and #14's extra jobs.
4. **#15 last.**
