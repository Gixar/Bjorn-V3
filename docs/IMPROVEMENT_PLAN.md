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
> Suite: **411 passing**. On-device sweep 2026-08-19 (`bf18e2c`): **39 PASS, 0 FAIL**, 4 WARN,
> 3 SKIP. The RDP-steal FAIL from `0fc93ea` (37 PASS / 1 FAIL) is confirmed closed — Section 9
> reads 6/6, "all six enforce per-file/per-run budgets and a free-space precheck". Every remaining
> WARN is *needs a target*, not a defect: SNMP, web templates and credential reuse have no rows
> because nothing on this network answers. That is §4's lab, not a bug.

## Index — what needs a diff

| # | Item | What is left |
|---|---|---|
| 15 | On-device LLM triage | audit half shipped; **target re-ranking deliberately not built** — see §3 |

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

### #9 — closed. The vuln sweep is off the cycle

**Landed.** `orchestrator._run_vuln_scans` replaced the serial idle-branch loop with a bounded
`ThreadPoolExecutor(max_workers=2)` — 2, not #8's budget, because nmap is CPU-heavy rather than
I/O-bound. It keeps #4's per-host `subprocess.run(timeout=300)` and the success/failed
retry-delay skip gates, and it fixed a latent silent lie: `skipped` now leaves **no** netkb mark,
matching `NmapVulnScanner.execute()`'s own contract, where the old loop wrongly stamped it
`failed_`. Covered by `test_vuln_scan_submits_only_eligible_hosts_and_stamps_results`.

**Closed (2026-08-15).** The sweep now *submits* and returns. `_run_vuln_scans` hands each
eligible host to a long-lived 2-worker pool; `_apply_vuln_results` drains finished scans at the
top of a later cycle and stamps netkb from the main thread. What it cost before: with each nmap
bounded at 300s (#4), a ten-host sweep held the orchestrator for up to **25 minutes** — no
rescan, no connectors, no stealers, no standalone recon, and `stop_orchestrator()`'s un-timed
`join()` waiting it out on shutdown.

**The netkb-ordering risk that deferred this turned out to be avoidable rather than manageable.**
The worry was a background worker racing #7's locks. It doesn't, because no worker touches netkb:
each reads a snapshot of its row and puts `(ip, result)` on a `queue.Queue`, and every write still
happens on the main thread inside the existing single-writer discipline. **No new lock was added.**
Three details that are not obvious:

- Results are keyed by **IP, not row object** — `read_data()` builds new dicts every cycle and
  minutes pass between submit and completion, so the submitted row no longer exists. A host that
  left netkb meanwhile is dropped with a log line.
- An **in-flight set** stops the interval gate stacking a second scan onto a host already being
  scanned; it is main-thread-only, so it needs no lock either.
- `_vuln_worker` reports in a **`finally`** — a worker that raises past its own `except` would
  otherwise strand its IP in-flight forever, making that host permanently unscannable. That is
  the #5 defect class (a silent permanent skip) reappearing in new clothes.

**Deliberately not done: planner-scheduled.** The index called for "non-blocking, planner-scheduled".
Scheduling it through the planner was worth doing only because the sweep blocked; now that it is
fire-and-forget, moving the trigger from the interval gate to a planner score is a
reorganisation with no behaviour change to show for it. Say so if you want it anyway.

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

# § 3 — #15, the bold bet: on-device, out-of-band LLM triage

The PRD's **P-AI** section names two halves. **The audit half shipped; the re-ranking half is
deliberately not built.**

### Shipped — the defensive audit

`AIAudit` (`actions/ai_audit.py`) is a standalone action, so it runs in the idle window between
cycles, never on the hot loop. It hands the redacted netkb to **Claude Haiku** and writes the
returned Markdown to `data/output/reports/ai_audit_<ts>.md`: hosts ordered by risk, each finding
with why it matters and the concrete fix, closing with the highest-leverage actions.

**`ai_triage.py` is the part that matters** — a standalone, dependency-free module in the same
shape as `path_safety` / `retry_policy`, holding the one rule worth testing: *no secret leaves the
device*. It is an **allowlist, not a denylist** — each host record is built field by field
(`IPs`, `Ports`, which checks succeeded, CVE tokens), never copied-then-scrubbed. A denylist leaks
the day someone adds a netkb column, so a test plants exactly that regression. Cracked credentials
and loot are not filtered at all: those live in `crackedpwd/` and `stolen_data/`, and this module
never reads those files. MAC addresses and hostnames are dropped (hardware ID; routinely a
person's name) — a remediation report addresses hosts by IP. Action marks are reduced to the verb,
so `success_<ts>` becomes `success`: the timestamp is a fingerprint of operator activity and
tells the model nothing.

**The PRD's non-negotiables, and how each is met:**

- **Degrades, never fails.** No key, no `anthropic` package, no network, nothing alive, or not yet
  due → `'skipped'`, which leaves no netkb mark. `b_needs_internet = True` means the orchestrator
  skips it outright while offline. Default is **off** (`ai_triage_enabled: false`).
- **Per-run token budget.** `ai_triage_max_hosts` caps the input, `max_tokens` caps the output,
  and the response's token usage is logged so the spend is observable rather than assumed.
- **Authorization-gated tools.** Satisfied by construction: the model is given **no tools at all**.
  It receives findings and returns prose; nothing it emits can run. That is the cheapest possible
  version of "the harness decides what may run" and the only one worth having while the output is
  a report.
- **Its own findings, not exploit generation.** The system prompt is explicitly defensive and
  states that the credential itself is never supplied.

**The API key is read from `ANTHROPIC_API_KEY` in the environment, never from
`shared_config.json`** — the web UI's `/load_config` serves that file verbatim to anyone who can
reach port 8000. Set it in the systemd unit. `anthropic` is deliberately **not** in
`requirements.txt`: it is an opt-in extra, imported lazily, and absent from CI (hence the
`.pylintrc` `ignored-modules` entry).

### Not built — target re-ranking, and why

Smart Planner V2 already re-ranks deterministically with no key, no network and no dependency, and
this file said from the start that #15's ordering half **must beat that baseline**. Nothing here
measures it yet, so shipping an LLM ordering now would swap a working planner for an unmeasured
one that also costs money and needs a network. The audit half has no local equivalent, so it is
pure addition — that asymmetry is the whole reason for the split.

If the re-ranking half is wanted, the honest first step is a bake-off, not a feature: run
`scripts/planner_benchmark.py` against a Haiku ordering on the same netkb and compare. Say so and
it gets built.

**Untested on hardware:** no live API call has been made from a Pi — the tests use an injected
fake client. Needs `pip install anthropic` and a key on the device.

---

# § 4 — 2026-08-19: what a day of running it on hardware actually found

Nothing in this section was on the list. Every item was found by running the thing on the Pi and
reading its logs, and every one had been shipping for a while. Recorded because the *pattern*
matters more than the individual fixes: each defect was silent, and the ones that were not silent
were buried under warnings nobody reads.

**The chain, in the order it unravelled:**

1. **`5aecb8b` — every `ThreadPoolExecutor` was dead.** `Bjorn.py`'s `__main__` registered its
   signal handlers and returned. The main thread finishing *is* the start of interpreter shutdown,
   and `threading._shutdown()` runs `concurrent.futures`' atexit hook **before** joining
   non-daemon threads — so the futures module was flagged shut down for good while the display,
   web and orchestrator threads kept the process alive for days. Every later `submit()` raised
   `cannot schedule new futures after interpreter shutdown`. The vuln sweep (#9) had therefore
   **never run** in the life of any process; `process_alive_ips`' per-host pool sat on the same
   landmine, unexposed only because the worker budget had been 1. Fix: `__main__` joins the
   threads it started.

2. **`4bf85a4` — `-p ""`.** With the sweep alive, nmap immediately failed on five of seven hosts:
   `Error #485: Your port specifications are illegal`. netkb stores `""` for a host with nothing
   open, and `"".split(";")` is `[""]`, not `[]`. Fixing one bug is what surfaced the other.

3. **`23ab2bf` + `4eeae4d` — the monitor-mode window `60001bc` did not close.** Captures were
   still dying with `ARP linktype is set to 1 (Ethernet)` *with* that fix deployed. Sampling
   `/sys/class/net/wlan1/type` every 10ms showed the netdev oscillating `803 → 1 → 803` over
   ~100ms after `ip link set up`, so a single matching read could land on the opening blip.
   Requiring the type to *hold* fixed the failure but revealed the real cause: `nmcli ... managed
   no` returns when NetworkManager has released the device, and **wpa_supplicant's teardown
   follows 336ms later and resets the interface to station mode**, undoing a mode change issued in
   between. `acquire()`'s first attempt had therefore never once succeeded — 67 `redoing the mode
   change` warnings in the log, and the retry that "fixed" it only worked because wpa_supplicant
   was gone by then. Now it waits for `/run/wpa_supplicant/<iface>` to disappear first. Cold
   acquire went 4.33s → 1.16s, and the flap stopped happening at all.

4. **`e5d9b9e`, `b84ce0d`, `0bfee98` — the noise that hid all of the above.** Three hours of
   journal held 49 + 30 WARNING lines for the healthy steady state (portless hosts, retry-delay
   gates), and every boot added 8 more for actions that have no e-paper artwork. A level that
   fires for a condition nobody intends to change is a level nobody reads — which is precisely how
   `wlan1 is up but still typed Ethernet` sat unnoticed 67 times. A full boot + sweep now logs
   **zero** WARNING lines.

5. **`bf18e2c` — the third and last `[""]`.** `/netkb_data_json` handed the manual-attack dropdown
   one blank port per portless host. `scanning.py` had guarded this idiom, `nmap_vuln_scanner`
   needed it, this was the one left.

**Also fixed on the device, not in the repo:** `systemd-timesyncd` was enabled, active, reporting
"Daemon is running" — and holding no UDP socket, having never attempted a query on any boot. It
waits on `systemd-networkd` link state, and every link here is `unmanaged` because NetworkManager
owns them. The clock was **14h35m** behind, so every log timestamp and every netkb retry gate
(`success_retry_delay`, `failed_retry_delay`) was comparing against fiction. Replaced with chrony,
which does not consult networkd: synced in seconds, `fake-hwclock` now saves a correct time for
offline boots.

**What this says about the plan.** Items closed on green tests were not wrong, they were untested
in the only environment that counts. The one item that would have caught all of it earlier is the
one still open: §4 of Sequencing, a target that answers.

---

## Sequencing

1. ~~**Finish #12's adapters:** SMB, FTP, SQL, then RDP — RDP closes #6 and #2.~~ ✅ `9b6906d`.
2. ~~**#14's arm-emulation + version-matrix jobs.**~~ ✅ `9b6906d` (watch the first armv7 run).
3. ~~**#5's side-effect verification.**~~ ✅ across WiFiScan, the stealers, BLE, SNMP, the vuln scanner.
4. **Stand up the weak-target lab** — [`WEAK_TARGET.md`](WEAK_TARGET.md). The connectors, the
   credential pool and all six stealers have never run against a host that answers; every sweep to
   date verified plumbing only. One afternoon, and it is worth more than any remaining item here.
   **Now the only open item, and §4 is the argument for it:** a day on hardware found five silent
   defects that green tests and a passing verifier both missed, and the three WARNs still in the
   sweep (SNMP, web templates, credential reuse) all read *needs a target*.
5. ~~**#9's non-blocking sweep.**~~ ✅ 2026-08-15. Out of band: re-pin #11 on the Pi.
6. ~~**#15 last.**~~ ✅ audit half shipped 2026-08-15; re-ranking half needs a bake-off first (§3).
7. **Field soak.** The radio path is the freshest code in the tree — `4eeae4d` has ~13 clean
   capture cycles behind it, which is consistent with fixed but is not a soak. An offline run away
   from a known network exercises exactly the paths that were broken: `acquire()` from cold,
   offline cycling with no uplink, and the handshake hunter holding `wlan1` for hours.
