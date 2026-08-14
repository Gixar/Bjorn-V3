# Improvement Plan — what is still open

> Baseline audited: **v3.0.1-beta**. Items that are done **and** proven have been removed from
> this file; `CHANGELOG.md` and git history hold them. What is left splits three ways by the
> kind of effort it needs.
>
> **Closed and removed:** **#1** RDP brute-force (Pi-verified, `bjorn_verify` Section 9) ·
> **#4** a wall-clock timeout on every network op (locked by an AST guard) · **#6** recursion /
> byte / free-space caps on every steal · **#7** atomic config + serialized writers.
>
> Suite at the time of writing: **363 passing**, tip `89bccc4`, in sync with `v3/main`.

## Index

Four items straddle two sections — the shipped half needs a run, the unshipped half needs code.
They are listed once in each, never described twice. A ✅ in the § 1 column means that half is
confirmed and its entry has been deleted; the § 2 half is still open.

| # | Item | § 1 run it | § 2 build it | § 3 not started |
|---|---|---|---|---|
| 2 | RDP + Telnet loot | Telnet steal (H) | RDP remote transport | |
| 3 | wpa-sec upload loop | live upload (G) | | |
| 5 | Outcome contract | | verification + lint + panel | |
| 8 | Parallel host execution | benchmark (D) | | |
| 9 | Vuln scan off critical path | | non-blocking sweep | |
| 10 | e-ink frame cost | refresh cadence (E) | | |
| 11 | Live web UI + weight | browser check (B) | dependency re-pin | |
| 12 | Base + adapters | connectors (C) | `BaseStealer` | |
| 13 | Web hardening | | auth / bind decision | |
| 14 | Real CI | ✅ confirmed 2026-08-14 | arm job + matrix | |
| 15 | On-device LLM triage | | | ✔ |
| — | Smart Planner V2 | observation window (F) | | |

---

# § 1 — Awaiting confirmation

**Nothing here needs a diff.** Every line of code is written and merged; what is missing is a
run that proves it.

**How this section is used:** the **Run sheet** below is numbered steps — every command, in
order, tagged with where to run it. The lettered entries after it explain what each result
*means*; read those only when a step is not a clean pass.

**Step numbers are stable identifiers and are never reused.** When an item confirms, its steps
and its lettered entry are deleted and the rest keep their numbers, so a note that says "step 11
failed" stays meaningful. Currently **4–19 remain**; 1–3 closed **A** on 2026-08-14.

**When an item confirms, delete it from this file** — but record the result first, in
`docs/BACKLOG.md` (sweeps and on-Pi runs) or `CHANGELOG.md` (behaviour and tuned values).
An item removed without a recorded result is indistinguishable from one that was never checked,
which is the exact failure this file exists to prevent.

---

## Run sheet

**Where:** `[dev]` = repo root on your machine · `[pi]` = ssh to the Pi, `cd /home/bjorn/Bjorn`
· `[web]` = browser. **`✓`** = what a pass looks like. Anything that is not a clean `✓` → read
that item's letter below.

---

**4. `[dev]`** — screen/log change tokens.

```bash
for i in 1 2 3; do
  curl -s http://<pi>:8000/api/stats \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["screen_version"],d["log_version"])'
  sleep 5
done
```

✓ non-zero, and they move between reads.

**✅ Passed 2026-08-14** against `192.168.1.35`. `screen_version` and `log_version` both move.
**Gotcha that cost a false FAIL first time round:** `log_version` reads **`0` until something has
hit `/get_logs` at least once since boot** — `data/logs/temp_log.txt` is created lazily by
`serve_logs` and deleted at startup by `shared.py:292`, and `_asset_mtime` correctly returns 0
for an absent file. Curl `/get_logs` once, then re-read. (That first call also always errors —
see the new row in `BACKLOG.md`.) Steps 5 and 6 are still outstanding, so **B is not closed**.

**5. `[web]`** — `http://<pi>:8000/` → **Ctrl+Shift+R** (a cached `dashboard.js` voids this) →
DevTools → Network → filter `screen.png`.

✓ idle: no repeating `screen.png` · preview still updates when the panel changes · console on:
`/get_logs` fires on new lines, not on a timer · restart the service: preview recovers, does not
freeze. → **closes B**

*Only `screen.png` and `/get_logs` are under test.* A repeating **`/api/stats`** every 3s is
**correct** — it is the WebSocket-fallback poller (`dashboard.js:114`), and it feeds
`applySnapshot`, which is itself token-gated. Reading it as a failure is the easy mistake here.

**6. `[web]`** — Settings → type a comma-separated portlist → Save → reload.

✓ round-trips as a list. → **closes #176**

---

**7. `[dev]`** — deploy current `main`. *(The installer skips an existing install; never
overwrite `config/shared_config.json`.)*

```bash
rsync -av --exclude 'data/' --exclude '.git/' --exclude 'config/shared_config.json' \
  ./ bjorn@<pi>:/home/bjorn/Bjorn/
ssh bjorn@<pi> 'sudo systemctl restart bjorn && systemctl is-active bjorn'
```

✓ `active`

**8. `[dev]`** — restamp the commit under test.

```bash
ssh bjorn@<pi> "printf 'synced_at=%s\nsource_commit=%s\n' \
  \"\$(date -Is)\" '$(git log -1 --format="%H %cs %s")' >> /home/bjorn/Bjorn/build_info"
```

**9. `[pi]`** — full verification sweep.

```bash
sudo python3 scripts/bjorn_verify.py --save
```

✓ Section 9 prints **three PASS** verdicts. A `WARN` is **not** a pass — see **C**.
→ **closes C**

**10. `[pi]`** — is parallelism engaging?

```bash
grep "Cycle work:" data/logs/orchestrator.py.log | tail -3
```

✓ `parallel workers=2` (expected on a Zero 2 W). `workers=1` with 3+ hosts = serial fallback.

**11. `[pi]`** — measure it. *(Needs 3+ alive hosts with open ports.)*

```bash
grep -E "Cycle work:|Action outcome:" data/logs/orchestrator.py.log | tail -30
```

✓ sum the `duration=` fields of one cycle, compare to the wall clock between its `Cycle work:`
line and its last `Action outcome:` line → **wall ≈ sum ÷ 2**, not ≈ sum.

**12. `[web]` + `[pi]`** — A/B. Settings → `host_parallel` = `1` → Save → restart → repeat step
11 → set back to `0`.

✓ serial run is measurably slower. → **closes D**

**13. `[pi]`** — watch the panel ~3 min. Ghosting → lower the constant; flashing → raise it.

```bash
sudo sed -i 's/^FULL_REFRESH_EVERY_FRAMES = .*/FULL_REFRESH_EVERY_FRAMES = 30/' display.py
sudo systemctl restart bjorn
```

✓ legible, no distracting flash, panel silent on a static screen. → **closes E**

---

**14. `[pi]`** — after several hours on a LAN with real targets.

```bash
grep "Planner chose:" data/logs/orchestrator.py.log | tail -20
python3 scripts/planner_report.py --path data/action_telemetry.json
```

✓ attempts accumulating · `estimated_success` moved **away from 0.5** · `duration_ewma_s`
plausible per action. → **closes F**
*(Reset: stop the service, delete `data/action_telemetry.json`, start it.)*

---

**15. `[pi]`** — wpa-sec preconditions. *(Set `wpasec_api_key` on the config page first.)*

```bash
which hcxpcapngtool
ls -la data/output/handshakes/
```

✓ the tool resolves · captures exist.

**16. `[pi]`** — upload half.

```bash
grep -o '"uploaded": "[^"]*"' data/output/handshakes/index.json | head
tail -n 30 data/logs/wpasec_import.py.log
```

✓ an `uploaded` timestamp, **one per BSSID**, and the capture visible on your wpa-sec dashboard.

**17. `[pi]`** — download half.

```bash
ls -la data/output/crackedpwd/wifi_wpasec.csv
sudo grep -n 'autoconnect-priority' /etc/NetworkManager/system-connections/wpasec-*.nmconnection
```

✓ a PSK in the CSV · priority is **`-10`**. Anything else → stop, P1 defect. → **closes G**

**18. `[web]`** — manual-attack dropdown → `StealFilesTelnet` against an authorized Telnet host
that already has a cracked credential in `data/output/crackedpwd/telnet.csv`.

**19. `[pi]`** — check what actually landed.

```bash
ls -la data/output/data_stolen/
sha256sum data/output/data_stolen/<file>
tail -n 40 data/logs/steal_files_telnet.py.log
```

✓ hash **matches the source file** — test a binary and a `$`-containing file. A file that arrives
*wrong* is the failure mode here; "a file appeared" is not a pass. → **closes H**

---

## What the results mean

### B. #11 — the event-driven dashboard was never opened in a browser

**What landed.** `get_stats_snapshot` (`utils.py:139-140`) carries two change tokens —
`screen_version` and `log_version`, each `os.stat(path).st_mtime_ns` via `_asset_mtime`, `0` if
the file is absent. Both ride on the `/ws/stats` push (every `stats_ws_interval`, default 2s)
**and** on `GET /api/stats`, so the fallback path is event-driven too.
`dashboard.js::applySnapshot` re-fetches `screen.png` and `/get_logs` only when its stored token
moves, and the blind `setInterval` pollers (2s image, 1.5s logs) are gone.

**Why it isn't proven.** Verified by trace only. There is no JS harness, and the server helper
sits behind the starlette import wall, so this class of change cannot be unit-tested in this
repo — the same "confident wrong answer" shape that has bitten here before.

**Pass:** tokens present, non-zero, and moving (step 4); no blind polling but still-live updates
(step 5); portlist round-trips (step 6).
**Fail:** three identical readings in step 4 while the panel is actively rendering means
`_asset_mtime` is resolving the wrong path — check `sd.webdir` and `sd.webconsolelog`. Requests
still repeating on a timer in step 5 is usually a cached `dashboard.js`; hard-reload before
concluding anything.

### C. #12 — the source verifier has not run since the four conversions

**What landed.** All six connectors are adapters on `base_connector.py` (`98780d4`, −528 net
lines). The scaffolding — `__init__` / `load_scan_file` / `worker` (with `task_done` in a
`finally`) / `run_bruteforce` (mac resolved *before* the queue fill, so #1 cannot recur) /
`save` / `dedupe` — exists exactly once.

The load-bearing part for verification: `bjorn_verify.py` Section 9, `test_bjorn_verify.py` and
`test_connector_netkb_reuse.py` parse each connector's *source* for those guarantees. Since they
now live in the base, the verifiers were taught to **follow delegation** — `_effective(src)`
returns `base_connector.py` when the connector contains the literal string
`from base_connector import` (`bjorn_verify.py:842`). All six carry that exact line today.

**Why it isn't proven.** The last full sweep ran against `83349da`, which **predates** the
SMB / Telnet / RDP / SQL conversions. Section 9 has only ever validated the SSH+FTP shape, and
the delegation-following logic has never had to resolve four adapters at once.

**Pass — Section 9 must print exactly these three verdicts:**

| Verdict | Expected detail |
|---|---|
| `PASS` brute force resolves mac/hostname before the queue fill | *"all six ordered correctly (the RDP fix is in the running code)"* |
| `PASS` a raising worker still drains its queue | *"task_done() is in a finally in every connector"* |
| `PASS` no UnboundLocalError logged at runtime | *"none in the orchestrator log"* |

**Fail — what each outcome means:**

- **`WARN … could not parse run_bruteforce in: <protocols>`** — the conversion-specific risk, and
  a *silent* loss of coverage rather than an error. Delegation did not resolve: the adapter's
  import line drifted from the literal `from base_connector import`, or the deployed
  `base_connector.py` is missing or stale. **A WARN is not a pass** — those protocols are no
  longer being checked at all.
- **`FAIL … referenced before assignment`** — the #1 ordering bug is in the running code; the
  deployed tree is behind. Re-sync (step 7) and re-run.
- **`FAIL … task_done() is not in a finally`** — a raising connect can skip `task_done()` and hang
  `queue.join()`, and with it the orchestrator. Regression in the base.
- **`FAIL … N UnboundLocalError in orchestrator.py.log`** — static and runtime disagree; a
  connector crashed mid-run. Trust the log over the source read.

Section 9 also prints info lines for cracked creds per protocol and the stolen-loot count, and
adds a `PASS` if `rdp.csv` is non-empty (*"the fix is confirmed end to end"*). Empty is the normal
result without a crackable target.

**Record:** `--save` writes the report under `data/output/`. Note the PASS/FAIL totals and the
`build_info` commit in `docs/BACKLOG.md` alongside the previous sweeps.

### D. #8 — parallel host execution has never been timed

**What landed.** `process_alive_ips` groups candidates by host row (MAC) and runs each group's
actions in planner order — so a same-host parent→child stays sequential and the child sees the
parent's row update — while **distinct host groups run concurrently** under a
`ThreadPoolExecutor`. Standalones stay serial (they share the radio and bettercap). A
per-action-class lock serializes two hosts needing the same connector singleton. Cycle-end
`write_data` is single-threaded and #7-locked.

**Know what to expect before measuring.** `_host_parallel_workers` (`orchestrator.py:190`) is a
budget, not a free-for-all:

```
budget = cores × 4
inner  = bruteforce_threads          # resolved at init: min(8, cores×4)
auto   = budget ÷ inner
cap    = min(host_groups, planner_max_host_actions)   # planner default 4
workers = min(cap, auto)
```

On a **Pi Zero 2 W** (4 cores): `budget=16`, `inner=8`, `auto=2` → with 3+ host groups,
**`workers=2`**. The honest expectation is roughly **2× on this board**, not `1/k` for arbitrary
`k`. If you want more, `bruteforce_threads` is what is eating the budget — that trade-off is what
the formula encodes: outer × inner must not thrash the board.

**Why it isn't proven.** The budget cap has a unit test
(`test_host_parallel_worker_count_stays_within_budget`). The wall-clock win does not.

**Pass:** wall clock at `host_parallel: 0` is meaningfully below the serial run, in the direction
of `sum ÷ 2` on this board.
**Fail — two distinct failures, do not conflate them:**

- **wall ≈ sum despite `workers=2`** — the per-action-class lock is serializing everything, i.e.
  the hosts are contending on the same connector singleton. Expected if both only offer SSH;
  retest with mixed services before calling it a defect.
- **the parallel run is *slower*** — the board is thrashing. Lower `bruteforce_threads` before
  lowering `host_parallel`.

**Record:** both wall-clock numbers, the host/action counts, and the board. An unqualified
speedup figure is exactly the claim this repo has learned not to make.

### E. #10 — the e-ink refresh cadence was picked, not tuned

**What landed.** The render loop's EPD write is a single `Display._display_frame(image)` that
mirrors `_write_screen_png`'s byte-compare gate: `image.tobytes()` is compared against the last
frame pushed and the panel write is **skipped when unchanged**. The duplicate `display_partial`
call is gone, `init_partial_update()` runs only when actually writing, and a full refresh fires
every `FULL_REFRESH_EVERY_FRAMES` (`display.py:35`, currently **60** ≈ once/min) via
`EPDHelper.display_full` + the existing `init_full_update`.

**Why it isn't proven.** 60 is a guess. Ghosting and flashing are physical properties of the
panel — no test can see them. This is the calibration knob a minimal model cannot infer.

Note this device runs `epd2in13_V3`; a V4 panel may want a different value (see the #113 note in
`BACKLOG.md` — that bug is blocked on buying a V4 panel).

**Pass:** legible after several minutes, no distracting flash, panel quiet on a static screen.
**Record:** the chosen value **and the panel model** in `CHANGELOG.md`. It is a knob, not a bug —
marked `ponytail:` in the source.

### F. Smart Planner V2 — learning has never seen a real target

**What landed.** A deterministic local-adaptation layer, no LLM and no new dependency: the
planner blends its static heuristic with a **Beta-smoothed success rate** and an **EWMA
duration** per action, learned into `data/action_telemetry.json` (atomic write, bounded to 512
records, no secrets or loot, gitignored). Retries became `(action, target)`-scoped with
cause-aware backoff. `action_outcome.py`'s `ActionOutcome`/`normalize_outcome` arrived in the
same batch — that is also #5's typed contract. Off-switch `smart_planner_enabled` (default true)
restores legacy scoring.

**Why it isn't proven.** The `+536%` useful-work/hour figure is from the synthetic
`mixed_lab_v1` fixture in `scripts/planner_benchmark.py` — a deterministic **scheduling
simulation** with precomputed outcomes. It is an ordering regression test, not a field promise,
and the file says so. No telemetry has ever been collected against a real network. This is the
one item that cannot be rushed: estimates start at their priors and only separate with attempts.

**Pass — three things, in order of what matters:**

- attempts accumulating and `estimated_success` moved **away from 0.5** for actions with history;
- `duration_ewma_s` in the right order of magnitude per action — a brute-force reading as 0.1s
  means it is returning early, not succeeding fast;
- the resulting order is defensible: cheap high-yield actions first. That is the whole claim.

**Fail:** if the ordering looks worse than the static heuristic on a real network, set
`smart_planner_enabled: false` and record why. That is what the off-switch is for.

### G. #3 — the wpa-sec loop has never talked to wpa-sec

**What landed.** `wpasec_import.py` uploads *then* downloads, closing the capture → crack →
auto-join chain. A completeness gate runs `hcxpcapngtool -o out.hc22000 <pcap>` and treats
non-empty output as a real EAPOL/PMKID capture (tool missing → log + skip, never a crash);
complete captures are deduped **by BSSID** so one AP uploads once; the multipart POST goes to
`?api` with `Cookie: key=`; the index entry is stamped `uploaded` with an ISO timestamp,
atomically, and `bettercap_pwn.build_index` carries `uploaded`/`complete`/`hc22000` forward across
a re-index. `_urlopen`/`_which`/`_spawn` are injectable, so the whole path tests offline.
`hcxtools` is installer-provisioned since `83349da` — before that the upload half silently
no-opped on a fresh install.

**Why it isn't proven.** No live upload has ever happened; everything above is exercised against
injected fakes.

**Pass — two separate claims, confirm them separately:** an `uploaded` stamp plus the capture
visible on the wpa-sec dashboard (upload); a PSK in `wifi_wpasec.csv` plus a `wpasec-<ssid>`
profile carrying `autoconnect-priority=-10` (download).

**That priority is load-bearing.** A cracked network must never outrank Bjorn's own uplink — the
author's rewrite dropped it once and it was restored on integration; `test_nmconnection_contents`
pins it.

**Fail:** *"hcxpcapngtool not installed"* → the install predates `83349da`;
`sudo apt-get install -y hcxtools`. Complete captures with no stamp and no error → check the API
key and that the POST reached `?api`.

### H. #2 — Telnet steal has never run against a live host

**What landed.** The base64 download was rebuilt so both historical failure modes are
*structurally* impossible rather than merely fixed:

- markers carry **underscores**, outside the base64 alphabet, so a marker can never collide with
  payload bytes;
- the remote command **splits the literals with `''`**, so the shell's command-echo carries
  `__BJORN''_B64_...` and not the contiguous marker `read_until` scans for — the echo can no
  longer be mistaken for the payload boundary.

Reliability is now at parity with SSH/RDP: connect + read timeouts, latch reset per run, a
`run_token`-guarded daemon timer, `telnet_connected` actually set on connect, and a bounded,
prompt-independent `find`. Telnet is back in `test_steal_modules.py::MODULES`, plus
`test_telnet_download_is_binary_safe_and_echo_proof`, which round-trips all 256 byte values and a
`$`-laden payload through a fake login shell reproducing the command-echo ordering.

**Why it isn't proven.** Unit-verified only. It also assumes `base64` exists on the target
(busybox or coreutils); if absent, the read yields nothing and the file is skipped with a logged
warning — never a crash, but never any loot either.

**Pass:** hashes match, including for a binary file and one containing `$`.
**Fail — the failure mode here is a file that arrives and is *wrong*,** not one that is missing.
A plausible-looking but truncated file is exactly what the old `cat` + `read_until(b"$")`
implementation produced. A *missing* file with *"base64 not found"* in the log is the benign
case — the target lacks the tool and the skip is working as designed.

*(RDP loot is the other half of #2 and is not here — it has no code yet. See § 2.)*

---

# § 2 — Partial: landed, but a piece is missing

**These need a diff.** Each shipped something real and stopped short; the named remainder is what
is left, with where to start. Ordered so the earlier ones unblock the later ones.

### #12 — `BaseStealer` (all six steal modules are still copy-paste)

**Landed.** The connector half. `base_connector.py` owns the scaffolding once and all six
connectors are adapters on it — SSH and FTP first (`15f7811`, `84d048b`; FTP went 187 → ~35
lines), then SMB, Telnet, RDP and SQL (`98780d4`, −528 net lines).

**Missing.** The six steal modules — ~1,250 LOC, ~85% duplicated. Extract `BaseStealer` with
abstract `connect` / `list` / `fetch`, centralizing threading, timeouts, the latch, the byte and
depth caps and atomic writes once.

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
dependency and no network, so #15's ordering half must beat a working baseline — and §1 F is what
establishes what that baseline actually achieves. Do F before committing to this.

---

## Sequencing

1. **§ 1 first — it costs no code.** Run-sheet steps 4–6 need only a reachable Pi and a browser;
   7–13 are one hands-on Pi session, and `bjorn_verify --save` (step 9) is the highest-value
   single command in this file. Confirming before building stops the next change landing on an
   unproven base — and C in particular is checking a verifier that has never run against the code
   it now has to resolve.
2. **§ 2 in order:** `BaseStealer` (#12) → RDP transport (#2) → #5's lint, then its `_last_error`
   panel, then side-effect verification.
3. **Decide #13** (a human call, not a diff), then #9's non-blocking sweep and #14's extra jobs.
4. **§ 3 last:** #15, and only after §1 F says what the deterministic planner already delivers.
