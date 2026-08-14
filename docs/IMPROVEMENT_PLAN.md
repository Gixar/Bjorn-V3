# Improvement Plan — 15 bold moves for a ≥30% better Bjorn

> Baseline audited: **v3.0.1-beta**. Read end-to-end: the orchestrator/planner spine, all 6
> connectors, all 6 steal modules, display/web, bettercap/offline stack, and the infra/install
> layer. Every finding below is anchored to `file:line`.

## The headline

Bjorn *looks* finished — 313 tests, RustScan, a scored planner, offline mode, atomic writes.
But the audit found **three capabilities you already paid for that are silently dead**, a
**hang class that can freeze the whole device**, and an orchestrator that **attacks one host at a
time while the Pi sits idle**. Fixing those isn't polish — it's a step-change in how much authorized
testing Bjorn actually gets done per hour.

**What "30% better" means here** (three independent axes, each cleared on its own):

- **Effectiveness** — successful authorized actions per hour. Restoring RDP brute-force, RDP+Telnet
  loot, and the handshake→crack loop brings back **~3 of ~12 offensive modules that currently do
  nothing**, before any speed work. That alone is >30%.
- **Throughput** — cycle wall-clock. Parallel host execution + a non-blocking vuln scan + halving
  the e-ink cost cut sweep time on a multi-host LAN by far more than 30%.
- **Reliability** — the freeze/silent-lie rate. Timeouts + an outcome contract + atomic config
  remove the failure modes that make a run stall or lie about what it did.

Exact percentages need on-Pi benchmarking (this repo's own discipline). The *direction and
magnitude* are not in doubt.

---

## Progress

**2026-08-11 — Tier 1 #1 shipped and verified on hardware.** RDP brute-force is fixed and confirmed
live on a Pi Zero 2 W, now on `Bjorn-V3/main` (tip `5100b76`):

- **#1 RDP ordering** — done (`d2fec2d`), with a `run_bruteforce` regression test on the
  `orchestrator_should_exit=False` path CI was blind to.
- **Down payment on #4** — RDP's `xfreerdp` connect is now bounded (`communicate(timeout=15)` +
  kill/drain, `5100b76`). SSH / SMB / Telnet connect timeouts are still open.
- **Verification asset added** — `bjorn_verify.py` gained a source-read **Section 9** (`d16caa8`)
  that parses the deployed connectors and proves the fix is in the *running* code even though the Pi
  tree is not a git checkout. On-Pi run 2026-08-11: **33 PASS / 0 FAIL**, Section 9 all green —
  *"all six ordered correctly (the RDP fix is in the running code)"*, *"no UnboundLocalError logged
  at runtime"*.

**2026-08-11 — Tier 1 #2 partially landed (RDP steal).** The RDP steal module is hardened and made
safe: a 30s `xfreerdp` connect timeout, and a `_looks_like_local_root` guard that refuses to run when
`/mnt/shared` looks like the Pi's own filesystem (the original "steals its own disk" bug). True
remote→local RDP steal still needs a different transport (SMB / a staged remote command) — honestly
deferred in the module docstring, since `/drive` + `+auth-only` cannot pull remote files.

**2026-08-11 — Telnet steal reworked and landed (unit-verified).** The held base64 download is
rebuilt and the end-marker/echo bug is gone. The transfer now base64-encodes the remote file between
markers chosen so both prior failure modes are structurally impossible: the markers carry underscores
(outside the base64 alphabet, so they can never collide with payload bytes), and the remote command
splits the literals with `''` (so the shell's command-echo carries `__BJORN''_B64_...`, not the
contiguous marker `read_until` scans for). Reliability is now at parity with SSH/RDP: connect + read
timeouts, latch reset per run, a `run_token`-guarded daemon timer, `telnet_connected` actually set on
connect, and a bounded, prompt-independent `find`. Telnet is no longer excluded from
`test_steal_modules.py` (it's in `MODULES`), and a new `test_telnet_download_is_binary_safe_and_echo_proof`
round-trips all 256 byte values + a `$`-laden payload through a fake login shell that reproduces the
command-echo ordering. Full suite: **318 passing**. Honest caveats: still unverified against a *live*
Telnet host, and the transfer assumes `base64` exists on the target (busybox/coreutils) — if it's
absent the read yields no data and the file is skipped with a logged warning, never a crash.

**2026-08-11 — Tier 2 #4 done (timeouts everywhere).** Every external-network call now carries a
wall-clock bound (5 connectors + nmap + the two remaining steal transfers), with an AST guard that
fails if any establish/exec site loses its timeout. This is the freeze-class killer — no single dead
host can wedge the single-threaded orchestrator anymore. 319 passing.

**2026-08-11 — Tier 2 #7 done (atomic config + serialized writers).** `save_config` is atomic
(temp+fsync+replace, indented), a class-level `_data_lock` serializes netkb `write_data` + config
saves, the web config path routes through it, and nmap's 2 workers no longer race on the vuln
summary. No more boot-brick on a yanked plug, no more lost hosts from concurrent writes. 320 passing.

**2026-08-12 — #6 done + #5 partially landed.** Every steal now caps recursion depth, file/run bytes,
and free space (no more symlink-loop hang or full-SD OOM); the bettercap poller no longer fails
silently (first-failure log + backoff + recovery line). 322 passing. #5's typed-Outcome contract +
lint + web last-error panel remain.

**2026-08-12 — Tier 3 #8 landed (parallel host execution).** `process_alive_ips` now groups
candidates by host and runs distinct hosts concurrently under a budget-capped `ThreadPoolExecutor`
(`host_parallel` config knob, core-aware `outer×inner` cap, per-action-class locks, standalones kept
serial). The flagship throughput change — same-host parent→child order preserved. 323 passing;
on-Pi multi-host benchmark still needed to quantify the win.

**2026-08-12 — Tier 3 #10 + #9 landed.** Display: draw once/tick, skip the EPD write on an unchanged
frame, full refresh every ~60 frames to clear ghosting (new `_display_frame` + `EPDHelper.display_full`).
Vuln scan: the serial idle-branch loop is now a bounded 2-worker `_run_vuln_scans` (~2× faster, keeps
the #4 per-host timeout; `skipped` no longer mis-stamped `failed`). Expected ~327 passing (run pytest).
On-Pi still needed: #10 refresh-cadence tuning, #8 multi-host benchmark.

**2026-08-12 — #13 file-access holes closed.** Path traversal (`download_file`/`download_backup`)
and zip-slip (`restore`) are fixed via a new dependency-free, unit-tested `path_safety.py`; the
unauthenticated-bind/auth decision is deferred (UX call). Expect ~332 passing (run pytest).

**2026-08-12 — #11 live-UI half landed (browser check pending).** Screen/log are now event-driven off
`screen_version`/`log_version` tokens in the stats stream; the blind 2s image + 1.5s log pollers are
gone. Dep re-pin (Pi-only) + pandas removal deferred.

**2026-08-12 — Smart Planner V2 batch integrated (author-supplied, evaluated + verified).** A
deterministic local-adaptation layer (no LLM/deps): the planner blends its static heuristic with a
Beta-smoothed success rate + EWMA duration per action, learned into `data/action_telemetry.json`
(atomic, bounded to 512 records, no secrets/loot). Retries become `(action,target)`-scoped with
cause-aware backoff. New typed `ActionOutcome`/`normalize_outcome` (advances #5). Off-switch
`smart_planner_enabled` (default true) restores legacy scoring. Preserves #7/#8/#9 verbatim; a
`+536%` useful-work/hour result on the synthetic `mixed_lab_v1` fixture (ordering regression, not a
field promise). Suite: **356 passing** (+24). Evaluation verdict: high quality, backward-compatible,
correct paths; integrated as-is with one add — `.gitignore` now excludes the runtime telemetry file.
On-Pi window still needed to tune values/durations against a real target.

**2026-08-12 — #11 pandas trim done (`2579fc3`).** The last three modules that still lazy-imported
pandas are on stdlib `csv`: `actions/scanning.py` (LiveStatusUpdater → `csv.DictReader`),
`actions/nmap_vuln_scanner.py` (header-only create, append + `(IP,MAC)` keep-last dedupe under
`_summary_lock`, pure-Python vuln-token union) and `actions/steal_data_sql.py` (`text()` +
`engine.connect()` — raw strings raise on SQLAlchemy 2.0 — streaming rows through `csv.writer`).
**pandas is now imported nowhere in the codebase.** Two traps found in the port and fixed before
merge: `_is_alive` had to tolerate the string `"1"` under `DictReader` (else every host reads dead),
and the credential loop variable `row` shadowed the `execute()` `row` parameter — every SQL steal
would have returned `failed`. 356 passing. **Still open: `requirements.txt` keeps the `pandas==2.2.3`
pin** — dead weight now, and the actual 50–80 MB win on the Pi.

**2026-08-13 — Tier 1 #3 done (`e27bc0a`): the handshake → crack loop is closed.** `wpasec_import.py`
uploads *then* downloads. A completeness gate runs `hcxpcapngtool -o out.hc22000 <pcap>` and treats a
non-empty result as a real EAPOL/PMKID capture (missing tool → log + skip, never a crash); complete
captures are deduped **by BSSID** so one AP uploads once; the multipart POST goes to `?api` with
`Cookie: key=`, and the index entry is stamped `uploaded` atomically. `bettercap_pwn.build_index`
carries `uploaded`/`complete`/`hc22000` forward across a re-index. `_urlopen`/`_which`/`_spawn` are
injectable, so the whole path is testable offline. Two regressions the author's rewrite had dropped
from the download half were restored on integration: `autoconnect-priority=-10` (a cracked network
must never outrank Bjorn's own uplink — now enforced by `test_nmconnection_contents`) and the
deterministic `wpasec-<ssid>` profile name. **Needs `hcxtools` on the Pi** (`apt-get install -y
hcxtools`) or the upload half no-ops; not yet live-verified against wpa-sec.

**2026-08-13 — #12 foundation landed (`15f7811`, `84d048b`).** New `base_connector.py` holds the
shared scaffolding once — `__init__` / `load_scan_file` / `worker` (with `task_done` in a `finally`) /
`run_bruteforce` (mac resolved *before* the queue fill, so #1 can't recur) / `save` / `dedupe`, plus a
thin `BaseBruteforce.execute`. A subclass sets `PORT`/`HEADER`/`OUTFILE_ATTR` and implements
`attempt(ip, user, pw) -> bool`. **SSH and FTP are converted** (FTP went 187 → ~35 lines, −170).
The load-bearing part for the remaining four: the **source-parsing verifiers**
(`bjorn_verify.py` Section 9, `test_bjorn_verify.py`, `test_connector_netkb_reuse.py`) used to parse
each connector file for `run_bruteforce`/`worker`/row-passing, which now live in the base — they were
taught to **follow delegation**, so a connector containing `from base_connector import` is verified
against `base_connector.py` instead. Converting SMB/Telnet/RDP/SQL is therefore adapter-only, no
verifier edits. 357 passing.

**2026-08-13 — #14 CI shipped (`e60d436`), lint triage still pending.** `.github/workflows/ci.yml` is
split into `test` (pytest on `tests/_stubs.py`, unchanged, guaranteed green) and `lint`. `lint` now
installs the installable subset — `grep -vE '^\s*(gpiozero|lgpio|spidev)\b' requirements.txt >
requirements-ci.txt`, since those three are Pi-only and can't install on x86 — and runs
`pylint --errors-only` over the original four paths **plus the never-linted core**
(`shared.py utils.py orchestrator.py base_connector.py telegram_client.py`); `.pylintrc` gained
`ignored-modules=gpiozero,lgpio,spidev`. The "missing tests" #14 asked for already existed (the
`should_exit=False` brute-force test, the connect-timeout AST guard, the traversal/zip-slip tests) and
CI already runs them. **The first Actions run *is* the triage** — any E-finding it raises in the core
is either a real bug to fix or needs a narrow `# pylint: disable=` with a reason. Deferred by choice:
the arm-emulation job and the version matrix.

**2026-08-13 — the idle loop was pinning a core (`6cca94e`), found in on-Pi logs.** On a network with
no live hosts the planner picks the `SNMPEnum` standalone every cycle (p=1.00, t=0s, top score), and
`process_alive_ips` returned True whenever *any* action ran — standalone included — so `run()` never
reached its paced idle branch and spun at **~10 cycles/s**: a pinned Pi Zero core while idle,
`orchestrator.py.log` + `shared.py.log` churning their 5 MB rotations, and the telemetry counter past
878k. `process_alive_ips` now returns `host_action_executed`; standalones still run for their side
effects but no longer keep the loop hot (the paced idle wait re-runs them anyway, self-throttled).
Same commit: the two missing-status-image warnings in `shared.py` log **once per status** instead of
once per render frame — SNMPEnum alone had written 10k+ identical lines.

Next: run the CI lint triage (#14) and drop the dead `pandas` pin; browser-verify #11; the on-Pi
Smart-Planner observation window (`planner_report.py`, `planner_benchmark.py`) plus the #8 multi-host
benchmark and #10 refresh-cadence tuning; then finish #12 (SMB/Telnet/RDP/SQL adapters, then
`BaseStealer` — #2's RDP transport lands inside it), close out #5's lint + side-effect verification,
and make the #13 auth/bind call.

---

## Tier 1 — Restore capability you already lost (tiny diffs, biggest effectiveness win)

### 1. ✅ DONE — Fix RDP brute-force (was 100% broken; verified on Pi 2026-08-11)
- **Evidence:** `actions/rdp_connector.py:143` puts `mac_address, hostname` on the queue, but they
  aren't assigned until `:155-165` — *after* the fill loop. Any real attack
  (`orchestrator_should_exit=False`) throws `UnboundLocalError` at `:143`; the orchestrator catches
  it (`orchestrator.py:230`) and marks every RDP host `failed`. **RDP never tries a single
  credential.** Both connector tests set `orchestrator_should_exit=True` and return at `:142`, so
  CI is blind to it.
- **How:** hoist the `if row is not None: … else load_scan_file()` block (`:155-165`) above the
  queue-fill loop (`:139`), exactly as the other five connectors order it. Add a `run_bruteforce`
  test with `orchestrator_should_exit=False` and `rdp_connect` mocked.
- **Payoff:** restores a whole attack protocol — port 3389, the planner's second-highest-weighted
  target (`action_planner.py:33`, `+24`).
- **Status:** ✅ shipped (`d2fec2d`) with the regression test; RDP connect timeout added (`5100b76`);
  verified live on the Pi 2026-08-11 via `bjorn_verify` Section 9 — the fix is in the running code.

### 2. 🟡 PARTIAL — Fix RDP + Telnet loot (Telnet landed; RDP steal hardened, needs remote transport)
- **Evidence:** `steal_files_rdp.py:49-50` redirects the *Pi's* `/mnt/shared` into the session, then
  `find_files:74` does `os.walk("/mnt/shared")` **locally** — it copies Bjorn's own disk, never the
  target. `steal_files_telnet.py:102-105` never resets the `stop_execution`/`telnet_connected`
  latch (the exact bug the other five already fixed), is excluded from `test_steal_modules.py`, and
  `steal_file:91` uses `cat {file}` + `read_until(b"$")` which truncates at the first `$` and
  corrupts binaries.
- **How:** RDP — pull from the *redirected* remote drive (or drive an SMB/`xfreerdp` file transfer
  against the target). Telnet — reset the latch per run, guard the timer with a `run_token` daemon
  thread, and transfer via a length-prefixed/base64 read instead of `cat`+prompt-scan.
- **Payoff:** restores 2 of 6 loot modules.
- **Status:** 🟡 partial. **Telnet steal** — ✅ landed (unit-verified). The base64 download is
  rebuilt: markers carry underscores (outside the base64 alphabet → no payload collision) and the
  remote command splits the literals with `''` (so the command-echo doesn't contain the contiguous
  marker `read_until` waits on). Reliability now matches SSH/RDP — connect + read timeouts, latch
  reset, `run_token` daemon timer, `telnet_connected` set on connect, bounded prompt-independent
  `find`. Now in `test_steal_modules.py::MODULES` plus a binary-safe/`$`-safe round-trip regression
  test; 318 passing. Not yet live-verified; assumes `base64` on the target (else logged skip, no
  crash). **RDP steal** hardened + made safe — 30s connect timeout and a `_looks_like_local_root`
  guard that stops it copying the Pi's own files. True remote RDP steal is still deferred to a
  transport redesign (documented in the module: `/drive` + `+auth-only` can't pull remote files).

### 3. ✅ DONE — Close the handshake → crack loop (captures were collected but never cracked)
- **Evidence:** `bettercap_pwn.py` captures per-AP PCAPs, indexes them, and awards coins
  (`:249-256`), but nothing ever uploads them. `wpasec_import.py` is **download-only**
  (`WPASEC_URL …dl=1`, `:30`). The offline pocket-carry feature — the reason V3 exists — produces
  loot that rots on the SD card.
- **How:** at index time, convert each PCAP to `hc22000` (`hcxpcapngtool`), POST it to wpa-sec
  (`dl=0` submit), and dedupe by **BSSID + handshake completeness**, not filename (today an
  incomplete capture counts as "owned" and inflates coins).
- **Payoff:** the capture → crack → `WpaSecImport` → auto-join chain finally completes.
- **Status:** ✅ shipped (`e27bc0a`). Upload-then-download in `wpasec_import.py`: a completeness gate
  (`hcxpcapngtool -o out.hc22000 <pcap>`, non-empty = real EAPOL/PMKID), **BSSID dedupe** so one AP
  uploads once, multipart POST to `?api` with `Cookie: key=`, and an atomic `uploaded` stamp on the
  index entry that `bettercap_pwn.build_index` now carries across a re-index. `_urlopen`/`_which`/
  `_spawn` are injectable, so it tests offline; new
  `test_upload_is_one_per_bssid_and_skips_incomplete`. On integration, two behaviours the rewrite had
  dropped from the download half were restored: `autoconnect-priority=-10` (a cracked net must never
  outrank Bjorn's uplink — locked in by `test_nmconnection_contents`) and the deterministic
  `wpasec-<ssid>` profile name. **Open:** needs `hcxtools` on the Pi (`apt-get install -y hcxtools`)
  or the upload half silently no-ops; not yet live-verified against wpa-sec.

---

## Tier 2 — Stop the freezes and the silent lies (reliability)

### 4. ✅ DONE — Put a wall-clock timeout on every network op
- **Evidence — the recurring hang class:** no timeout on the Telnet constructor
  (`telnet_connector.py:83`), pysmb `conn.connect` (`smb_connector.py:86`), `smbclient`/`xfreerdp`
  `communicate()` (`smb:111`, `rdp:90`), SSH socket/auth (`ssh_connector.py:87` only sets
  `banner_timeout`), `nmap_vuln_scanner.py:85` `subprocess.run`, and every steal transfer
  (`steal_files_ssh.py:44`, `steal_files_rdp.py:51`). A black-holed 445/3389/23 wedges the worker,
  and because the orchestrator is single-threaded, **one dead host freezes Bjorn** — the
  long-reported "start scan freezes the Pi" symptom.
- **How:** thread a bounded connect/read timeout (config-driven, default ~10s) through every
  external call — `timeout=` on socket connects and `communicate()`, `auth_timeout` on paramiko,
  `subprocess.run(..., timeout=)` on nmap.
- **Payoff:** no single host can stall the loop. This is the single highest-reliability change given
  the history.
- **Status:** ✅ done. Every external call is now bounded: SSH (`timeout`+`banner_timeout`+`auth_timeout`),
  SMB (pysmb `connect(timeout=)` + `smbclient` `communicate(timeout=)` with kill/drain), Telnet
  (`Telnet(timeout=)` + `read_until` timeouts), SQL (`pymysql connect_timeout`/`read_timeout`/`write_timeout`),
  nmap (`subprocess.run(timeout=300)`, inside the existing broad `except`), and RDP's `xfreerdp` (15s/30s,
  earlier). FTP was already bounded. Steal transfers: SSH-steal and SMB-steal connects now carry timeouts;
  FTP-steal/SQL-steal/RDP-steal/Telnet-steal were already bounded. A new AST guard
  (`test_connectors.py::test_every_connect_path_carries_a_timeout`) asserts each of the 11 establish/exec
  sites keeps its bound, so this class can't silently regress (the #14 assertion). Full suite: **319 passing**.
  Honest caveat: timeouts are module-level constants (~10–15s), not yet the config-driven knob #4 envisioned
  — a `shared_data` setting can thread through later without changing the call sites.

### 5. 🟡 PARTIAL — An outcome contract so "silent success on a dead path" can't recur
- **Evidence:** the BACKLOG names this defect class three times (`WiFiScan: success=4`, `release()`
  logging success on a radio it never restored, "the status line that cannot fail"). It was still
  live: `bettercap_client.py` poll_once swallowed daemon-down/401 with no log — a wrong password =
  **8,640 silent failed polls/day**, nothing on screen.
- **How:** actions return a typed `Outcome{success|failed|skipped}` and must *verify* their side
  effect before claiming success (a capture wrote rows; a radio is actually `managed`). A one-line
  test helper asserts the contract, and a lint rejects an unconditional `return 'success'`. Surface
  a first-failure log + last-error on the web panel with backoff.
- **Payoff:** diagnostics stop reassuring you about dead features.
- **Status:** 🟡 mostly landed. Two independent pieces now exist:
  (a) `BettercapPoller.poll_once` logs the first failure, then backs off (30s→…→30m cap), records
  `_last_error`, and logs a recovery line — no silent polls, no flood
  (`test_poller_backs_off_repeated_failure_logs`).
  (b) **The typed contract shipped with the Smart Planner V2 batch:** `action_outcome.py` defines
  `ActionOutcome`/`OutcomeCode` and `normalize_outcome()`, and the orchestrator now wraps every
  `execute()` — legacy strings, mappings, `ActionOutcome`, or a raised exception all normalise to one
  typed outcome, with `should_stamp_failure`/`skipped` deciding the netkb mark (a timeout/`FileNotFoundError`
  becomes `TIMEOUT`/`UNAVAILABLE`, not a silent success). `test_smart_orchestrator.py` covers the boundary.
  **Still open:** per-action *side-effect verification* (a capture actually wrote rows; a radio is actually
  `managed`) — modules still self-report; a lint rejecting an unconditional `return 'success'`; and
  surfacing `_last_error` on the web panel. Migration is opt-in per module (return an `ActionOutcome`),
  so the remaining work is incremental, not a rewrite.

### 6. ✅ DONE — Cap recursion, bytes, and free space on every steal
- **Evidence:** unbounded remote-tree recursion with no visited-set (`steal_files_ftp.py:58`,
  `steal_files_smb.py:56`) → a symlink loop recursed forever; `steal_data_sql.py:80` did
  `SELECT *` + `pd.read_sql` (whole table into RAM); **no size cap on any transfer** and no
  free-space check → OOM / full SD on a 512 MB Pi Zero.
- **How:** depth cap + visited-set, per-file and per-run byte budget, a free-space precheck.
- **Payoff:** a large or hostile host can't OOM the Pi or fill the card.
- **Status:** ✅ done. FTP + SMB `find_files` gained a `MAX_DEPTH` cap + visited-set + a
  `MAX_FILES_PER_RUN` cap (the depth cap is the real symlink-loop backstop, since a loop grows the
  path each level — `test_smb_find_files_bounds_an_infinite_tree`). Every steal enforces a free-space
  precheck (`shutil.disk_usage` ≥ `MIN_FREE_BYTES`), a per-file cap (`MAX_FILE_BYTES`, streamed so a
  huge file aborts mid-download) and a per-run budget (`MAX_RUN_BYTES`), and unlinks partial files on
  error. SQL now validates the identifier, backtick-quotes it, and reads `SELECT * … LIMIT MAX_ROWS`,
  deleting the dump if it exceeds the cap. The ftp/smb/bettercap fixes came from the user's
  `Downloads/Fixes/#6#5` set (verified); the missing part I completed was `steal_data_sql.py`'s
  `import shutil` + the four cap constants it referenced but never defined (a guaranteed `NameError`).
  Deferred (minor): atomic temp+rename *per stolen file* — a crash leaves an incomplete loot file, not
  corrupt Bjorn state, and the error path already unlinks partials; visited-set is path-keyed, not
  inode-keyed. 322 passing.

### 7. ✅ DONE — Make config writes atomic and serialize shared state
- **Evidence:** `shared.py:593 save_config` was a plain `open('w')`+`json.dump` — **not atomic**,
  unlike netkb/stats. A power loss mid-write corrupts `shared_config.json`, then `validate_config`
  raises and **bricks boot**. And the "single writer" claim on netkb was false: the web
  `save_configuration` and two nmap workers (`nmap_vuln_scanner.py`) did unlocked read-modify-write
  → lost updates / CSV corruption.
- **How (shipped):** `stats_engine._atomic_write` gained an `indent=` param and `save_config` now
  routes through it (temp+fsync+`os.replace`, pretty-printed so the web form stays editable). A
  **class-level** `SharedData._data_lock` serializes `save_config` and the netkb `write_data`
  read-merge-rewrite (used by the orchestrator cycle + web) — class-level so it also protects
  instances built via `__new__` and reflects that netkb/config are process-global files. The web
  `save_configuration` no longer does its own `open('w')`; it merges into the in-memory config
  (no TOCTOU re-read) and calls `save_config`. nmap's two-worker `update_summary_file` is guarded
  by a class-level `_summary_lock` so the concurrent `read_csv → concat → to_csv` can't lose rows.
- **Status:** ✅ done. `save_config`/`write_data`/`_atomic_write`/`utils.save_configuration` fixes came
  from the user's `Downloads/Fixes/#7` set (verified correct); the missing parts I added were the
  nmap `_summary_lock` and promoting `_data_lock` to class-level (the provided instance-lock silently
  swallowed an `AttributeError` and skipped the save on any `__new__`/partial-init path). New guard
  `test_config_validation.py::test_atomic_write_honors_indent_and_leaves_no_tmp`; the existing
  default-merge test now transitively covers the class-level lock. Full suite: **320 passing**.
  Deferred (honest): `clear_files` is a deliberate `sudo rm -rf` wipe, not a lost-update RMW, so it's
  left unlocked; a cross-**process** lock (`fcntl`/`portalocker`) isn't needed while all writers are
  threads in one process — revisit if a separate process ever writes netkb.
- **Payoff:** no boot-brick, no silently dropped hosts/results.

---

## Tier 3 — Go faster on the same hardware (this is the literal 30%)

### 8. ✅ DONE — Parallelize per-cycle work across hosts
- **Evidence:** `orchestrator.process_alive_ips` ran candidates in a `for` loop with
  `with self.semaphore:` **one at a time, in one thread** — the `Semaphore(10)` was a vestige of a
  removed design; effective cross-host concurrency was **1**. On an N-host LAN, Bjorn attacked serially.
- **How (shipped):** candidates are grouped by host row (MAC) and each group's actions run in planner
  order (so a same-host parent→child stays sequential and the child sees the parent's row update),
  while **distinct host groups run concurrently** under a `ThreadPoolExecutor`. Standalones stay
  sequential (they share the radio / bettercap). The worker count comes from `_host_parallel_workers`:
  a core-aware budget (`cores×4`) divided by `bruteforce_threads`, then capped by the group count and
  the planner's `max_host_actions` — so `outer_pool × inner_threads` can't thrash a Pi Zero. New config
  key `host_parallel` (0 = auto, 1 = serial/old behaviour, N = hard cap), range-validated in
  `config_validation`. A per-action-class lock serializes two hosts that need the same connector
  singleton (shared queue/results). Cycle-end `write_data` is single-threaded and #7-locked.
- **Status:** ✅ done. Files came from the user's `Downloads/Fixes/#8` set (`orchestrator.py` +
  `shared.py`, verified — the `shared.py` only adds the `host_parallel` default and preserves all #7
  locking). Improvements I added: `host_parallel` range-validation in `config_validation`, its key in
  the test fixture, and `test_host_parallel_worker_count_stays_within_budget` proving the budget cap
  (serial when =1, never exceeds groups / planner cap, shrinks as inner threads grow). 323 passing.
  Honest caveat: the gain is unmeasured on hardware — needs an on-Pi multi-host benchmark to confirm
  the `1/k` wall-clock. Default `host_parallel=0` (auto) turns it on; set `1` to revert to serial.
- **Payoff:** an I/O-bound multi-host sweep finishes in roughly `1/k` the time.

### 9. 🟡 PARTIAL — Move the vuln scan off the critical path and bound it
- **Evidence:** the idle branch ran `NmapVulnScanner` serially, looping every alive host one at a
  time under `self.semaphore`. One slow host used to block it with no timeout.
- **How:** make it a standalone, parallel action (2 workers already exist) with a per-host nmap
  `timeout=`, scheduled by the planner like the other standalones.
- **Status:** 🟡 → effectively done for this pass. The per-host nmap timeout landed in #4
  (`subprocess.run(timeout=300)`). The serial loop is now `orchestrator._run_vuln_scans`: eligible
  alive hosts (same success/failed retry-delay skip gates) run through a bounded
  `ThreadPoolExecutor(max_workers=2)` — ~2× faster, and safe (each host mutates its own row, nmap is
  timeout-bounded, `update_summary_file` is `_summary_lock`-guarded from #7). Also fixed a latent
  silent-lie: `'skipped'` now leaves **no** netkb mark (matching `NmapVulnScanner.execute()`'s own
  contract; the old loop wrongly stamped it `failed_`). Test:
  `test_vuln_scan_submits_only_eligible_hosts_and_stamps_results`. **Deferred (chosen scope):** the
  sweep still runs *inside* the idle branch (blocks it until done) and isn't a true planner-scheduled
  standalone — a fully non-blocking background sweep is a larger, riskier change left for later.
- **Payoff:** the loop no longer serial-stalls on the vuln sweep; one slow host is bounded.

### 10. ✅ DONE — Halve the e-ink + CPU cost per frame
- **Evidence:** `display.py` called `display_partial(image)` **twice per tick**, re-ran
  `init_partial_update()` **every frame**, drove the EPD even on an identical frame (only the *PNG*
  write was change-gated), and did **no periodic full refresh**, so partial-only updates accumulated
  ghosting (the long-standing "unreadable" complaint).
- **How (shipped):** the render loop's EPD write is now a single `Display._display_frame(image)`
  (mirrors `_write_screen_png`'s byte-compare gate): `image.tobytes()` is compared to the last frame
  pushed and the panel write is **skipped when unchanged**; the duplicate `display_partial` is gone;
  `init_partial_update()` runs only when actually writing. A full refresh fires every
  `FULL_REFRESH_EVERY_FRAMES` (60 ≈ once/min) via the new `EPDHelper.display_full` + the existing
  `init_full_update`, clearing ghosting. Tests: `_display_frame` skip/refresh cadence
  (`test_display_screen_png.py`) + a `display_full` lifecycle case (`test_epd_mock.py`).
- **Status:** ✅ code done. On-Pi tuning still needed: confirm the full-refresh cadence clears
  ghosting without visible flashing; `FULL_REFRESH_EVERY_FRAMES` is the knob (marked `ponytail:`).
- **Payoff:** multi-fold less SPI/CPU on the Zero, less ghosting, longer panel life.

### 11. 🟡 PARTIAL — Make the web UI genuinely live and shed weight
- **Evidence:** the dashboard cache-buster-polled `screen.png` every 2s and logs every 1.5s even
  though a WebSocket (`/ws/stats`) already existed; `requirements.txt` still carries the **stale 2024
  pins** (numpy 2.1.3, Pillow 9.4.0, pandas 2.2.3), and pandas (50-80 MB) is still pulled by 3 modules.
- **How:** push screen/log deltas over the existing WebSocket (or SSE); refresh + re-pin deps via
  `pip freeze` on the Pi (the PRD's own deferred step); finish the pandas removal in the last 3
  modules so it's never imported on-device.
- **Status:** 🟡 the live-UI half is done (needs a browser check). `get_stats_snapshot` now carries two
  cheap **change tokens** — `screen_version` / `log_version` (file mtime, via `_asset_mtime`) — on both
  the WS push and `/api/stats`. `dashboard.js` re-fetches `screen.png` / `/get_logs` **only when its
  token moves** (in `applySnapshot`), and the blind `setInterval` pollers (2s image, 1.5s logs) are
  removed — so the UI is event-driven in both live and fallback modes, with far fewer Pi requests when
  nothing changes. Verified by design/trace only (no JS test harness; the server helper sits behind the
  starlette import wall) — **browser-tested, not unit-tested**, and that browser check is still owed.
  The **pandas removal** is ✅ done (`2579fc3`): `nmap_vuln_scanner` / `scanning` / `steal_data_sql` are
  on stdlib `csv`, and pandas is imported nowhere in the codebase. **Deferred:** dropping the now-dead
  `pandas==2.2.3` line from `requirements.txt` (that, not the code change, is where the 50–80 MB
  on-device win actually lands), and the **dep re-pin**, which is Pi-only (`pip freeze` on the target
  Python, not this dev box).
- **Payoff:** fewer Pi requests, a truly live UI; boot/memory wins wait on the dep+pandas work.

---

## Tier 4 — Bold structural + capability bets

### 12. 🟡 PARTIAL — Collapse the 12 near-identical modules into a base + adapters
- **Evidence:** the 6 connectors (1,340 LOC) and 6 steal modules (1,250 LOC) are **~85%
  copy-paste** — identical `__init__`/`worker`/`run_bruteforce`/`save_results`/`execute`
  scaffolding; only `<proto>_connect`/`find`/`steal` differ. This duplication *is* the root cause of
  the RDP divergence (#1), the Telnet drift (#2), and the inconsistent timeouts (#4).
- **How:** extract `BaseConnector` (abstract `attempt(ip,user,pw)`) and `BaseStealer` (abstract
  `connect`/`list`/`fetch`), with threading/queue/timeout/latch/atomic-write centralized once. Each
  protocol becomes a ~40-line adapter.
- **Payoff:** deletes **~1,500 lines**, and the whole hang/latch/divergence bug class becomes
  *structurally impossible* — fix once, every protocol inherits it.
- **Status:** 🟡 the connector half is underway. `base_connector.py` (repo root) now owns
  `__init__`/`load_scan_file`/`worker` (`task_done` in a `finally`)/`run_bruteforce` (mac resolved
  before the queue fill, so #1 cannot recur)/`save`/`dedupe` + a thin `BaseBruteforce.execute`; a
  subclass sets `PORT`/`HEADER`/`OUTFILE_ATTR` and implements `attempt(ip, user, pw) -> bool`.
  **SSH (`15f7811`) and FTP (`84d048b`) are converted** — FTP dropped 187 → ~35 lines. The `b_*`
  globals are unchanged, so the orchestrator needed no edit. Key enabler for the rest: the
  source-parsing verifiers (`bjorn_verify.py` Section 9, `test_bjorn_verify.py`,
  `test_connector_netkb_reuse.py`) were taught to **follow delegation** — a connector importing from
  `base_connector` is checked against the base file — so the next four conversions are adapter-only.
  357 passing. **Still copy-paste:** SMB, Telnet, RDP and SQL connectors, plus all six steal modules
  (→ a future `BaseStealer`). Sequence deliberately: `BaseStealer` **before** #2, so RDP-steal's
  remote transport lands as one adapter method, and #6's deferred atomic per-file write +
  inode-keyed visited-set land once instead of six times.

### 13. 🟡 PARTIAL — Harden the web surface for the roaming reality it now has
- **Evidence:** the web UI is fully unauthenticated on `0.0.0.0:8000`, serving secrets
  (`/load_config` returns tokens/passwords), destructive endpoints (`/reboot`, `/shutdown`,
  `/execute_manual_attack`), plus **path traversal** (`download_file`, `download_backup` —
  `?path=../../etc/passwd` escapes) and **zip-slip** (`restore extractall`). The "no auth — the
  operator controls the network" decision was made for a *stationary* device — and **V3's headline
  feature is carrying it onto networks it does not control.** The premise no longer holds.
- **How:** bind to `127.0.0.1` by default with an opt-in token for LAN access (or a shared-secret
  gate on destructive/secret endpoints); fix traversal with a `realpath`-under-base check and
  validate zip members in `restore` — those two are one-liners and worth doing regardless of the
  auth decision.
- **Status:** 🟡 the file-access holes are closed; the auth/bind decision is intentionally deferred
  (it changes how the operator reaches the dashboard remotely — a UX call, not a bug). New
  dependency-free `path_safety.py` (`safe_under`, `zip_escapes`, both testable without the web
  stack — same standalone pattern as `retry_policy`/`config_validation`): `download_file` and
  `download_backup` now `realpath`-confine the requested path under their base dir and 404 on
  escape; `restore` validates every zip member is inside the extract dir before extracting a byte,
  and `basename()`s the upload's own filename (a second traversal — a `../evil.zip` name wrote the
  archive outside `upload_dir`). Tests: `test_path_safety.py` (traversal + absolute-path bypass +
  zip-slip). **Still open:** unauthenticated `0.0.0.0` bind, secret-serving `/load_config`, and the
  destructive endpoints — the auth/token/bind design.
- **Payoff:** the two remotely-exploitable file holes are shut the moment it roams; the auth surface
  remains a deliberate follow-up.

### 14. 🟡 PARTIAL — Real CI + the tests that would have caught all of the above
- **Evidence:** `ci.yml` runs a single Python 3.11 on `ubuntu-latest`, **skips
  `requirements.txt`**, and runs `pylint --errors-only` on 4 paths only (utils/shared/telegram
  unlinted). The RDP death, the Telnet drift, and the hang class are all invisible to it.
- **How:** install requirements in CI; lint the core modules; add the missing tests the audit named
  — a `run_bruteforce` test with `orchestrator_should_exit=False`, an assertion that every connect
  path carries a timeout, and traversal/zip-slip tests; add an arm-emulation job for the Pi target.
- **Payoff:** these bug classes can't regress silently again — the whole point of the 313 tests.
- **Status:** 🟡 the workflow shipped (`e60d436`); the triage it exists to produce hasn't run yet.
  `ci.yml` is split into `test` (pytest against `tests/_stubs.py` — unchanged, guaranteed green) and
  `lint`. `lint` installs the installable subset (`grep -vE '^\s*(gpiozero|lgpio|spidev)\b'
  requirements.txt > requirements-ci.txt` — a full install can't pass on x86, those three are Pi-only)
  and runs `pylint --errors-only` over the original four paths **plus the core that was never linted**:
  `shared.py utils.py orchestrator.py base_connector.py telegram_client.py`. `.pylintrc` gained
  `ignored-modules=gpiozero,lgpio,spidev`. The tests #14 named already exist and CI already runs them
  (`run_bruteforce` with `orchestrator_should_exit=False`, the connect-timeout AST guard,
  traversal/zip-slip).
- **Triage run 2026-08-14 — the code was clean, the gate was not.** Ran locally:
  `pylint --rcfile=.pylintrc --errors-only retry_policy.py config_validation.py shared.py utils.py
  orchestrator.py base_connector.py telegram_client.py scripts/ tests/`. **Zero real E-findings in the
  never-linted core** — the answer #14 wanted. But three defects in the gate itself, each of which
  alone would have made the first Actions run worthless:
  1. **`fail-on=E` was missing, so the job could never fail.** `fail-under=8` decides pylint's exit
     code, and with `--errors-only` the score stays above 8 — pylint printed 35 errors and **exited
     0**. A real undefined name in the core would have been reported and the job would still have gone
     green. The gate was decorative; this is the same "a status line that cannot fail tells you
     nothing" class as `WiFiScan: success=4` and `release()`.
  2. **`.pylintrc` carried `suggestion-mode=yes`**, an option pylint 4 removed. An unknown key is
     `E0015`, which `--errors-only` counts — a stale line of default-config boilerplate was enough to
     fail the build on its own. Removed, and CI now pins `pylint~=4.0` so an upstream release can't
     redden the build with no code change.
  3. **~40 bogus `E0401 import-error`s across `tests/`**, because the test files reach `shared` /
     `orchestrator` / `_stubs` / `bjorn_verify` through a runtime `sys.path.insert` that pylint does
     not execute. Fixed with an `init-hook` in `.pylintrc` that puts the same three entries
     (`.`, `tests`, `scripts`) on the path. Run pylint from the repo root, as CI does.
  With all three fixed the command exits **0** and errors now fail the build. Deferred by choice: the
  arm-emulation job, the Python version matrix, and the dep re-pin (Pi-only).

### 15. The bold bet — on-device, out-of-band LLM triage + audit report
- **Evidence/context:** the PRD's entire **P-AI** section is scoped but deferred, and half of it
  already exists offline (`scripts/analyze_reports.py` summarizes run-reports via Claude). This is
  the biggest capability lever left, and it lines up with the operator's own AWS + Claude cert
  track.
- **How (within the PRD's own guardrails):** between cycles — never in the hot loop — hand the
  redacted netKB to **Claude Haiku** to (a) re-rank the next targets with a rationale the e-Paper
  can show, and (b) write the P2 defensive audit report (per-finding severity + remediation).
  Degrades to today's heuristic planner with no key/network; per-run token budget; findings expose
  Bjorn's actions as **typed, authorization-gated tools** (the harness decides, not the model). It
  reasons over Bjorn's *own findings* for triage and remediation — not novel exploit generation.
- **Payoff:** smarter attack ordering and an explainable defensive report — the capability jump the
  PRD promised but never shipped.

---

## Suggested sequencing

1. **This week (small diffs, restore capability):** #1 RDP (a 5-line hoist), #4 timeouts, #7 atomic
   config. Each is a big reliability/effectiveness win for almost no code.
2. **Next (structural, do once):** #12 base classes — then #2, #6 land *inside* the base and can't
   drift again.
3. **Then throughput:** #8 parallel execution + #9 vuln-off-path + #10 display — the measurable 30%.
4. **Then the bets:** #3 wpa-sec loop, #13 roaming auth, #14 CI, #15 the LLM layer.

Do #14 (CI + the specific tests) alongside #1 so the RDP fix ships with the test that proves it —
and so the next silently-dead module is caught by a machine, not an audit.
