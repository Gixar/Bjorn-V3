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

Next: Tier 1 #2 (RDP+Telnet loot) and #3 (wpa-sec upload), then finish #4 for SSH/SMB/Telnet.

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

### 2. Fix RDP + Telnet loot — one steals the Pi's own files, the other corrupts what it grabs
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

### 3. Close the handshake → crack loop — captures are collected but never cracked
- **Evidence:** `bettercap_pwn.py` captures per-AP PCAPs, indexes them, and awards coins
  (`:249-256`), but nothing ever uploads them. `wpasec_import.py` is **download-only**
  (`WPASEC_URL …dl=1`, `:30`). The offline pocket-carry feature — the reason V3 exists — produces
  loot that rots on the SD card.
- **How:** at index time, convert each PCAP to `hc22000` (`hcxpcapngtool`), POST it to wpa-sec
  (`dl=0` submit), and dedupe by **BSSID + handshake completeness**, not filename (today an
  incomplete capture counts as "owned" and inflates coins).
- **Payoff:** the capture → crack → `WpaSecImport` → auto-join chain finally completes.

---

## Tier 2 — Stop the freezes and the silent lies (reliability)

### 4. Put a wall-clock timeout on every network op
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
- **Status:** 🟡 partial — RDP's `xfreerdp` connect is now bounded (15s, `5100b76`). Still open: SSH
  (`banner_timeout` only), SMB (pysmb `connect` + `smbclient` `communicate()`), Telnet (constructor),
  `nmap_vuln_scanner`, and the steal transfers.

### 5. An outcome contract so "silent success on a dead path" can't recur
- **Evidence:** the BACKLOG names this defect class three times (`WiFiScan: success=4`, `release()`
  logging success on a radio it never restored, "the status line that cannot fail"). It's still
  live: `bettercap_client.py:206-208` swallows daemon-down/401 with no log — a wrong password =
  **8,640 silent failed polls/day**, nothing on screen.
- **How:** actions return a typed `Outcome{success|failed|skipped}` and must *verify* their side
  effect before claiming success (a capture wrote rows; a radio is actually `managed`). A one-line
  test helper asserts the contract, and a lint rejects an unconditional `return 'success'`. Surface
  a first-failure log + last-error on the web panel with backoff.
- **Payoff:** diagnostics stop reassuring you about dead features.

### 6. Cap recursion, bytes, and free space on every steal
- **Evidence:** unbounded remote-tree recursion with no visited-set (`steal_files_ftp.py:58`,
  `steal_files_smb.py:56`) → a symlink loop recurses forever; `steal_data_sql.py:80` does
  `SELECT *` + `pd.read_sql` (whole table into RAM); **no size cap on any transfer** and no
  free-space check → OOM / full SD on a 512 MB Pi Zero.
- **How:** depth cap + visited-inode set, per-file and per-run byte budget, a free-space precheck,
  and atomic temp-file + rename for every write.
- **Payoff:** a large or hostile host can't OOM the Pi or fill the card.

### 7. Make config writes atomic and serialize shared state
- **Evidence:** `shared.py:593 save_config` is a plain `open('w')`+`json.dump` — **not atomic**,
  unlike netkb/stats. A power loss mid-write corrupts `shared_config.json`, then `validate_config`
  raises and **bricks boot**. And the "single writer" claim on netkb is false: the web
  `clear_files`, the planner, and two nmap workers (`nmap_vuln_scanner.py:51`) all do unlocked
  read-modify-write → lost updates / CSV corruption.
- **How:** reuse the existing `stats_engine._atomic_write` (temp+fsync+replace) for `save_config`;
  put one file lock (`fcntl`/`portalocker`) around every netkb / config / summary
  read-modify-write. `os.replace` prevents corruption but not lost updates — the lock does.
- **Payoff:** no boot-brick, no silently dropped hosts/results.

---

## Tier 3 — Go faster on the same hardware (this is the literal 30%)

### 8. Parallelize per-cycle work across hosts
- **Evidence:** `orchestrator.process_alive_ips` runs candidates in a `for` loop with
  `with self.semaphore:` **one at a time, in one thread** — the `Semaphore(10)` is a vestige of a
  removed design; effective cross-host concurrency is **1**. The only real concurrency in the repo
  is `nmap ThreadPoolExecutor(max_workers=2)`. On an N-host LAN, Bjorn attacks serially.
- **How:** the planner already picks ≤4 distinct action-classes on distinct host rows per cycle —
  run them through a bounded `ThreadPoolExecutor`; each mutates its own row dict, and the single
  `write_data` at cycle end persists all. *Caveat (honest):* connectors spawn `bruteforce_threads`
  internally, so cap `outer_pool × inner_threads` to a total budget (~cores×4) so a Pi Zero doesn't
  thrash — a small knob, not a rewrite.
- **Payoff:** an I/O-bound multi-host sweep finishes in roughly `1/k` the time.

### 9. Move the vuln scan off the critical path and bound it
- **Evidence:** `orchestrator.py:466-500` runs `NmapVulnScanner` serially inside the idle branch,
  looping every alive host, each `nmap -sV --script vulners` taking minutes — with **no timeout**.
  One slow host blocks the whole loop.
- **How:** make it a standalone, parallel action (2 workers already exist) with a per-host nmap
  `timeout=`, scheduled by the planner like the other standalones.
- **Payoff:** the loop never stalls on one nmap; vuln coverage keeps up with discovery.

### 10. Halve the e-ink + CPU cost per frame
- **Evidence:** `display.py:389-390` calls `display_partial(image)` **twice per tick**; `:326`
  re-runs `init_partial_update()` **every frame**; the full PIL frame is rebuilt even when identical
  (only the *PNG* write is change-gated, `:404`); and there's **no periodic full refresh**, so
  partial-only updates accumulate ghosting (the long-standing V4 "unreadable" complaint).
- **How:** draw once per tick; hash the composed frame and skip the EPD write when unchanged (reuse
  the `_write_screen_png` pattern); do a full refresh every N frames to clear ghosting.
- **Payoff:** multi-fold less SPI/CPU on the Zero, less ghosting, longer panel life.

### 11. Make the web UI genuinely live and shed weight
- **Evidence:** the dashboard cache-buster-polls `screen.png` every 2s and logs every 1.5s
  (`dashboard.js:124,149`) even though a WebSocket (`/ws/stats`) already exists; `requirements.txt`
  still carries the **stale 2024 pins** (numpy 2.1.3, Pillow 9.4.0, pandas 2.2.3) that CI never
  installs, and pandas (50-80 MB) is still pulled by 3 modules.
- **How:** push screen/log deltas over the existing WebSocket (or SSE); refresh + re-pin deps via
  `pip freeze` on the Pi (the PRD's own deferred step); finish the pandas removal in the last 3
  modules so it's never imported on-device.
- **Payoff:** fewer Pi requests, a truly live UI, faster boot and lower memory.

---

## Tier 4 — Bold structural + capability bets

### 12. Collapse the 12 near-identical modules into a base + adapters
- **Evidence:** the 6 connectors (1,340 LOC) and 6 steal modules (1,250 LOC) are **~85%
  copy-paste** — identical `__init__`/`worker`/`run_bruteforce`/`save_results`/`execute`
  scaffolding; only `<proto>_connect`/`find`/`steal` differ. This duplication *is* the root cause of
  the RDP divergence (#1), the Telnet drift (#2), and the inconsistent timeouts (#4).
- **How:** extract `BaseConnector` (abstract `attempt(ip,user,pw)`) and `BaseStealer` (abstract
  `connect`/`list`/`fetch`), with threading/queue/timeout/latch/atomic-write centralized once. Each
  protocol becomes a ~40-line adapter.
- **Payoff:** deletes **~1,500 lines**, and the whole hang/latch/divergence bug class becomes
  *structurally impossible* — fix once, every protocol inherits it.

### 13. Harden the web surface for the roaming reality it now has
- **Evidence:** the web UI is fully unauthenticated on `0.0.0.0:8000`, serving secrets
  (`/load_config` returns tokens/passwords), destructive endpoints (`/reboot`, `/shutdown`,
  `/execute_manual_attack`), plus **path traversal** (`utils.py:1059 download_file`,
  `:642 download_backup` — `?path=../../etc/passwd` escapes) and **zip-slip**
  (`:635 restore extractall`). The "no auth — the operator controls the network" decision was made
  for a *stationary* device — and **V3's headline feature is carrying it onto networks it does not
  control.** The premise no longer holds.
- **How:** bind to `127.0.0.1` by default with an opt-in token for LAN access (or a shared-secret
  gate on destructive/secret endpoints); fix traversal with a `realpath`-under-base check and
  validate zip members in `restore` — those two are one-liners and worth doing regardless of the
  auth decision.
- **Payoff:** the device is safe the moment it roams — which is exactly when today's model fails.

### 14. Real CI + the tests that would have caught all of the above
- **Evidence:** `ci.yml` runs a single Python 3.11 on `ubuntu-latest`, **skips
  `requirements.txt`**, and runs `pylint --errors-only` on 4 paths only (utils/shared/telegram
  unlinted). The RDP death, the Telnet drift, and the hang class are all invisible to it.
- **How:** install requirements in CI; lint the core modules; add the missing tests the audit named
  — a `run_bruteforce` test with `orchestrator_should_exit=False`, an assertion that every connect
  path carries a timeout, and traversal/zip-slip tests; add an arm-emulation job for the Pi target.
- **Payoff:** these bug classes can't regress silently again — the whole point of the 313 tests.

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
