# Changelog

## [Unreleased]

### Added
- **Offline recon mode** (`offline_mode.py`, `offline_mode_enabled` default on) — the orchestrator
  had no idea whether it was connected to anything: with no network it swept an empty netkb forever
  on a Pi Zero. Offline is not a fault state, it is the state Bjorn is *carried around* in, and the
  one where 802.11/BLE recon is the only work that still pays. With no default route it now pauses
  the IP sweep, runs the wireless recon that needs no target (`wifi_scan_interval_offline`, 120 s
  instead of 900 s), and tries to rejoin.
  - **Radio choice** (`pick_scan_iface()`): the configured dongle if present, otherwise any radio
    that is not the uplink. The onboard chip becomes eligible offline not through a special case
    but because with no default route *nothing* is the uplink — the safety property is carried
    entirely by `name != uplink`, which is also why `wifi_scan_iface` may now be left blank.
  - **Order is load-bearing:** recon first, reconnect second. A capture holds the radio in monitor
    mode and nmcli cannot associate such an interface — it fails *quietly*, which would read as
    "auto-join doesn't work" rather than "auto-join ran too early". `reconnect()` re-checks.
  - **Auto-join** (`wifi_autojoin`, default on): rejoins a saved network that comes back in range.
    `wifi_autojoin_open` (default **off**) also joins open networks Bjorn has no profile for —
    associating with someone else's AP is a posture decision, not a connectivity fix. A saved
    network always beats a stronger open one.
  - **No new log floods:** offline cycles repeat every 60 s, so actions needing the internet
    (`TelegramReport`, `WpaSecImport`, flagged with a new `b_needs_internet` module attribute) are
    skipped rather than failing once per cycle, and the repeating auto-join outcome logs on change
    instead of every minute. Skipping is not throttling — the delta/interval logic is untouched, so
    the first cycle back online still sends.
- **Per-page dumps & logs panel** — each module page now lists its own CSVs and `.log` files with
  view + download (`/module_files/{group}`, `/module_file/{group}/{key}`; wifi, ble, scan, web,
  snmp, telegram). Previously `/download_file` was hardcoded to `data_stolen/`, so `wifi_aps.csv`,
  `ble_devices.csv` and every module log were unreachable from the UI. The endpoint takes a
  **whitelist key, never a path**: the obvious `?path=` version puts every dump on the device behind
  one sanitizer being right forever, while a key cannot traverse anywhere because it never becomes a
  path. A page opts in with one line — `<div class="card" data-files-group="wifi"></div>`.
- **The e-Paper reports as well as jokes** (`comment_info_ratio`, default 3) — every third comment
  slot shows live findings instead (`7 raids logged`, `2 keys on my belt`, `No uplink. Reading the
  air.`). Counters still at zero are left out rather than becoming `0 creds` filler. Same slot, same
  delay, one ratio knob (0 = jokes only, as before).
- **74 new comment lines**, including themes for `WiFiScan`, `BLEScan`, `SNMPEnum`,
  `HTTPFingerprint`, `WebTemplateScan`, `TelegramReport` and `WpaSecImport` — all seven Wave 2–4
  actions had no theme, so each silently fell back to IDLE and logged a warning per comment.
  `comments.json.cache` is no longer tracked: a checkout could carry a cache older than the JSON
  beside it, hiding every newly added line.
- **Service-aware planner weights** — `load_service_hints()` reads the `Server` / `X-Powered-By` /
  `<title>` that `HTTPFingerprint` already banked and boosts hosts that look like an *appliance*
  rather than a generic web server: NAS +30, camera +28, admin panel +26, router +22, embedded +20,
  printer +18. Those are the classes that ship with default credentials **and** hold something worth
  having, so they should be reached before a random Linux box. A host with several web ports keeps
  its strongest hint, and the reason line names the class
  (`SSHBruteforce@10.0.0.1 - NAS - :22`). Matching is unambiguous-substring only: a false positive
  silently reorders the whole attack queue, so `nginx` earns nothing and `axis` is deliberately
  absent (Apache Axis is a SOAP library, not a camera). No new scanning — this is meaning read out
  of data collected two actions ago.
- **Adaptive idle interval** (`adaptive_scan_interval`, default on) — the sleep after a fruitless
  scan is no longer a flat `scan_interval`:
  - **Backs off** as fruitless scans accumulate (`scan_interval x min(4, failed_scans)`). An
    exhausted network doesn't become interesting by being asked four times a minute, and each pass
    costs CPU and SD writes on a Pi Zero. Capped at 4x so a newly-arrived device is still noticed.
  - **Wakes early** when the only thing blocking real work is a retry window. `collect()` now
    records `next_retry_wait` — the soonest a blocked action becomes runnable — and the sleep is cut
    to it, with a 30 s floor so a nearly-expired window can't turn into a busy loop. Previously a
    45 s backoff behind a 180 s interval wasted 135 s every time.
  - Only blocks that *expire* count: a success with `retry_success_actions` off never becomes
    runnable, and a closed port is structural rather than temporal. Neither shortens the wait.
  - The gates were split into `host_gate()` / `standalone_gate()` returning
    `(eligible, seconds_until_eligible)`; the `is_*_eligible()` predicates remain as wrappers.
- **Scored work selection — the orchestrator picks what to do next instead of following load
  order** (`action_planner.py`, see [`docs/SMART_ORCHESTRATOR.md`](docs/SMART_ORCHESTRATOR.md)).
  `process_alive_ips` walked `self.actions` in load order and `break`ed on the first success per
  host, so whichever action loaded first always went first regardless of how promising the target
  was, and a child action only ran if it happened to follow its parent in the same pass. Now every
  eligible `(host, action)` pair and standalone action is scored each cycle and the top picks run.
  - **Signals:** parent already succeeded (+55), never tried (+45), host has known CVEs (+35, read
    from `vulnerability_summary.csv`), retry due (+20), high-value port (+8…+28), open-port count,
    minus a small penalty for an action class run in the last six picks.
  - **Fairness:** up to `planner_max_host_actions` (4) per cycle, **one action class per cycle** so
    twenty SSH boxes can't fill the window, and a standalone turn every `planner_standalone_every`
    (3) cycles *while host work remains* — standalone recon previously waited for a fully idle net.
    `idle_boost` raises standalone priority as host work dries up.
  - **Why it's shown:** `bjornstatustext2` carries the reason
    (`StealFilesSSH@192.168.1.10 - parent ok - :22`), idle reads `thinking...` / `resting...`, and
    the log records `Planner chose: … (score=N)`.
  - Ranking is pure functions over dicts — no SharedData, netkb or hardware in
    `tests/test_action_planner.py`. Knobs are re-read every cycle via `sync_config()`, so a change
    applies without a restart, and validated as >= 1 (`planner_standalone_every` is a modulus).
  - **Trade-off:** a parent unlocked mid-cycle no longer runs its child in that same cycle; the
    child tops the next one. Cycles with work don't sleep, so this is one cycle of latency.
- **`/wifi`: "Scan now", band selection, and channel lock** — the page could configure a capture but
  never start one, so testing a new adapter meant waiting out an idle window.
  - **Scan now** (`POST /wifi_scan_now`) runs one capture immediately, ignoring both
    `wifi_scan_enabled` and `wifi_scan_interval` — asking for a scan by hand *is* the schedule.
    Backgrounded like the benchmark, since a capture is 30 s+ and must not hold the HTTP request
    open; the button disables itself for the capture window and then refreshes the tables.
  - **`wifi_scan_band`** (`bg` default, `abg`, `a`) → airodump `--band`. This is the setting most
    likely to be wrong on a dual-band adapter: airodump listens on **2.4 GHz only** unless told
    otherwise, so every 5 GHz AP was simply absent from the results. Widening it spreads the same
    capture time over ~3× the channels, so the page says to raise the duration alongside it.
  - **`wifi_scan_channel`** (`0` = hop) → airodump `-c`. Parks the radio on one channel: much more
    thorough there, blind everywhere else. Overrides the band, and `config_validation.py` rejects a
    channel outside 1–196 — a typo'd channel captures nothing and reads as dead hardware.
  - `WiFiScan.build_cmd()` is a pure static method so the flag logic is testable without a radio;
    the defaults deliberately emit **no** `--band`/`-c`, rather than restating airodump's own.
- **Monitor-mode radio lock** (`monitor_mode.py`) — "Scan now" is the second consumer of the single
  radio that the module's ponytail note anticipated, so the mutex landed where that note said it
  would: around `acquire()`/`release()`, not at the call sites. Non-blocking on purpose — a caller
  arriving mid-capture is told to come back rather than queued behind 30 s of airodump with an HTTP
  request open. Without it, a manual scan started during a scheduled one would `ip link set down`
  the interface underneath a running capture and both would return nothing. `release()` frees the
  lock in a `finally`, after the radio is back in managed mode, so the next caller can never take a
  half-restored interface.
- **`/help` page — how to use and configure the device** — a static page (no API, no new endpoint
  beyond the route) covering what Bjorn does, a five-step first run, how the scan → act → idle cycle
  decides what runs when, what every page is for, the optional modules and what hardware each needs,
  a settings reference for the keys that actually change behavior, where files are written, and a
  troubleshooting table leading with `scripts/bjorn_doctor.sh`. Linked from the nav and from the
  Config page.
- **Per-page descriptions and manuals for BLE, Telegram and Wi-Fi** — each module page now opens
  with a plain description of what the module does, plus a collapsed `<details>` manual: setup steps
  (including how to get a Telegram bot token and chat id), what each setting actually controls, and
  how to read the results table — what a randomized MAC, a probed ESSID or a name-only tracker match
  means. The two hazards are called out where the buttons are, not only in the docs: Wi-Fi's
  second-radio requirement, and the third-party hop that "include cracked credentials" creates.
  Native `<details>`, no JS.
- **Wi-Fi AP/client recon via airodump-ng** (backlog Wave 4) — new opt-in standalone action
  `WiFiScan` (`actions/wifi_scan.py`): puts a **second** radio into monitor mode, runs a timed
  `airodump-ng` capture and records nearby access points and their clients to
  `data/output/scan_results/wifi_aps.csv` / `wifi_clients.csv`. Own files, not `netkb.csv` — same
  call as BLE, since 802.11-layer discoveries have no IP or ports. Rows merge by BSSID / station MAC
  and keep their original `FirstSeen`. New `/wifi` page (config + AP and client tables + a "test
  monitor mode" button), both CSVs join the Telegram/SMTP dataset, and the installer provisions
  `aircrack-ng` + `iw`. Config: `wifi_scan_enabled`, `wifi_scan_iface`, `wifi_scan_duration` (30s),
  `wifi_scan_interval` (900s).

  Chosen over bettercap's `wifi.recon` for the first pass: airodump writes a plain CSV, which is the
  "external process + parse its output" pattern already used for nmap/nmcli/snmpget/bluetoothctl,
  whereas a bettercap-backed version needs a daemon, a REST client and auth hardening before it
  parses anything. Bettercap stays scoped in `BETTERCAP_PLAN.md`.
- **Monitor-mode lifecycle guard** (`monitor_mode.py`) — every acquisition funnels through
  `acquire()`, which **refuses any interface carrying the default route**. Monitor and managed mode
  are mutually exclusive on one radio, so monitor-moding Bjorn's own uplink would kill the web UI,
  reporting and IP scanning from inside the process that would have to report it. The guard keys on
  the **routing table, not the interface name** — names aren't stable across USB dongles and
  reboots, so a `wlan0` check would silently pass the day the dongle enumerates first. Deliberately
  avoids `airmon-ng start`, whose ubiquitous companion `airmon-ng check kill` kills NetworkManager
  and wpa_supplicant; plain `iw` sets the same mode without touching any other interface. The `/wifi`
  dropdown labels the uplink as unusable rather than hiding it.
- **SMTP fallback delivery channel for reports** (backlog Wave 3) — `telegram_client.py` gained
  `send_email()` (stdlib `smtplib`/`EmailMessage`; port 465 = implicit SSL, anything else = STARTTLS
  when the server offers it) and a `_deliver()` that sends via Telegram and falls back to SMTP when
  Telegram is unconfigured or fails — the case the backlog called out: public/hotel/corporate Wi-Fi
  that blocks one channel or the other. New config keys `smtp_enabled`, `smtp_host`, `smtp_port`
  (587), `smtp_user`, `smtp_password`, `smtp_to` (comma-separated), validated in
  `config_validation.py` and editable on the `/telegram` page. `TelegramReport` now runs when
  *either* channel is enabled, and "Send test message" tests whichever is configured. The delta
  (sha256) + rate-floor logic is unchanged and shared by both channels.
- **BLE tracker detection from the advertisement, not just the name** (backlog Wave 3) — `BLEScan`
  is now two-stage: the name heuristic first, then — only for devices the name didn't flag —
  `bluetoothctl info <mac>`, matched against finder-network service UUIDs (Apple Find My `fd44`,
  Samsung SmartTag `fd5a`, Tile `feed`/`feec`) and Apple manufacturer data `0x004c` whose payload
  type is `0x12` (offline finding). Google Fast Pair (`fe2c`) is deliberately excluded — ordinary
  headphones advertise it. New `TrackerType` column in `ble_devices.csv` and a "Detected via" column
  on `/ble`, so a flag shows its evidence. Devices rename freely; the advertisement doesn't.
- **`match_server` tech gate for web templates** (backlog Wave 3) — templates in
  `config/web_templates.json` take an optional `match_server` list; `WebTemplateScan` reads the
  parent action's `http_fingerprints.csv` for the host's `Server` header and skips templates whose
  tech doesn't match (case-insensitive), so tech-specific checks stop costing a request per host on
  a Pi Zero. Fails **open** — no `match_server`, or no known Server header, still fires the template
  (a missed finding is worse than a spare request). `apache-status` is gated to `["apache"]`.

### Fixed
- **`monitor_mode.release()` claimed success even when the radio never came back** (found on-Pi
  2026-08-08: `wlan1` was left in monitor mode while the log said *"returned to managed mode"*).
  It ran `ip link down` / `iw set type managed` / `ip link up` **ignoring every return code** and
  then logged success unconditionally — a status line that cannot fail tells you nothing. Exactly
  the class of defect `BACKLOG.md` already records for `WiFiScan: success=4`, and the only reason
  it surfaced at all is that the verification script checks `iw dev` itself rather than trusting
  the log.
  - Now verifies the mode afterwards, **retries once** (`iw set type` commonly returns EBUSY for a
    moment right after a capture — the case a single blind attempt loses), and on a second failure
    logs at **ERROR** with the recovery command. Returns `True`/`False` so callers can react.
  - The lock is still freed on failure: a radio stuck in monitor mode must not also deadlock every
    future consumer, and `acquire()` re-runs `iw set type monitor` anyway.
  - `parse_iface_mode()` / `current_mode()` added alongside, both pure and tested.
  - The verifier now tails `monitor_mode.py.log` on this failure — `acquire`/`release` log there,
    not to `wifi_scan.py.log`, and showing the wrong log is how you conclude "nothing was logged"
    about a failure that was logged elsewhere.
- **`bjorn_verify.py` reported a *working* uplink guard as broken** (2026-08-08 Pi run, the port's
  worst bug). Bjorn's handlers signal a refusal with `_err()` — HTTP **500** plus a JSON
  `{"status": "error"}` body. `curl`, in the shell version, printed that body regardless of status
  code. `urllib` raises `HTTPError` instead, and the client swallowed it as `None`, so a correct
  refusal of `wlan0` came out as **"ACCEPTED wlan0 — do NOT run a capture, check_usable is
  broken"**. The guard was fine throughout; the verifier invented a catastrophe, and the early
  return it triggered also skipped the capture and release checks.
  - An HTTP error body is now read and returned — for these endpoints the error body *is* the
    answer.
  - `None` (no answer) and `{}` (empty answer) stay distinguishable, and the guard check reports
    **WARN "could not ask; guard NOT tested"** rather than FAIL when the request never landed.
    Claiming a safety guard failed when the question was never asked is the worst lie this script
    could tell.
  - Both paths are pinned as tests. Sobering note for the bash-vs-Python question: this is the
    exact class of silent wrong answer the port was meant to eliminate, introduced *by* the port —
    the difference is that it took one run to surface and is now covered.
- **The planner verdict printed `strator.py - INFO - Planner chose: …`** — a `[-70:]` tail slice
  cutting the log's own prefix mid-word. Sliced from the marker instead.
- **`apt install bettercap` left a root daemon enabled at boot** (found on-Pi 2026-08-08 by the
  verification run — the single FAIL in an otherwise-green sweep). Debian's debhelper enables
  **and starts** a packaged service at install time; `install_bettercap` never called
  `systemctl enable`, so nothing in Bjorn's code suggested the unit would be active. Result: a
  bettercap process with a REST API running at every boot, on a device carried onto other people's
  networks, with Bjorn not talking to it at all (`bettercap_enabled` defaults false). Now
  `systemctl disable --now bettercap` runs unconditionally after the apt step — before the
  already-provisioned early return, so it also repairs an install that already went out.
  **On an existing install, run `sudo systemctl disable --now bettercap` now.**
- **`bjorn_verify` skipped the Wi-Fi capture and the Stage A radio test when `wifi_scan_iface` was
  blank** — while Bjorn itself would have captured happily, because `offline_mode.pick_scan_iface`
  falls back to any non-uplink radio. The verifier was more pessimistic than the code it verifies,
  which is its own kind of wrong answer: on the 2026-08-08 run it skipped the *one* check that most
  needed running. `pick_monitor_iface()` now mirrors the fallback, and says which radio it picked
  and why. A configured radio that is missing or is the uplink still refuses rather than falling
  back silently.

### Added
- **The verification script is now Python** (`scripts/bjorn_verify.py`, replacing the shell
  version). The reason is narrow and evidenced: **every bug this script has ever had was a silent
  wrong answer from shell string handling** — `grep -c` printing `0` while exiting 1, so
  `|| echo 0` yielded `0\n0` and broke every numeric test; and a `\r` from `csv.writer` riding
  into the last field so `-eq` failed and a passing benchmark read as "no comparable row". A
  script whose entire job is to not lie about state cannot have that failure mode; `BACKLOG.md`
  already records what a reassuring-but-wrong diagnostic costs.
  - Both historical bugs are pinned as regression tests. 13 tests over the pure logic in
    `tests/test_bjorn_verify.py` — parsing, config truthiness, benchmark rows, repo resolution —
    none of which needs a Pi, a network or a subprocess.
  - `benchmark_ports()` reads with the `csv` module, so the CRLF that broke the shell version is
    the parser's problem rather than the caller's. `count_matching()` returns a real `int`.
  - Also drops `curl` as a dependency of verifying Bjorn (urllib), and runs every subprocess as an
    argv list — no `shell=True` anywhere.
  - **A regression the port introduced and the smoke run caught:** `run()` folds stderr into its
    output, so a *missing* `usb0` came back non-empty ("Device usb0 does not exist") and read as a
    present interface with carrier. The shell version got an empty string for free by sending
    stderr to `/dev/null`. Now keyed on the return code. The `iw` mode read had the same shape and
    now reports WARN ("could not tell") rather than a false FAIL ("radio stranded").
  - The security fixes from the shell version carry over intact: nothing is executed out of the
    located install tree, `build_info` rather than `git -C`, no fixed `/tmp` path.
- **The previous shell script was tracked and verified this whole batch** — it was living
  untracked on the device, which is exactly how `bjorn_doctor.sh` drifted from the code it
  inspected. New **section 8**, covering everything with no hardware confirmation yet:
  - **8a — the collect-by-default flips.** Checks the *effective* config, because a saved
    `shared_config.json` from before the upgrade overrides a changed default silently: everything
    keeps working, it just collects nothing. Also reads the `Port discovery engine:` log line
    rather than trusting `use_rustscan`, since the toggle being on is not proof the binary was
    found.
  - **8b — the Stage A rule.** Fires two overlapping captures and asserts the second is declined
    with **no new ERROR** in `wifi_scan.py.log`. That is the regression that would otherwise appear
    only once the hunter holds the radio for hours.
  - **8c — Bettercap plumbing.** Panel reachable, unit present but **not** enabled, and the
    generated password in sync between the unit and the config — a mismatch surfaces as a bare
    "unauthorized" with no hint as to which side is wrong.
  - **8d — the Unreleased wave**, none of which has run on hardware: planner activity, idle-notice
    volume (the P1 flood wrote 7000+ lines), offline mode, per-page file groups, help page,
    comment-theme misses.
  - Bug caught while writing it: `grep -c` prints `0` **and** exits 1 on no-match, so the obvious
    `|| echo 0` appends a second line and every numeric comparison on the result silently fails.
    `bjorn_diag.sh` shipped this exact bug once already.
- **Bettercap event poller — Stage B is complete** (`BettercapPoller`, step B2). Off unless
  `bettercap_enabled`: no thread is started and no request is made on a default install.
  - **It does not write netkb.** The orchestrator is the single writer (that discipline is lockless
    *because* there is exactly one), so the poller buffers hosts by MAC and
    `merge_bettercap_hosts()` drains it immediately before each `write_data`. A second writer
    wouldn't corrupt the file — `write_data` is atomic — but it would silently lose rows whenever
    the two read-modify-write cycles interleaved.
  - **Merge rules, both about not fighting the scanner:** an existing MAC keeps its `Ports` and
    every action column (bettercap knows a host *exists*, not what has been scanned or attacked on
    it), and `endpoint.lost` never marks a host dead — losing sight of a host and the host being
    down are different claims, and the scanner owns the second one.
  - **B0 is now self-reporting.** On its first non-empty poll the poller logs the distinct event
    tags bettercap actually sent, and warns loudly when events arrive but produce *no* hosts — the
    exact signature of a wrong `FIELDS` mapping for this bettercap version. The failure mode it
    replaces is silence: events flowing, zero hosts, nothing logged, indistinguishable from an idle
    network.
- **Bettercap web panel + installer provisioning** (Stage B steps B4/B5). Still inert: the daemon is
  installed and configured but **never enabled**, and nothing polls it until B2.
  - New `/bettercap` page — enable switch, API URL/user/password (masked, with the existing reveal
    control), ARP-spoof and sniff toggles, and a live status line from `GET /bettercap_status`.
    The page explains the difference between passive recon and ARP spoofing, because one of those
    transmits nothing and the other puts Bjorn in the middle of other machines' traffic.
  - `GET /bettercap_status` always answers **200**, including for "unreachable": it is a status
    probe on a feature that is off by default, so a down daemon is the expected answer rather than
    a server error. The per-state wording lives in the handler, not the JS — two copies are two
    chances to describe a state wrongly.
  - Installer: optional `apt install bettercap`, a `bettercap.service` bound to `127.0.0.1:8081`,
    and **a password generated per install** written into both the unit (`chmod 600`) and the
    config. bettercap's `api.rest` ships a documented default `user`/`pass`, which on a device
    whose job is to sit on other people's networks would hand out a root-equivalent local API.
    A re-run keeps existing credentials — regenerating would silently desynchronise a working
    install. Non-fatal throughout; `--dry-run` reports what it would do; teardown in
    `uninstall_bjorn.sh` removes the unit (it holds the password).
  - The installer block runs from `setup_services` (step 7), not `install_dependencies` (step 2):
    it writes the *installed* config at `$BJORN_PATH`, which `setup_bjorn` only creates at step 5.
    Run earlier it would have found no config, or written to the source tree and had `cp -r`
    overwrite it.
- **Bettercap config surface + REST client** (`bettercap_client.py`, Stage B steps B1/B3 of
  [`docs/BETTERCAP_PLAN.md`](docs/BETTERCAP_PLAN.md)). Nothing calls it yet — `bettercap_enabled`
  defaults off, no process is started, no unit is installed. Stdlib only (urllib + base64).
  - `BettercapClient` (`session` / `events` / `run` / `is_reachable`) never raises: the caller will
    be a poller living for the whole process against a daemon that restarts, so a refused
    connection is a `False`, not an exception. A 401 is reported as "check bettercap_user /
    bettercap_password" — bettercap ships weak default credentials, so it nearly always means the
    generated password never reached the config.
  - `parse_hosts()` is pure and deliberately tolerant. **Every field read goes through one `FIELDS`
    table**, so confirming bettercap's version-specific event schema on the Pi (step B0, the one
    part that needs hardware) is a table edit rather than a rewrite. Malformed events are skipped,
    not raised.
  - **MACs are upper-cased on the way in.** nmap writes upper-case and netkb is keyed by MAC;
    bettercap emits lower-case, so without normalising, every bettercap host would become a second
    netkb row for a host Bjorn already knew.
  - `config_validation.py` gains **string-key validation**, which it had no notion of, plus a real
    URL check on `bettercap_api_url` — it is where Basic-Auth credentials get sent, so a malformed
    value fails at startup instead of on the first poll, and an off-device host is refused while
    the feature is enabled.
  - The key is **`bettercap_password`, not `bettercap_pass`**: `_SECRET_KEY_PARTS` redacts by
    substring and `..._pass` matches none of them, so the credential would have been logged in
    plaintext on every config save — which `bjorn_diag.sh` then tails into a shareable report.

### Changed
- **The monitor-mode radio has an owner, and a busy radio is no longer an error**
  (`monitor_mode.py`, Stage A of [`docs/BETTERCAP_PLAN.md`](docs/BETTERCAP_PLAN.md)) — groundwork
  for the Bettercap hunter, but it fixes a problem that exists today.
  - `acquire(iface, owner="scan")` records the holder and `holder()` reports it. A bare lock
    answers "is it taken?", which was enough while both consumers were 30-second captures; the
    hunter will hold the radio for hours, and a consumer turned away needs to know by whom.
  - `acquire()` now returns `(ok, detail, reason)` with `reason ∈ BUSY / UNSAFE / FAILED`. **This
    is the point of the change:** `WiFiScan` returns `'skipped'` on `BUSY` — no netkb mark, no
    run-report row, no failed-retry backoff, INFO not ERROR — and keeps `'failed'` for a genuinely
    unusable interface. Without it, a long-running hunt would log a Wi-Fi scan error every single
    cycle, on every device, since `wifi_scan_enabled` went on by default.
  - **Latent bug fixed while there:** `release()` freed the lock unconditionally, so any caller
    could return a radio another consumer was mid-capture on and drop its lock in the process —
    exactly the interleaving the lock was added to prevent. It was unreachable while both consumers
    ran the same code path; it stops being unreachable the moment a second owner exists.
    `release(iface, owner)` now ignores a non-owner.
- **RustScan is now the default port-discovery engine** (`use_rustscan: true`) — the on-Pi benchmark
  that gated this ran on 2026-08-07: **2.01s vs nmap's 54.25s over 7 hosts / 41 ports (26.94x), the
  same 3 open ports found by both**. Every fallback the opt-in version shipped with is unchanged and
  is what makes the flip safe: no binary → nmap, a failed run → nmap, and `_rustscan_bin()` still
  resolves the off-PATH cargo install the systemd service can't see.
  - The "binary not found" line is now **INFO, said once per process** rather than a WARNING once
    per scan. With the toggle on by default, an arch the installer couldn't provision is a normal
    handled state, not a misconfiguration to nag about — but it stays worth saying once, because a
    silent 27x slowdown is worse than a line in the log.
  - **`rustscan_full_port` stays off.** The benchmark measured the curated 41-port list; sweeping
    all 65,535 is a different workload and hasn't been timed on this board.
  - *Caveat carried over from the benchmark, deliberately:* 3 open ports is a thin sample. It says
    "auto batching is not obviously dropping ports", not "proven at scale". Re-run the Benchmark
    button against a port-rich host before treating `rustscan_batch_size` as settled.
- **BLE and Wi-Fi recon are now on by default** (`ble_scan_enabled`, `wifi_scan_enabled`) — Bjorn is
  meant to be carried in a pocket, and wireless recon is the half of its job that does not need a
  network to be on. Both were opt-in, so out of the box a carried device collected *nothing*: it
  swept a LAN it wasn't attached to and never listened to the air around it.
  - **BLE costs nothing to leave on.** The radio is built into every supported Pi, `bluez` is
    already provisioned by the installer, and the action already no-op'd cleanly when
    `bluetoothctl` was absent. It is also the only recon that keeps working with no dongle *and* no
    uplink, which is exactly the pocket case.
  - **`ble_scan_interval_offline`** (60 s, vs. 300 s online) mirrors `wifi_scan_interval_offline`.
    Five minutes is a cadence tuned for "don't disturb the real job"; offline there is no real job,
    and a five-minute gap crosses a whole café. Editable on `/ble`.
  - **Wi-Fi default-on needed one fix first, or it would have been a log flood.** With no dongle,
    `WiFiScan` resolved to no interface, `acquire("")` refused it, and that path logged an **error**
    and returned `'failed'` every cycle. Nothing configured and no spare radio is *missing
    hardware*, not a misconfiguration — the same class as "airodump-ng not found" — so it now
    returns `'skipped'` silently. A radio that **is** configured and absent still errors: that is
    the moved-USB-port case, which already cost one silent 15-minute lockout and must stay loud.
- **`scripts/bjorn_diag.sh` added to the repo** — the deep diagnostic (system health, service and
  process state, network, SPI/I2C, external tools, netkb/stats summary, config, log errors, recent
  orchestrator activity, plus `--save` / `--short` / `--repo`). It had been living untracked on the
  device, where it wasn't versioned, wasn't backed up, and drifted from the code it inspects — it
  was still recommending a planner patch that had already merged. Fixed while importing it:
  redacted config output (its fallback grepped for `telegram` and printed the bot token verbatim),
  dependency checks keyed on import names (`pysmb` → `smb`), commit/branch/behind-count reporting,
  an NTP-sync check for the no-RTC clock-jump case, a `grep -c` no-match bug that produced the
  string `"0\n0"` and silently failed every numeric test on it, ANSI colour suppressed when stdout
  isn't a terminal, and a `wait` on the `--save` tee so the report's tail isn't truncated.
- **`bjorn_doctor.sh` merged into `bjorn_diag.sh` and removed** — the diag reported a strict
  superset of it, so keeping both meant two places to update and one of them quietly going stale.
  `bjorn_diag.sh` is now the single "start here" diagnostic (`--short` for a quick pass, `--save`
  for a timestamped copy) and is committed executable, so `sudo ./scripts/bjorn_diag.sh` works
  without the `bash` prefix. `README.md`, `TROUBLESHOOTING.md` and the `/help` page repoint to it;
  `--help` now prints the whole comment header instead of a hardcoded line range that truncated
  the moment the header grew. A new test fails if any doc references a `scripts/*` file that
  doesn't exist — the rot that prompted it — while still allowing prose that names a retired
  script ("supersedes X").
- **`bjorn_doctor.sh` reports the commit, not just `version.txt`** — a diagnostic pull described a
  device many merged commits behind and nothing in the report said so, because `version.txt` is
  bumped per *release*, not per commit. It now prints the short SHA, date, subject, branch, whether
  the working tree is dirty, and how many commits behind its upstream branch it is — with a
  "git pull before trusting this report" nudge when that count is non-zero. Uses
  `git -c safe.directory=…` so it still works run under sudo against a repo owned by another user,
  without mutating any git config.
- **`bjorn_doctor.sh` gained a dependency check keyed on import names** — pip name and import name
  differ often enough that guessing produces false alarms: `pysmb` imports as `smb`, `Pillow` as
  `PIL`, `get-mac` as `getmac`. A separate diagnostic script reported `pysmb NOT IMPORTABLE` for a
  package that was installed and working — worse than not checking at all, since it sends you
  chasing a non-bug. Each row shows both names when they differ.
- **`rustscan_batch_size: 0` now means memory-aware auto, not "RustScan's default"** — 1500 on a
  board under 640MB (Pi Zero / Zero 2 W), 3000 under 1.5GB, otherwise RustScan's own 4500. Its
  documented failure mode under too-aggressive batching is *silently dropped ports* rather than an
  error, so an over-large batch costs findings without announcing itself. Same `0 = auto` contract
  as `bruteforce_threads`; set any number to override. *(Precautionary — the on-Pi diagnostic that
  prompted it turned out to have a benign explanation: the hosts showing no open ports are phones
  and IoT devices that legitimately answer nothing.)*
- **`/wifi` says so when the configured radio isn't present** — interface names follow probe order,
  not the physical port, so a dongle moved to another USB socket or re-enumerated after a reboot
  can come back under a different name, or not at all. The saved `wifi_scan_iface` then pointed at
  nothing and the dropdown simply rendered blank, which reads as "my config was lost" rather than
  "the radio is gone". `/wifi_ifaces` now reports `configured_missing` and the page explains it.
- **Module settings moved off the Config page onto their own pages** — `config.js` now hides any key
  owned by a dedicated page (`ble_scan_*`, `wifi_scan_*`, `telegram_*`, `smtp_*`) from the generic
  auto-generated form, so each module is configured in one place, next to its own results, test
  button and manual, instead of being split between a labelled page and a flat list of raw key names.
  Matched by **prefix**, so a new key on an existing module needs no change here; `/save_config`
  merges key-by-key, so a save from either page leaves the other's keys untouched. The form ends with
  a note linking to each module page — a setting that silently vanished would read as a bug. This
  also retires a real trap: `wifi_scan_iface` was a free-text field on Config, next to the `/wifi`
  dropdown that exists specifically to stop you selecting Bjorn's own uplink.
  `tests/test_web_pages.py` fails if a key is hidden from Config without the owning page's script
  setting it, or if a nav link points at a page missing from `webapp._PAGES`.
- **Offline CVE enrichment now also reads un-CPE'd services** — `_parse_service_versions` gained a
  `-sV` service-line fallback: when nmap can't emit a CPE (common on consumer gear — a Wave 0 test
  router returned "2 services unrecognized"), it takes the first two tokens of the version detail
  (`PORT open SERVICE <product> <version>`) as `(product, version)`. Garbage products simply match
  no signature, so it only adds hits, never false positives. Catches the single-token products in
  the seed DB (vsftpd/openssh/proftpd/unrealircd) even without a CPE.

### Fixed
- **A module with no `execute()` is no longer registered as an action** (found in an on-Pi
  diagnostic, 2026-08-07 — the only ERROR in an otherwise clean run). `actions/IDLE.py` is a
  template stub: no `execute()`, and `b_port = None`. Because `None == 0` is False it was filed
  under *host* actions rather than standalone, so the planner scored it "never tried" (+45) against
  every alive host, ran it, and got `AttributeError: 'IDLE' object has no attribute 'execute'` —
  **7 errors and 7 failed netkb marks in a 10-minute run**, plus a permanent `IDLE` column of
  failures in `netkb.csv`, for something that is not an action at all. Two fixes, both at the
  loader rather than at the symptom:
  - `load_action()` skips any instance whose `execute` is not callable, logging it once. Any future
    stub or half-written module is simply never registered.
  - `b_port` of `None` now classifies as portless (`port in (0, None)`) like `0`. The
    manual-attack dropdown already had to work around this same `None`-vs-`0` trap downstream
    (`utils.py`); this applies the rule at the source, where both callers inherit it.
- **Down interfaces are no longer scanned** (found in an on-Pi diagnostic, 2026-08-06) —
  `get_networks()` took every interface with an IPv4 address, and `netifaces` reports one whether
  or not the link is up. On the Pi the USB gadget `usb0` keeps `172.20.2.1/24` with **no carrier by
  design** (the #68 fix), so Bjorn swept all 254 addresses of a subnet that physically cannot
  answer — every cycle, at `-T2`, on a Pi Zero. The diagnostic caught it in the act:
  `nmap -oX - 172.20.2.0/24 -sn` in the service's cgroup with `usb0 DOWN, carrier 0`. Interfaces
  whose kernel `operstate` is `down` are now skipped; `unknown` (tunnels, loopback) still counts as
  usable, and an unreadable operstate fails open.
- **The installer stamps what it deployed (`build_info`)** — `bjorn_diag.sh` reported
  `commit ? (not a git checkout)` on the device, because the install path copies from local source
  (and a downloaded zip has no `.git` at all), so the commit reporting added a commit earlier could
  never work where it mattered most. `install_bjorn.sh` now writes `build_info` with the source
  commit, install time and source path; the diag reads it as a fallback. Existing installs show
  the "reinstall to stamp the build" hint until then.
- **Saving config no longer writes secrets to the logs** — `save_configuration()` logged the whole
  params dict at INFO, so every save from the `/telegram` page wrote the **bot token and SMTP
  password in plaintext** into `data/logs/webapp.py.log`, and `wpasec_api_key` alongside them. Those
  logs are exactly what the diagnostic script tails into a report meant for pasting into an issue —
  a leak with a delivery mechanism attached. Values for keys containing `token` / `password` /
  `api_key` / `secret` / `passwd` are now replaced with `***`; the key names stay, since knowing
  *which* keys a save touched is the diagnostic value. Substring match, so a future `*_token` key
  is covered without anyone remembering. Covered by `test_config_redaction.py`.
- **Disabled and throttled standalone actions no longer report success** (found by an on-Pi
  diagnostic, 2026-08-05) — every no-op path in `BLEScan` / `WiFiScan` / `WpaSecImport` /
  `SNMPEnum` / `TelegramReport` returned `'success'`, which the orchestrator wrote to netkb and
  counted in the run report. A diagnostic pull therefore read **`WiFiScan: success=4`** for an
  action that had never completed a single capture — the reporting was reassuring about a feature
  that was dead. Those paths now return a third outcome, `'skipped'`: the action still gets its
  turn, but leaves no netkb mark, no run-report entry, and doesn't count as work for the cycle.
  `TelegramReport` likewise distinguishes *not sent* (unchanged data / inside the rate floor) from
  a genuine send failure, which used to be reported as success too.
- **A failed monitor-mode acquire no longer burns the whole Wi-Fi scan interval** — `WiFiScan` set
  `_last_scan` *before* attempting, so a configuration error (dongle unplugged, wrong interface)
  cost a full `wifi_scan_interval` — 15 minutes by default — before it could be retested. The clock
  now starts only once a capture actually begins; the orchestrator's `failed_retry_delay` still
  backs off a genuinely broken config.
- **A backwards clock jump can no longer park an action for years** — the Pi has no RTC, so it
  boots at the fake-hwclock time (a diagnostic showed `boot 1970-01-09`) and jumps when NTP lands.
  Any netkb status written before that sync is stamped *ahead* of everything after it, and
  `retry_wait_remaining` took it literally: the action would wait until the clock caught up.
  A status stamped in the future is now treated as runnable now.
- **The fd watchdog no longer runs `lsof` over the whole system every 10s** — the systemd
  `ExecStartPost` loop counted every open file on the box to decide whether *Bjorn* was leaking
  descriptors. On a Pi Zero 2 W that walk is expensive at a 10-second cadence and it answered the
  wrong question (another process could trip the threshold). Now reads `/proc/$MAINPID/fd`.
  **Existing installs keep the old unit until reinstalled** — see `install_bjorn.sh`.
- **SMTP delivery no longer downgrades to cleartext** (security review of `b624337`) —
  `telegram_client.py::send_email` treated `SMTPNotSupportedError` from `starttls()` as benign and
  carried on over the plaintext socket, then still called `smtp.login()` and sent the report. Two
  exposures on one path: the payload, which carries **every cracked credential** when
  `telegram_include_creds` is on, and the user's own mailbox password. Worse, this channel is
  reached precisely when the network was hostile enough to block Telegram (HTTPS-only) — so the
  downgrade handed secrets to exactly the network already interfering with delivery. The send is
  now **refused** with a message naming the cause, rather than downgraded; `send_targets` leaves
  the stored signature untouched on failure, so the next cycle retries. A plain LAN relay is no
  longer usable — if that case ever matters it needs an explicit opt-in key, not a silent `pass`.
  Also passes an explicit verifying `ssl` context to `SMTP_SSL` (port 465), whose stdlib default
  has historically skipped certificate verification. Covered by `test_telegram.py`.
- **New config keys were invisible in the web UI until an unrelated save** — `SharedData.load_config()`
  merged the defaults over the saved `shared_config.json` **in memory only**, so the file on disk kept
  whatever key set it was last written with. Everything that reads the *file* rather than the live
  object — the `/load_config` form, `save_configuration()` — therefore saw a config missing every key
  added since, and a setting introduced by an upgrade only appeared once some other save happened to
  rewrite the file. `load_config()` now writes the merged config back when the file is missing default
  keys: one write per upgrade, not per boot (a complete file is left alone — this runs at every start
  and an SD card doesn't need the churn). Writing it back also restores the canonical key order, so the
  config form's `__title_` section markers keep grouping their keys. Covered by
  `test_config_validation.py`., and no longer run only once** — found while
  adding a 5th standalone action. Two compounding faults in `orchestrator.py`:
  1. The idle loop `break`ed on the first action returning success. Every standalone action returns
     `'success'` when it is **disabled or throttled** (`ble_scan.py:60,64,68`, `snmp_enum.py:42`,
     `wpasec_import.py:43,48`, `telegram_report.py:32`), so a single switched-off action consumed
     the whole idle window and starved every action registered after it.
  2. Success was written to the netkb `STANDALONE` row and gated by `retry_success_actions`, which
     defaults to `False` — correct for a *host* action ("don't re-attack a box you already
     cracked"), but applied to a recurring job it meant each standalone action ran **exactly once
     per netkb lifetime**. Their own interval keys (`ble_scan_interval`, `wpasec_interval`,
     `telegram_min_interval`) never got a second turn in which to take effect.

  The loop is now `run_standalone_actions()`: every action gets a turn each idle window, and the
  success-retry gate no longer applies to standalone actions — they self-throttle. The *failed*
  retry delay is kept, so a genuinely broken action still backs off. This is very likely the real
  cause of the Wave 2 note "BLE recon — enabled + initialized, but didn't get a standalone-action
  turn", which was blamed on the short observation window. Also revives `WpaSecImport`, `SNMPEnum`
  and `TelegramReport`, all one-shot until now.
- **Removed the dead `'web_increment '` config key** — the long-known trailing-space key was never
  read anywhere in the codebase, so it was a dead default rather than a typo'd rename: dropped from
  `shared.py::get_default_config` and `config/shared_config.json`. Existing installs keep the stale
  key in their saved JSON, where it stays inert.
- **`epd_test.py` explains the `GPIO busy` failure instead of dumping a bare traceback** — during
  Wave 0, `epd_test.py --all` failed *every* driver with `lgpio.error: 'GPIO busy'` because
  `bjorn.service` was running and holding the RST pin, with no hint why. It now checks
  `systemctl is-active bjorn.service` up front and prints "stop bjorn.service first
  (`sudo systemctl stop bjorn`)", and on any `busy` error prints the same hint before the traceback.
  `TROUBLESHOOTING.md` updated to lead with stopping the service. (The panel itself is fine — V3
  renders under the running service.)
- **usb0 now gets its static IP without a host plugged in (#68)** — on-Pi verification showed
  `usb0` UP but `NO-CARRIER`/`DOWN` with no `inet`: systemd-networkd was waiting for carrier before
  configuring the interface, so the static `172.20.2.1` never appeared until a cable was connected.
  Added `ConfigureWithoutCarrier=yes` (+ `IgnoreCarrierLoss=yes`) to
  `/etc/systemd/network/10-usb0.network` in the installer, so the address and DHCP server come up
  immediately. Live fix on an existing install: add both lines under `[Network]` in that file, then
  `sudo networkctl reload && sudo networkctl reconfigure usb0`.
- **Manual attack no longer offers un-runnable actions (NetworkScanner 500)** — the manual-attack
  dropdown (`/netkb_data_json`) listed *every* netkb action column, so picking **NetworkScanner**
  (or IDLE / a standalone log action) hit `execute_manual_attack`'s "Action class … not found" path
  and errored. `serve_netkb_data_json` now filters to actions the handler can actually run per host:
  the port-based connectors plus the special-cased `NmapVulnScanner`, derived from the loaded action
  metadata (`port not in (0, None)`) rather than a hardcoded denylist. Found during Wave 0 on-Pi
  verification.

### Added
- **BLE recon** (backlog Wave 2 #6) — new opt-in standalone action `BLEScan`
  (`actions/ble_scan.py`): a timed BLE/Bluetooth discovery via `bluetoothctl` (bluez, already
  installed) records nearby devices to `data/output/scan_results/ble_devices.csv` and flags likely
  trackers (AirTag/Tile/SmartTag/Chipolo…). Kept in its **own file, not `netkb.csv`** — non-IP
  wireless entries don't fit the netkb IP+Ports schema, so a self-contained file avoids
  destabilizing the core pipeline (the unified `device_type` column stays a future foundation item
  for when wardriving/ESP32 also need it). New **`/ble` web page** (nav entry) to configure
  (enable / scan duration / interval, saved via `/save_config`) and a live results table (`GET
  /ble_data`, device names rendered with `textContent`). No-op unless `ble_scan_enabled` and
  `bluetoothctl` present; throttled by `ble_scan_interval`. New config keys `ble_scan_enabled`
  (default false), `ble_scan_duration` (10), `ble_scan_interval` (300). New `tests/test_ble_scan.py`.
  BLE devices are also folded into the Telegram raw-data payload (`compile_targets`), so a BLE change
  triggers a delta-send like the other recon data.
  *(ponytail: name-based tracker heuristic; robust FindMy manufacturer-data detection is a follow-up.)*
- **Telegram raw-data reporting** (backlog Wave 2, Telegram-only v1) — Bjorn can now auto-deliver its
  **raw target dataset** (netkb + HTTP fingerprints + web-template findings + SNMP + vulns +
  optionally cracked creds, as a JSON document) to a Telegram bot, so an AI agent can compile a
  report later. New standalone action `TelegramReport` sends **only when the data has changed** since
  the last send (sha256 delta) and a `telegram_min_interval` rate floor has elapsed — no fixed-timer
  spam. New dependency-free `telegram_client.py` (stdlib `urllib`; `sendMessage` plain-text +
  `sendDocument` multipart; `compile_targets`/`send_targets` shared with the web handler). New
  **`/telegram` web page** (nav entry) to configure the bot (enable, token, chat id, min interval,
  include-creds toggle — saved via the existing `/save_config` merge) and **Send test** /
  **Send data now** buttons (`POST /telegram_test`, `POST /telegram_send`). Config keys
  `telegram_enabled` (default false), `telegram_bot_token`, `telegram_chat_id`,
  `telegram_min_interval` (300), `telegram_include_creds` (true). New `tests/test_telegram.py`.
  *(Email/SMTP delivery deferred to a later pass.)*
- **SNMP enumeration** (backlog Wave 2) — new standalone action `SNMPEnum`
  (`actions/snmp_enum.py`). SNMP is UDP/161 (invisible to the TCP scanner), so instead of being
  port-gated it iterates the alive hosts in netkb itself and probes 161 with the configured
  community strings via `snmpget` (net-snmp), recording sysDescr + sysName to
  `data/output/scan_results/snmp_enum.csv`. No-op (logged) when `snmpget` is absent — same graceful
  external-tool pattern as RustScan. New `snmp_communities` config (default `["public","private"]`);
  installer now provisions the `snmp` apt package. New `tests/test_snmp_enum.py`.
- **nuclei-style templated web checks** (backlog Wave 2) — new `WebTemplateScan` action
  (`actions/web_template_scan.py`), a **child of `HTTPFingerprint`** (runs after a host's web
  services are fingerprinted). For each open web port it GETs each bundled template's path and
  reports a hit when the matchers pass (`status` any-of **and** `body_contains` any-of); findings go
  to `data/output/scan_results/web_template_findings.csv`. Templates live in
  `config/web_templates.json` — plain JSON (stdlib, **no pyyaml dep**), extensible without code;
  seeded with high-signal exposures (.git/config, .env, phpinfo, Apache server-status, .DS_Store,
  backup.sql). Stdlib `urllib`; self-signed certs accepted. New `tests/test_web_template_scan.py`.
- **HTTP(S) service fingerprinting** (backlog Wave 2, PRD P3-5) — new per-host recon action
  `HTTPFingerprint` (`actions/http_fingerprint.py`): for a live host with a web port open, it GETs
  each open web port (80/443/8080/8443/8000/8888/9090, TLS auto-detected) and records the status,
  `Server` / `X-Powered-By` headers, and page `<title>` to
  `data/output/scan_results/http_fingerprints.csv` — a map of the LAN's web tech and the feed for
  the planned nuclei-style checks. Stdlib `urllib` only (no new dependency); self-signed certs are
  accepted (fingerprinting, not trusting — same posture as nmap/`curl -k`). Registered on `b_port=80`
  and fingerprints *all* of the host's web ports per run. New `tests/test_http_fingerprint.py`.
- **wpa-sec Wi-Fi credential import** (backlog Wave 1 #4) — new opt-in standalone action
  `WpaSecImport` pulls your cracked Wi-Fi keys from wpa-sec.stanev.org and injects them into
  NetworkManager as autoconnect profiles, so Bjorn can roam onto networks it already has the key for
  instead of attacking them. No-op unless `wpasec_api_key` is set; throttled to one fetch per
  `wpasec_interval` seconds (default 3600). Fetch is stdlib `urllib` (no new dependency); results
  are deduped against `crackedpwd/wifi_wpasec.csv`. The injected profiles use a negative
  `autoconnect-priority` so they never outrank Bjorn's own connection. Remote data is treated as a
  trust boundary — SSID/PSK with control chars are dropped (they could inject NM keyfile sections) —
  and connection names are filesystem-sanitized. New `tests/test_wpasec_import.py`.
- **Coins / stats overhaul** (backlog Wave 1 #3 — see `docs/COINS_STATS_PLAN.md`) — coins/level are
  now a **monotonic, persisted** score instead of a live recompute. The old `update_stats()` derived
  them as a flat linear function of the *current* counts every refresh, so the score could **drop**
  (netkb cleaned, hosts offline) and reset to 0 on restart. New dependency-free `stats_engine.py`
  keeps a **high-water mark per category** (each only ever rises), computes `coins = Σ mark·weight`
  with **rebalanced weights** (rare wins like a cracked cred pay far more than a host appearing), an
  **RPG level curve** (`floor(sqrt(coins/25))`, rising thresholds), and persists to
  `data/stats.json` (atomic write; first run seeds from current counts so nothing resets). The stats
  dashboard gains a **coin-breakdown table** (per-category earned totals) via a new `breakdown`
  field on `/api/stats`. New `tests/test_stats_engine.py`. *(Deviation from the plan: server-side
  coin history was skipped — the dashboard already builds a live session trend chart, so persisting
  a history ring nothing consumes would be YAGNI.)*
- **Credential reuse / lateral chaining** (backlog Wave 1 #2) — a cred cracked on one host is now
  auto-replayed across every other host **and protocol**. All six brute-force connectors
  (SSH/FTP/Telnet/RDP/SMB/SQL) record each hit into a shared pool (`crackedpwd/known_creds.csv`) and,
  on their next host, try the pool pairs **first** before the full wordlist product. The candidate
  list is recomputed per attack (connectors are long-lived singletons), so reuse kicks in within the
  same scan cycle. New dependency-free `credential_pool.py` (unit-testable without `SharedData`,
  re-exported from `shared`), new `credential_reuse` config toggle (default `true`), and
  `tests/test_credential_reuse.py`.
- **Offline CVE enrichment** (backlog Wave 1 #1) — `NmapVulnScanner` now matches the service
  versions `nmap -sV` reports (parsed from the CPE lines) against a bundled offline signature DB
  (`config/cve_signatures.json`) and folds any matches into the same vulnerabilities set the online
  `vulners.nse` feeds — so it flows to the vuln summary / count / display for free, and flags
  known-vulnerable versions **with no internet** (works even when `vuln_scan_vulners` is off). New
  `vuln_offline_cve` config toggle (default `true`). The DB seeds a handful of high-signal,
  version-detectable CVEs (vsftpd 2.3.4, UnrealIRCd 3.2.8.1, ProFTPD 1.3.5, SambaCry, OpenSSH
  <7.7, Apache 2.4.49) and is a plain JSON list meant to be extended. Matching supports exact /
  contains / naive `version_lt`; new `tests/test_cve_enrichment.py`.

### Docs
- **Coins / stats overhaul plan** — `docs/COINS_STATS_PLAN.md`: phased scope for the backlog
  coins/stats item — a monotonic high-water-mark accumulator (persisted to `data/stats.json`,
  reuses the counts `display.py` already computes, no connector hooks), an RPG level curve, a
  richer web-UI breakdown/trend, and rebalanced award weights. Plan only, no code. Linked from
  `docs/BACKLOG.md`.
- **Bettercap integration plan** — `docs/BETTERCAP_PLAN.md`: phased scope for the backlog Bettercap
  item (managed-mode MVP — daemon + REST poller feeding `netkb`; monitor mode deferred behind a
  second radio), including a dedicated web config panel, config-key table, touched-files list,
  security notes, and acceptance criteria. Plan only, no code. Linked from `docs/BACKLOG.md`.

## [2.5.0-alpha] — 2026-08-02

> Most changes are sandbox / `py_compile` / TestClient-checked, not hardware-verified — see the
> README's Pi-gated note for the split. Some items below (RustScan port discovery, `usb0`
> addressing, live console) are confirmed on-Pi as of this tag.

### Added
- **Opt-in RustScan port discovery** (backlog #12) — new `use_rustscan` config toggle (default
  `false`, so existing installs are unchanged). When on **and** the `rustscan` binary is present,
  the port-discovery stage runs RustScan (`-g` greppable mode) instead of `nmap -sT`; nmap still
  does the service/version detail afterward, so it's a discovery-stage swap, not a pipeline
  rewrite. Falls back to nmap automatically if the binary is missing (logs a warning) or if a
  RustScan run fails mid-scan, so a scan is never lost. Renders as a switch on the web config page
  for free. New `rustscan_batch_size` config key (0 = RustScan's adaptive default) wires `-b <n>`
  into the command so the socket batch can be tuned down on a Pi Zero 2 W if a too-large batch
  drops ports (RustScan's documented failure mode). The installer (`install_bjorn.sh`) provisions the RustScan binary automatically:
  it drops the official prebuilt static binary into `/usr/local/bin` for arm64 (64-bit Raspberry
  Pi OS) / amd64 — no Rust toolchain, no on-Pi compile — and is non-fatal (32-bit armv7 and any
  download failure just leave Bjorn on nmap). `--dry-run` reports whether rustscan is present.
  Each scan now logs the chosen engine (`scanning.py`: `Port discovery engine: rustscan (N hosts,
  M ports)`) so the log positively confirms which engine ran, not just the fallback warnings.
  *Confirmed on-Pi:* the benchmark measured **36× faster** than nmap (1.68s vs 60.6s over 9 hosts /
  41 ports) with **identical open-port coverage** — rustscan is a clear win for the discovery stage.
- **RustScan full-port (65k) mode** (backlog) — new `rustscan_full_port` config toggle (default
  `false`). When on (and `use_rustscan` is on), the discovery pass sweeps the whole `1-65535` range
  (`rustscan -r`, its adaptive-async strength) instead of the curated `portlist`/`portstart-portend`
  set; nmap still does service/version detail on whatever comes back, so it's still a discovery-stage
  swap. Rustscan-only — nmap full-port on a Pi Zero would be far too slow — and the benchmark stays
  pinned to the curated list for a fair engine comparison regardless of the toggle. Longer subprocess
  timeout (600s) when on; renders as a switch on the web config page for free.
- **Scan-engine benchmark ("test mode")** — `python actions/scanning.py --benchmark` discovers the
  live hosts once, then runs the *same* port scan through both nmap and RustScan back-to-back,
  times each, and appends the result (host/port counts, per-engine seconds, speedup) to
  `data/scan_engine_benchmark.csv`. Diagnostic only — does not touch `netkb`/`livestatus`; skips
  RustScan with a note if it isn't installed. Use it to tune the batch size on real hardware before
  making RustScan the default. Also runnable from the web config page: a **"Benchmark" button**
  (`POST /run_benchmark` runs it in a background thread; `GET /benchmark_results` returns recent
  rows) that toasts the measured speedup when the run finishes.
- **Scan all interface subnets** (#133) — `get_networks()` returns one `IPv4Network` per interface
  subnet (all `AF_INET` addrs, deduped, loopback/link-local skipped) instead of only the default
  gateway's network, so a host on more than one LAN (eth0 + wlan0 + usb0 …) is finally seen. `scan()`
  loops every subnet and **accumulates** alive hosts into a single `update_netkb` write with the
  union of alive MACs (per-network writes would make each subnet mark the others' hosts dead).
- **In-WebUI Logs page** (from `BjornCocaine`) — `web/logs.html` + `web/scripts/logs.js` + a "Logs"
  nav entry and `logs` in `webapp.py`'s `_PAGES`. The colorize/escape renderer was extracted to
  `common.js` and shared with the home console.
- **Static IP assignment** (#26) — the Wi-Fi connect panel now takes optional Address/CIDR + Gateway
  + DNS fields; `utils.py::_static_ipv4` validates them with stdlib `ipaddress` (rejects malformed
  input / requires a prefix), and the NM keyfile is written `method=manual` when set, else DHCP as
  before. Blank (default) path unchanged.

### Changed (performance — Pi Zero; PRD §10, passes P1–P5 + L3)
- **P1 — brute-force thread count is config-driven.** The SSH/Telnet/SQL/SMB/FTP/RDP connectors no
  longer hardcode 40 threads; new `bruteforce_threads` key (0 = auto → `min(8, cpu*4)`), validated
  non-negative.
- **P2 — `pandas` off the hot import path.** Removed the module-top `import pandas` from all 10
  action files. The 6 connectors + `display.py` now use stdlib `csv` (via shared `netkb_targets` /
  `append_csv_rows` / `dedupe_csv` helpers); `scanning.py`, `nmap_vuln_scanner.py`, and
  `steal_data_sql.py` **lazy-import** pandas only in the methods that need it, so a run that never
  vuln-scans or SQL-steals never loads it.
- **P3 — batched netkb writes.** `execute_action`/`execute_standalone_action` and the vuln loop no
  longer call `write_data` per action; `run()` batches to one `netkb.csv` write per cycle branch.
  Trade-off: mid-cycle results are lost on a crash (actions just re-run next cycle).
- **P4 — dropped a duplicate action loop** that `run()` ran inline after `process_alive_ips()`.
- **P5 — change-gated display recomputes.** A `data_generation` counter bumps once per completed
  scan; the display threads re-parse netkb/livestatus only when it changes (safe fallback: if the
  counter never bumps, they recompute as before).
- **L3 — optional vuln-scan steps.** New `vuln_scan_sv` and `vuln_scan_vulners` bools (default True)
  make `-sV` and the internet-dependent `vulners.nse` optional in the nmap vuln scan.

### Fixed
- **USB gadget `usb0` now actually gets an IP** (#68) — *needs on-Pi verification.*
  `configure_usb_gadget` was a three-way conflict: `cmdline.txt` loaded the legacy `g_ether`
  gadget **and** the script built a configfs/`libcomposite` gadget (g_ether grabbed the UDC first
  → "Device or resource busy"); the Pi's address was set imperatively with `ifconfig` while three
  managers (ifupdown `/etc/network/interfaces`, `systemd-networkd` with no `.network` file, and
  Bookworm's actual NetworkManager) fought over `usb0`; and **nothing gave the connected host an
  address at all**. Rewritten to one coherent stack: dwc2-only (no g_ether), `systemd-networkd`
  owns `usb0` via `/etc/systemd/network/10-usb0.network` (static `172.20.2.1/24` + a built-in
  `DHCPServer` that leases the host `172.20.2.10-30`), and NetworkManager is told to leave `usb0`
  unmanaged. cmdline/config.txt edits are now idempotent. Boot-file changes + kernel gadget
  bring-up mean this can only be confirmed on real hardware.
- **Live console no longer freezes the page on Start** — `colorizeLogLine()` (`web/common.js`)
  mixed a stateful global-regex `exec()` with reassigning the string inside the loop, so each
  `.py` filename it wrapped got re-matched and the loop never terminated; over ~2000 log lines
  polled every 1.5s, hitting Start locked the browser's main thread. Replaced with a single
  stateless `String.replace(/\w+\.py/g, cb)`. *Confirmed on-Pi.*
- **Stale `config_validation` test fixture** — `_good_config()` was missing `vuln_scan_sv`,
  `vuln_scan_vulners`, and `bruteforce_threads` (added to the validator earlier), so the suite
  failed; fixture updated (and now includes `use_rustscan`).

### Fixed (pre-existing)
- **Manual attack with `NmapVulnScanner` no longer 500s** ("Action class NmapVulnScanner not
  found"). The manual-attack handler only searched `self.actions`, but the vuln scanner is loaded
  separately (`self.nmap_vuln_scanner`) and has a different `execute(ip, row, status_key)`
  signature than the connectors. It's now special-cased. (In the FastAPI `utils.py` — takes effect
  once the web dashboard / Tier-2 files are deployed.)
- **Bjorn no longer scans/attacks itself.** `NetworkScanner` now detects this device's own IPv4
  addresses (all interfaces, via `netifaces`) at the start of *every* scan and adds them to the
  scan blacklist — dynamic, so it survives DHCP address changes (a fixed IP in the config would
  rot). Fixes the case where the Pi's own netKB row uses a fallback MAC, so the existing
  MAC-blacklist missed it and the SSH brute-force ran against localhost.

### Added (merged via sync — FastAPI web rewrite / live stats dashboard)
- Web server migrated from stdlib `http.server` to **FastAPI/Starlette + uvicorn** (`webapp.py`,
  `utils.py`), adding a **live stats dashboard** (`/api/stats`, WebSocket `/ws/stats`,
  `web/stats.html`). Adds `fastapi`/`uvicorn[standard]`/`python-multipart` to `requirements.txt`
  and `stats_ws_interval` to the config. (Landed on the remote between 2.4.2 and this sync;
  documented here for completeness — see the `webapp v3` migration note in `utils.py`.)

## [2.4.2-alpha] — 2026-07-28

### Fixed
- **e-Paper log spam** (found on hardware). The display calls `init_partial_update()` +
  `display_partial()` on every refresh (~1–2×/s); the logging added in 2.3.0 logged success on
  those per-frame paths, producing ~3 log lines/second (85 KB in 11 min → needless SD writes,
  against the PG-2 SD-protection goal). Now the per-frame methods log **failures only**; the
  one-time full-init/load/clear messages stay. Live fix for an existing install:
  `sudo sed -i "/Initializing EPD.*partial update/d; /EPD partial update initialization complete/d; /Partial display update complete/d" /home/bjorn/Bjorn/epd_helper.py && sudo systemctl restart bjorn.service`.

## [2.4.1-alpha] — 2026-07-28

### Fixed
- **PG-4 watchdog was a silent no-op** (found on real hardware). In the systemd unit, the
  heartbeat-age `ExecStartPost` used `date +%s` / `stat -c %Y`, but `%` is a systemd *specifier*
  char — systemd expanded `%s`→shell and `%Y`→a path when loading the unit, corrupting the
  command so it never computed a real age and never restarted on a hang. Escaped as `%%s` / `%%Y`.
  Everything else (service, display, fd-watchdog) was unaffected. Live fix for an existing
  install: `sudo sed -i 's/date +%s/date +%%s/; s/stat -c %Y/stat -c %%Y/'
  /etc/systemd/system/bjorn.service && sudo systemctl daemon-reload && sudo systemctl restart
  bjorn.service`.

All notable changes to this project are documented here. This file also serves as the
process log for the PRD §9 (P1) modernization pass.

## [2.4.0-alpha] — 2026-07-28

### Added (resilience — Pwnagotchi ideas PG-2/3/4; PRD §11)
- **PG-4 loop watchdog.** The main loop refreshes a `/run/bjorn_heartbeat` file each iteration
  (tmpfs → zero SD writes); a systemd `ExecStartPost` background loop restarts `bjorn.service` if
  it goes stale (>180 s), catching a *wedged* main loop that `Restart=always` alone can't (the
  process is still alive). Chose this over `Type=notify` sd_notify to avoid any chance of the
  service failing to start on hardware that couldn't be tested.
- **PG-3 battery/UPS awareness** (`battery.py`, opt-in via `battery_monitor_enabled`). Reads charge
  from a PiSugar power server (stdlib sockets, no dependency); when charge ≤ `battery_shutdown_percent`
  (default 10) Bjorn powers off cleanly to protect the SD card. No-op when no battery server is
  reachable, so it's harmless on a mains-powered Pi.

### Changed
- **PG-2 SD-card protection.** `netkb.csv` is now written atomically (`write temp → fsync →
  os.replace`) so a power loss mid-write can't leave a half-written, corrupt CSV (it's rewritten
  on every action — the most exposed file). The systemd unit gained `TimeoutStopSec=30` so a
  commanded shutdown/reboot gives Bjorn time to flush, and `RestartSec=10`.

### Added
- **`scripts/bjorn_doctor.sh`** — one read-only command that aggregates the whole health
  picture into a single report: version/OS/arch, SPI + `epd_type`, `bjorn.service` status,
  recent errors from **every** log location (`data/logs/*.log`, the systemd journal, and the
  newest `/var/log/bjorn_install/` log), and a map of where every log/loot/output file lives.
  Runs even when Bjorn won't start. Documented as the "start here" step in `TROUBLESHOOTING.md`.

## [2.3.0-alpha] — 2026-07-27

### Added
- **`epd_type: "auto"`** display driver selection (idea PG-1, from Pwnagotchi's multi-display
  support; PRD §11). At startup Bjorn tries the real-panel drivers in order and uses the first
  that initializes, logging each attempt — so it boots even if the configured driver errors or
  the HAT is absent. **Honest limit:** this keys off driver *init*, which can't tell V3 from V4
  (both init on the same panel with no render feedback); for a "inits but renders blank" panel,
  use `scripts/epd_test.py --all` (visual probe) to find the right one, then pin it.
- **PRD §11** — evaluated the Pwnagotchi ecosystem for transferable ideas; recorded graceful
  shutdown (PG-2), UPS awareness (PG-3), loop watchdog (PG-4), plugin system (PG-5), GPS tagging
  (PG-6) in `docs/BACKLOG.md`.
- **`scripts/epd_test.py`** — a standalone e-Paper diagnostic (run on the Pi). Checks SPI, then
  loads → inits → draws a visible test pattern → clears for a given `epd_type` (or `--all` to
  probe every driver in a fresh process each). Prints exactly which step fails, with traceback —
  the fastest way to find the driver that matches your HAT when the panel stays blank.

### Changed
- **e-Paper failures are now logged.** `epd_helper.py` logs through Bjorn's `Logger` (rich +
  data/logs/) with step-by-step init messages and full tracebacks (falls back to stdlib logging
  off-device so it stays importable in tests). `shared.py::initialize_epd_display` now logs an
  actionable blank-panel checklist (SPI enabled? epd_type correct? run epd_test.py) plus the
  traceback. Previously EPD errors went to a bare, unconfigured logger and were effectively
  swallowed.
- **Installer installs from the local repo instead of cloning from GitHub.** `install_bjorn.sh`
  now copies the repo it was run from (the folder the script lives in) into `/home/bjorn/Bjorn`
  — no network, works with a private repo. It only falls back to `git clone` when run standalone
  and `/home/bjorn/Bjorn` doesn't already exist. Fixes the private-repo clone failure (GitHub no
  longer supports git password auth). README/INSTALL updated to the "download repo → run installer
  inside it" flow.
- Installer prerequisite check no longer warns about `nmap` — it's installed in the dependency
  step, so pre-checking it always false-flagged on a fresh image (`nmcli`/`python3` are still
  checked, as they must pre-exist).

### Removed
- Dropped the public security-disclosure channel — deleted `SECURITY.md` and the issue-template
  "Security Reports" link. This fork is a private, personal-use repo; the inherited policy
  pointed vulnerability reports at the upstream author's email, so it was misleading rather than
  useful.

### Docs
- Repointed all install/self-references from upstream `infinition/Bjorn` to this fork
  (`Gixar/Bjorn-v2`): the README `wget` URL, the installer's `git clone`, `INSTALL.md`, the
  Contact/Star-History sections, and the issue-template links. Kept MIT attribution (LICENSE,
  original author) and the upstream Bjorn Detector reference. Noted the private-repo caveat for
  `wget`/`git clone`.

## [2.2.0-alpha] — 2026-07-26

### Changed (performance — target: Raspberry Pi Zero; see PRD §10)
- **Scan engine now uses nmap for port scanning** (L1): replaced the pure-Python socket
  scanner (a thread per host×port, throttled by a 200-thread semaphore) with a single
  `nmap -sT` process across all alive hosts. Deleted the dead `PortScanner` class + `socket`
  import.
- **Host MAC comes from the `nmap -sn` result** (L2): dropped the per-host 5×2 s ARP retry
  loop; `get-mac` is now a fallback only (and capped at ~2 s).
- **Removed the fixed `time.sleep(5/7/0.1)` scan delays** (P6): host discovery is now
  synchronous, which also fixes a read-before-threads-finish race.
- **Wi-Fi scan uses `nmcli` instead of the deprecated `iwlist wlan0 scan`** (L4).

> ⚠️ **Unverified off-device.** These change the core scan path and the Wi-Fi scan, and could
> only be `py_compile`-checked here (no nmap/network on the dev box). They need a real Pi + LAN
> to benchmark and confirm no regression before relying on them. Remaining perf items (P1–P5,
> L3) are tracked in `docs/BACKLOG.md`.

## [2.1.0-alpha] — 2026-07-26

### Fixed (from upstream/fork bug reports)
- **404 when executing a manual attack** (upstream #130 / #81, the most-upvoted open bug):
  after a manual attack, `web/index.html` fetched `/recent_logs`, which has no server route
  (the real endpoint is `/get_logs`) — the 404 users saw. Fixed the endpoint; removed the dead
  `/manual.html` route (the manual-attack UI already lives in `index.html`). *(Fix is against
  the verified server contract; not click-tested — needs the running WebUI to confirm.)*
- **Web server port hopping on restart** (upstream #16): `webapp.py` now uses a
  `ReusableTCPServer` with `allow_reuse_address = True` (SO_REUSEADDR), so a restart while the
  old socket is in TIME_WAIT rebinds :8000 instead of hopping to :8001+.
- **Installer aborted when one apt package was unavailable** (upstream #147, `libatlas-base-dev`
  removed in Debian trixie): `install_bjorn.sh` now warns and continues per-package instead of
  hard-failing the whole install.
- **Installer e-Paper prompt** (upstream #152): listed 5 display options but prompted "(1-4)";
  fixed to "(1-5)".

### Added
- `docs/BACKLOG.md`: tracked ideas mined from community forks and upstream issues (wpa-sec import,
  scan-all-interfaces, BadUSB, tri-color e-Paper, WebUI log viewer, Wi-Fi selection, etc.), each
  with a concrete implementation pointer. Most need the Pi/WebUI/hardware to build and verify.

## [2.0.0-alpha] — 2026-07-26

Modernization baseline. Executes the implementable subset of `docs/PRD.md` §9 (P1).
Hardware/OS-gated items (dependency refresh via `pip freeze` on the Pi, real e-Paper render,
full installer run) are prepared but must be verified on the target Raspberry Pi — see the
"Pi-gated" note below.

### Added
- **Mock e-Paper backend** (`resources/waveshare_epd/epdmock.py`) + a `"mock"` branch in
  `shared.py::initialize_epd_display`, so the app can run on a non-Pi dev box with
  `epd_type: "mock"` (testing only). (P1-3)
- **Fail-fast config validation** (`config_validation.py`, wired into `SharedData.load_config`):
  required keys/types are checked at startup and a clear `ValueError` lists every problem. (P1-6)
- **`retry_policy.py`** — the action retry-delay window decision, extracted from four
  copy-pasted blocks in `orchestrator.py` (one guard, all callers). (P1-4)
- **Baseline test suite** (`tests/`): retry policy, config validation, mock display, and one
  connector path (`SSHConnector.ssh_connect` with paramiko mocked). Each runs under pytest and
  as `python tests/test_*.py` with zero install. (P1-4)
- **CI** (`.github/workflows/ci.yml`): pytest + pylint (errors-only) on push/PR; badge in README. (P1-5)
- **Run reports + offline improvement path** (prior work this cycle): per-run redacted JSON
  reports (`Orchestrator.write_run_report`), `scripts/analyze_reports.py`,
  `scripts/export_reports.sh`, and `docs/IMPROVEMENT_PROCESS.md`. (PRD §4a DEV-1/1a/2/3)
- **Installer `--dry-run`** and an `nmap`/`nmcli`/`python3` prerequisite probe in
  `install_bjorn.sh`; reuses the existing `verify_installation` healthcheck. (P1-7)

### Changed
- `requirements.txt`: removed the dead `RPi.GPIO==0.7.1` pin (the e-Paper driver already uses
  `gpiozero`); added `gpiozero` + `lgpio`. Other pins flagged for a Pi `pip freeze`. (P1-1)
- `debug_mode` now defaults to `false` (in both `config/shared_config.json` and the in-code
  default). (P1-6)

### Pi-gated (not verified on this dev box — operator verifies on the Pi)
- **Dependency refresh** (P1-2): bump numpy/Pillow/pandas/paramiko/pysmb/smbprotocol/pymysql/
  python-nmap and re-pin via `pip freeze` on the target Pi OS Python; then `pip install -r
  requirements.txt` in CI.
- **Full installer run**, **real e-Paper render**, **clean install on a fresh image**.
