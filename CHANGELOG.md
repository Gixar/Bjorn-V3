# Changelog

## [Unreleased]

### Changed
- **Offline CVE enrichment now also reads un-CPE'd services** — `_parse_service_versions` gained a
  `-sV` service-line fallback: when nmap can't emit a CPE (common on consumer gear — a Wave 0 test
  router returned "2 services unrecognized"), it takes the first two tokens of the version detail
  (`PORT open SERVICE <product> <version>`) as `(product, version)`. Garbage products simply match
  no signature, so it only adds hits, never false positives. Catches the single-token products in
  the seed DB (vsftpd/openssh/proftpd/unrealircd) even without a CPE.

### Fixed
- **Manual attack no longer offers un-runnable actions (NetworkScanner 500)** — the manual-attack
  dropdown (`/netkb_data_json`) listed *every* netkb action column, so picking **NetworkScanner**
  (or IDLE / a standalone log action) hit `execute_manual_attack`'s "Action class … not found" path
  and errored. `serve_netkb_data_json` now filters to actions the handler can actually run per host:
  the port-based connectors plus the special-cased `NmapVulnScanner`, derived from the loaded action
  metadata (`port not in (0, None)`) rather than a hardcoded denylist. Found during Wave 0 on-Pi
  verification.

### Added
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
