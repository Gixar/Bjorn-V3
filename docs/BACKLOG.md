# Backlog — ideas from community forks & upstream issues

Sourced from the MIT-licensed Bjorn ecosystem (reuse is clean with attribution in
`CHANGELOG.md`). These are **not yet built** — most need the Pi, a running WebUI, a live
network, or a vendor driver to build and verify properly, so they're tracked here rather than
shipped blind. Each entry names the concrete change so it's ready to pick up.

Already fixed this cycle (see `CHANGELOG.md`): #16 port hopping, #147 installer apt abort,
#152 EPD option-count prompt. Already covered by the v2 baseline: run-without-display (#11 →
`epd_type: "mock"`), dependency modernization (P1-1/P1-2).

## Bugs still open (need the WebUI/Pi to reproduce + verify)
| Ref | Issue | Likely fix / pointer |
|---|---|---|
| #176 | Can't enter comma-separated ports in GUI Settings | **Appears already resolved** in current code — `web/scripts/config.js` renders `portlist` as a text input and `saveConfig` splits on commas into an array. Re-test in the UI; no code change identified. |
| ~~#190 / #160~~ | ~~Wi-Fi APs not shown / no SSID switch in WebUI~~ | **Appears already resolved** — `config.js::scanWifi` renders `data.networks`, marks `current_ssid`, and click-to-connect POSTs `{ssid, password}`; backend uses `nmcli` (not the old `iwlist`). Only the on-Pi runtime (sudo/nmcli perms on `wlan0`) remains — re-test on the device. |
| ~~#130 / #81~~ | ~~404 / error executing a manual attack~~ | ✅ **FIXED** — real cause was `index.html` fetching `/recent_logs` (nonexistent) right after the attack; changed to `/get_logs`. The dead `/manual.html` route was removed. The manual-attack UI already lives in `index.html`. |
| #155 | Web server not showing | Overlaps #16 (port hopping) — re-test after the SO_REUSEADDR fix; if still failing, check the systemd unit + firewall. |
| #122 | Installed but no Display *or* WebUI (most-commented) | Multi-cause: partly #16 (port), partly EPD init failing on the panel. Re-test after the port fix; if the display is still dead, check `epd_type` + wiring. Pi-only. |
| #113 | Waveshare **V4 unreadable** display | Affects the **default** `epd_type: "epd2in13_V4"` — reported as unreadable/garbled since May 2025. Likely a refresh-mode / LUT or rotation issue in the vendor driver. Needs the actual V4 panel to diagnose. |
| #68 | `usb0` IP not assigned | **Fix written — needs on-Pi verification.** `configure_usb_gadget` was rewritten to one coherent stack: dwc2-only (dropped the `g_ether` that raced the configfs gadget for the UDC), `systemd-networkd` owns `usb0` via a `.network` file (static `172.20.2.1/24` + built-in DHCP server so the *host* gets `172.20.2.10-30`), NetworkManager set to leave `usb0` unmanaged, and the conflicting ifupdown/imperative-`ifconfig` bits removed. Verify on hardware (plug into a host → usb0 addressed, host leased, `http://172.20.2.1:8000/` loads). Pi-only. |

## From runtime logs (`bk_log`, Jul 31 – Aug 1 2026 — priority order)

Triaged from a live Pi log pull (24 files). Totals: **505 ERROR, 7221 WARNING**, all
collapsing to 4 distinct issues.

1. ~~**[P1] Orchestrator floods the log at WARNING every second while idle**~~ — ✅ **FIXED** —
   `orchestrator.py` logged `"Scanner did not find any new targets. Next scan in: N seconds"` at
   `logger.warning` once per second for the whole `scan_interval` (180s) idle window → **7217 lines
   / 829 KB in `orchestrator.py.log`**, with an ANSI console-cursor trick (`\x1b[1A\x1b[2K`) mixed in.
   Now logs the idle notice **once** per idle window at **INFO** ("Scanner found no new targets;
   idling Ns until next scan.") and the idle loop just sleeps; dropped the per-second WARNING, the
   ANSI write, and the now-unused `import sys`. This was the **likely root cause of the `logs.html`
   freeze** — the log file no longer balloons.
2. ~~**[P2] `usb0` "Cannot find device" — 505 errors**~~ — ✅ **FIXED** — `display.py::is_usb_connected`
   logged ERROR every ~25s whenever `ip neigh show dev usb0` failed, but a missing `usb0` (gadget
   down / nothing plugged in) is the **normal not-connected state**, not an error — it produced all
   505 errors in the log pull. Now the "Cannot find device" case logs at **DEBUG** and returns
   `False` (not connected); only genuinely unexpected stderr stays at ERROR. Independent of #68
   (the gadget-config fix) — even with usb0 configured, an unplugged device shouldn't spam ERROR.
3. ~~**[P3] `use_rustscan: True` but the `rustscan` binary "not found"**~~ — ✅ **FIXED (path resolution)** —
   rustscan **was** installed (`/home/gixar/.cargo/bin/rustscan`, v2.4.1) but `shutil.which("rustscan")`
   missed it: the service runs as `root` under systemd with a minimal PATH that omits `~/.cargo/bin`,
   and here it was built under a **different** user (`gixar`, not `bjorn`). Added `NetworkScanner._rustscan_bin()`
   — `which` first, then a glob fallback over `/home/*/.cargo/bin`, `/root/.cargo/bin`, `/usr/local/bin`,
   `/usr/bin` (root can traverse the 700-mode `/home/gixar` and exec the binary). Wired it into
   `selected_engine`, the benchmark guard, and `_rustscan_cmd` (now takes the resolved path instead of
   the literal `"rustscan"`). Works on the existing install with no reinstall. Tests updated + a new
   `test_rustscan_bin_falls_back_to_cargo_path_off_PATH`. **Now unblocks** the batch-size tuning item
   below — the benchmark can finally run rustscan's pass. Verify on the Pi: WebUI Benchmark now shows a
   rustscan column.
4. **[P4] nmap port scan incomplete — 1×, self-recovered** — `scanning.py` (Jul 31 21:28) logged
   `"nmap port scan did not complete this cycle … keeping existing port data"` once. Transient,
   self-healing. Monitor only; no action unless it recurs.

> Note — the **"start scan freezes the Pi"** symptom is **not** in these logs (a hang isn't logged).
> Needs the systemd journal + `dmesg` (OOM check) pulled while reproducing — see the SSH log-pull steps.

## New capabilities (extend the offensive/recon surface — feeds P3-1 module contract)
- **wpa-sec / Pwnagotchi network import** (from `LOCOSP/BjornWpaSecHarvester`): pull cracked Wi-Fi creds from wpa-sec.stanev.org, dedupe, inject via `nmcli`. Pre-populates known creds instead of blind brute-force. New standalone action; needs network + `nmcli`.
- ~~**Scan all network interfaces**~~ (#133): ✅ **DONE** — `get_network()` → `get_networks()` returns one IPv4Network per interface subnet (all AF_INET addrs, deduped, loopback/link-local skipped). `scan()` loops every subnet and **accumulates** hosts into a single `update_netkb` write with the union of alive MACs — writing per-network would make each subnet mark the others' hosts dead. Dropped the dead (never-printed) `table` builder while there. Needs a multi-interface host to verify end-to-end.
- **SNMP enumeration** and **HTTP service fingerprinting**: new recon modules against the P3-1 `b_class/b_module/b_port/execute()` contract (HTTP fingerprint is already the PRD's P3-5 example).

## Hardware / display
- **Waveshare 2.13" B/C tri-color** (#166) — **deferred (YAGNI, single panel for now).** Only the
  default 2.13" V4 panel is in use, so multi-panel support isn't needed yet. Revisit when a
  tri-color (or other) panel is actually on hand — the change is small: add
  `resources/waveshare_epd/epd2in13bc.py` from the vendor driver, an `epd2in13bc` case in
  `shared.py::initialize_epd_display`, and the type to `KNOWN_EPD_TYPES` in `config_validation.py`.
  Needs the vendor driver + the actual panel to verify.

## Quality-of-life
- ~~**In-WebUI log viewer**~~ (from `BjornCocaine`): ✅ **DONE** — added `web/logs.html` + `web/scripts/logs.js` + a "Logs" nav entry (`common.js`) + `logs` in `_PAGES` (`webapp.py`). The colorize/escape renderer was extracted to `common.js` (`colorizeLogLine`/`renderLogsInto`) and shared with the home console. WebUI-only; re-check rendering on the Pi.
- ~~**Static IP assignment**~~ (#26, done upstream): ✅ **DONE** — the Wi-Fi connect panel now takes optional Address/CIDR + Gateway + DNS fields (`config.html`/`config.js`); `utils.py::_static_ipv4` validates them with stdlib `ipaddress` (rejects malformed input / requires a prefix so nothing unsafe reaches the NM keyfile) and `update_nmconnection` writes `method=manual` when set, else DHCP as before. Default (blank) path unchanged. Needs on-Pi verification that NetworkManager applies the manual profile.
- ~~**Proxmox / headless-VM deployment**~~ (#138): ✅ **DONE (docs)** — added `docs/INSTALL_VM.md` (set `epd_type: "mock"`, which installer steps are Pi-only). End-to-end verification on a real hypervisor still open.
- **Coins / stats overhaul** — **M.** 📋 **scoped: see [`COINS_STATS_PLAN.md`](COINS_STATS_PLAN.md)** (monotonic high-water-mark model, persisted, level curve, richer web breakdown). Today `shared.py::update_stats()` recomputes `coinnbr`/`levelnbr`
  as a flat linear function of *current* counts (`networkkbnbr*5 + crednbr*5 + datanbr*5 +
  zombiesnbr*10 + attacksnbr*5 + vulnnbr*2`) on every refresh, so the score is a live gauge that
  **can drop** (netkb cleaned, hosts go offline) and rewards nothing durably; levels are a flat
  multiplier with no progression. Overhaul across four fronts (all confirmed wanted):
  1. **Earned & persistent score** — make coins **event-driven and monotonic**: award on the moment
     an achievement happens (new host, cred cracked, file stolen, vuln found, zombie, attack) and
     **persist** the running total across restarts (a small `data/stats.json`), instead of deriving
     it from mutable live counts. Coins only ever go up.
  2. **RPG level curve** — levels use **rising thresholds** (each level costs more coins than the
     last, e.g. a simple geometric curve) instead of the flat multiplier, for real progression.
  3. **Richer stats in the web UI** — expose the **breakdown + trend** on the stats dashboard
     (per-category earned totals, recent-coin history, what earned the last coins), not just the
     single totals shown today. Builds on the existing `/api/stats` + `web/stats.html`.
  4. **Rebalanced weights** — retune the award table so rare achievements (cred cracked, file
     stolen) pay more than common ones (a host merely appearing), decided alongside (1).
  *Touches:* `shared.py` (award hooks at the achievement sites + persistence), `utils.py`/`webapp.py`
  (stats snapshot + history), `web/stats.html`/`stats.js` (breakdown view), `display.py` (still reads
  `coinnbr`/`levelnbr`, unchanged). Design decision needed on the award table + persistence shape
  before coding; keep the change-gated (P5) recompute discipline so it stays cheap on a Pi Zero.

## AI / learning (overlaps §4a + P-AI — keep lazy)
- **Anonymized mission-data export** (the `infinition/Bjorn-cortex` framing): our run-reports already do the redacted-export half. Adopting Cortex's `.csv.gz` shape would make us swarm-compatible later **without** committing to the heavy VPS/TensorFlow stack. YAGNI until there's a Cortex to feed — revisit only if we join a swarm.

## Performance (deferred — full analysis in PRD §10)

Done in v2.2.0-alpha: **L1** (nmap port scan), **L2** (MAC from nmap), **P6** (removed scan
sleeps/race), **L4** (nmcli Wi-Fi scan). Still deferred (mostly safe code changes, held back to
keep each pass to one testable area):

- ~~**P1**~~ — ✅ **DONE** — brute-force connectors (SSH/Telnet/SQL/SMB/FTP/RDP) no longer hardcode 40 threads; new `bruteforce_threads` config key (0 = auto → `min(8, cpu*4)`), validated non-negative in `config_validation.py`.
- ~~**P2**~~ — ✅ **DONE** — removed the module-top `import pandas` from all 10 files. The 6 brute-force connectors + `display.py` now use stdlib `csv` (via three shared helpers in `shared.py`: `netkb_targets`, `append_csv_rows`, `dedupe_csv`) since they only read/count/dedupe. `scanning.py` (LiveStatusUpdater), `nmap_vuln_scanner.py`, and `steal_data_sql.py` keep pandas but **lazy-import** it inside the methods that need it (groupby/read_sql), so a run that never vuln-scans or SQL-steals never loads pandas at all. Substring port-match and drop-duplicates semantics preserved. Needs the Pi to confirm the memory/startup win.
- ~~**P3**~~ — ✅ **DONE** — `execute_action`/`execute_standalone_action` and the vuln loop no longer call `write_data` per action; `run()` now batches to one `netkb.csv` write per cycle branch (active + idle). `write_data` itself (atomic temp-file + fsync merge) is unchanged. Trade-off: mid-cycle results lost on a crash — actions just re-run next cycle. Needs the Pi to verify end-to-end.
- ~~**P4**~~ — ✅ **DONE** — removed the duplicate nested action loop that `run()` ran inline after `process_alive_ips()`; the single `process_alive_ips()` call now handles it.
- ~~**P5**~~ — ✅ **DONE** — added a `shared_data.data_generation` counter bumped once per completed scan (`scanning.py`). The display threads (`display.py`) now re-parse netkb/livestatus only when it changes: `update_vuln_count` skips the full netkb/vuln_summary read when unchanged, and `update_shared_data` gates the livestatus read the same way (action-driven cred/loot/zombie/attack counts stay per-tick). Safe fallback: if the counter never bumps, it just recomputes as before. Single writer / lockless. Needs the Pi to verify counts stay live.
- ~~**L3**~~ — ✅ **DONE** — vuln-scan flags now config-driven: timing was already `nmap_scan_aggressivity`; added `vuln_scan_sv` and `vuln_scan_vulners` bools (both default True) so `-sV` and the internet-dependent `vulners.nse` are optional. Args built conditionally in `nmap_vuln_scanner.py`; both validated as bools.

## Ideas from Pwnagotchi (adjacent project — full analysis in PRD §11)

Done: **PG-1** (`epd_type: "auto"`, v2.3.0-alpha); **PG-2/PG-3/PG-4** (v2.4.0-alpha — atomic
netkb writes + `TimeoutStopSec`; opt-in `battery.py` PiSugar monitor + low-charge shutdown;
`/run` heartbeat + systemd watchdog restart). Deferred:

- **PG-5 — plugin system** (lifecycle + UI + web hooks): widen the P3-1 module contract from attack-modules-only to features generally (folded into P3-1 scope, not separate work).

## Adjacent-project feature ideas (survey — Flipper/Pwnagotchi/bettercap/Kismet/Responder/nuclei)

Ideation pass mining adjacent cybersec projects for capabilities that fit Bjorn's shape (Pi Zero,
the `netkb.csv` pipeline, the `b_class` action-module contract, the network it already joins via
`nmcli`). Same offensive class as the existing tool — authorized-testing use assumed. Ranked by
fit ÷ effort. Effort tags: **S** ≈ 1 session, **M** ≈ 2–3 sessions, **L** ≈ multi-PR.

1. **Offline CVE enrichment** *(searchsploit / nuclei-cves)* — **S.** Map the service versions
   `nmap -sV` already gathers to a bundled offline CVE DB; flag vulnerable hosts in `netkb.csv`.
   Extends `NmapVulnScanner`; no new hardware, no scan-time internet. Highest fit ÷ effort.
2. **Responder-style LLMNR/NBT-NS/mDNS poisoning** *(Responder / Impacket)* — **M.** Passive
   NetNTLM-hash capture on the joined LAN → loot file for offline cracking. See effort detail below.
3. **nuclei-style templated web checks** *(ProjectDiscovery nuclei)* — **M.** Templated vuln checks
   against discovered HTTP services; builds directly on the **HTTP fingerprinting** item above
   (fingerprint → fire matching YAML templates, extensible without code).
4. **Credential reuse / auto-lateral chaining** *(CrackMapExec pattern)* — **S–M.** When a
   brute-force cracks a cred, auto-replay it across every other host/protocol in `netkb` (reuse /
   spray). Pure logic on top of the existing 6 connectors + netkb; compounds every crack.
5. **PCAP capture + offline exfil** *(tcpdump / bettercap sniff)* — **M.** Rotating capture on the
   joined network, delivered via the planned Telegram/report pipeline. Extends the Bettercap
   managed-mode **sniff** capability already scoped in [`BETTERCAP_PLAN.md`](BETTERCAP_PLAN.md).
6. **BLE recon + tracker detection** *(Flipper/Marauder BLE, OpenHaystack/AirGuard)* — **S–M.**
   Enumerate nearby BLE devices, detect Apple/Google trackers, feed into netkb. Scanning needs **no
   monitor mode**. See effort detail below.
7. **Passive Wi-Fi survey / wardriving** *(Kismet / Pwnagotchi)* — **M** (on top of Bettercap
   Phase 4) / **L** standalone. Log nearby APs+clients (BSSID/signal/channel, optional GPS) to a
   wardriving map. Needs monitor mode → shares the second-radio gate. See effort detail below.
8. **Evil Twin / rogue AP + captive portal** *(WiFi Pineapple / hostapd+dnsmasq)* — **L.** Lookalike
   AP + credential-harvesting portal. Needs an AP-capable radio; overlaps bettercap. Later project.
9. **HID / BadUSB payload delivery** *(Flipper BadUSB / P4wnP1 / Rubber Ducky)* — **M.** Bjorn is
   already a USB gadget (`usb0`) — add HID-keyboard emulation to type payloads on the plugged host.
   ⚠️ BadUSB was **deliberately dropped** earlier (commit `f914191`) — this is a reversal to
   reconsider, not a fresh idea.
10. **Defensive "canary" mode** *(OpenCanary / Thinkst)* — **M.** Blue-team pivot: fake services as
    a tripwire that alerts on touches. Reuses the web/report stack; a legally-safer second personality.

### Effort detail — #2, #6, #7

**#2 Responder LLMNR/NBT-NS/mDNS poisoning — Effort: M (~2 sessions).**
- *Hardware:* none — runs on the LAN Bjorn already joined (same model as current scanning). Root required.
- *Approach (lazy):* run the existing **Responder** tool (Python, GPL) as an external managed
  process — same "subprocess vs reimplement" pattern used for nmap/nmcli — and parse its output
  DB/logs for captured hashes rather than reimplementing the LLMNR/NBT-NS/mDNS listeners.
- *New/touched:* `responder_client.py` (spawn + parse) or a standalone action; loot schema for
  NetNTLM hashes (new `data/output/` file); `install_bjorn.sh` provisions Responder; a web toggle.
- *Risks:* **port conflicts** — Responder wants 53/80/139/445, which can clash with the Pi's own
  services; needs to bind the right interface; it's **noisy/detectable**; runs continuously (not
  per-cycle), so it needs its own start/stop lifecycle like the Bettercap poller.
- *Bulk of the work:* process lifecycle + output parsing + loot integration, not the capture itself.

**#6 BLE recon + tracker detection — Effort: S–M (~1.5–2 sessions).**
- *Hardware:* built-in — Zero 2 W has BLE (Zero W BT 4.1). **Scanning needs no monitor mode**, so
  it's far lower-risk than any Wi-Fi-monitor idea.
- *Approach (lazy):* passive scan via BlueZ — either `bleak` (asyncio) or shell out to
  `bluetoothctl scan`/`btmgmt` (subprocess pattern). A data-source thread (like the Bettercap
  poller), not a per-target action.
- *New/touched:* `ble_scanner.py`; **netkb schema** needs a `device_type`/`source` column for
  non-IP wireless entries (the *same* schema gap flagged in the Bettercap Phase-4 / ESP32 items —
  do it once, share it); web toggle.
- *Tracker detection:* match Apple/Google Find My manufacturer-data / service-UUID heuristics
  (OpenHaystack/AirGuard approach) — this heuristics table is most of the "M" over the "S".
- *Web UI (required):* a dedicated panel — config (enable, scan interval, tracker-alert toggle)
  **and** a results view listing discovered BLE devices/trackers — modeled on the Bettercap panel.
- *Risks:* netkb schema change; BlueZ scan reliability; BT/Wi-Fi coexistence on the shared antenna.

**#7 Passive Wi-Fi survey / wardriving — Effort: M *if built on Bettercap Phase 4*, else L.**
- *Hardware:* **needs monitor mode → a second radio, never `wlan0`** (same gate, same nexmon
  caveats as Bettercap Phase 4). This radio requirement is the dominant cost.
- *Approach (lazy):* **don't build a separate monitor stack** — bettercap already does `wifi.recon`.
  Wardriving = subscribe the Bettercap poller to AP/client events and log them to a wardriving CSV +
  optional GPS tag. So this is largely an **extension of Bettercap Phase 4**, not standalone work.
- *New/touched:* extend the Bettercap poller + a `wardrive.csv`; optional GPS (needs a GPS module —
  note **PG-6 GPS tagging was dropped** earlier, so GPS is its own deferred sub-item).
- *Web UI (required):* a dedicated panel — config **and** a wardriving results view (AP/client
  table with BSSID/signal/channel, optional map) — modeled on the Bettercap panel.
- *Risks:* monitor-mode hardware instability (nexmon on Zero 2 W), second-radio requirement, GPS module.
- *Recommendation:* schedule **after** Bettercap Phase 4 lands; building it standalone duplicates
  the whole monitor-mode/second-radio effort for little gain.

## Reference forks
- `HackCocaine/BjornCocaine` — screen-agnostic WebUI-first, LOGS button, multi-Pi.
- `LOCOSP/BjornWpaSecHarvester` — wpa-sec/Pwnagotchi import.
- `infinition/Bjorn-cortex` — swarm-AI training hub (heavyweight).
- `PierreGode/Ragnar` — the predecessor project.

## Future changes ideas.

  - ~~**RustScan for full-port discovery**~~ — ✅ **DONE (opt-in, off by default)** — added the
  `use_rustscan` config toggle: when on and the `rustscan` binary is present, the discovery pass
  runs RustScan (`-g` greppable) instead of `nmap -sT`, with nmap still doing service detail;
  falls back to nmap automatically if the binary is missing or a run fails. `install_bjorn.sh`
  now provisions the official prebuilt binary into `/usr/local/bin` on arm64/amd64 (non-fatal;
  32-bit armv7 → `cargo install rustscan` manually). Benchmark test mode
  (`python actions/scanning.py --benchmark`) times both engines on the same target into
  `data/scan_engine_benchmark.csv`. The `rustscan_batch_size` config key (0 = RustScan default)
  now wires `-b <n>` into the command for on-device tuning. **Still open:** pick the actual batch
  value on a real Zero 2 W (run the web Benchmark button, lower `rustscan_batch_size` if ports drop)
  before considering making RustScan the default. Original note kept below for the tuning rationale.
  - **RustScan for full-port discovery** — replace/augment the 2.2.0-alpha `nmap -sT`
  sweep with RustScan for the initial port-discovery pass: it scans all 65,535 ports
  in ~3s via adaptive-batched async sockets (vs. the curated `portlist`/`portstart`-
  `portend` range scanning currently uses to stay within the scan interval), then
  hands its results to `nmap` for service/version detail — the same two-stage shape
  the current engine already uses, so this is a discovery-stage swap, not a pipeline
  rewrite. Officially install-only via `cargo install rustscan` (Rust toolchain
  required); community ARM packages exist (Snap Store, Arch Linux ARM aarch64) but
  aren't official releases — installer prerequisite checks would need a new block
  alongside the existing `nmap`/`nmcli` checks. GPL-3.0 licensed, same license family
  as `nmap`/`nmcli` which Bjorn already shells out to as external processes, so no
  new licensing exposure for Bjorn's own MIT code. Batch size needs on-device tuning
  against the Zero 2 W's file descriptor limits — too-aggressive batching is
  RustScan's documented failure mode (dropped/missed ports, not an error), so this
  needs real benchmarking before it replaces anything, not just a swap-in.

  - **Bluetooth PAN access from a phone** — run the Pi as a Bluetooth NAP (Network
  Access Point) via BlueZ's `bt-pan` so a paired phone gets a real IP over Bluetooth
  (`bnep0`/`pan0` + a `dnsmasq`-scoped DHCP lease) and can hit the existing FastAPI
  web server directly (`http://<bt-ip>:8000/`) — no new app-layer code needed, every
  current endpoint (config, stats, backup/restore, file download) works unmodified
  since it's just another network interface. Both Zero W (Bluetooth 4.1) and Zero 2 W
  (4.2 + BLE) already have the hardware. Real value: admin access without Bjorn
  needing to join or host a Wi-Fi network — useful given it's meant to be carried
  around. Needs: (1) pin down which BlueZ NAP tooling ships on the target Bookworm
  image (`pand` is deprecated; `bt-network`/`test-network` vs. the newer `bt-pan`
  script vary by guide/version), (2) `bluetoothd` plugin config so the Pi isn't
  misidentified as an audio device, (3) real on-device testing of connection
  stability (dropped-bnep0 reports exist in the wild), (4) confirm Android vs. iOS
  support — Android's PAN-client role is well-proven, iOS's is unconfirmed and may
  not be viable as a client into a third-party NAP. Installer would need a new
  prerequisite/setup block alongside the existing Wi-Fi (`nmcli`) handling.

  - **Auto-report collected data via Telegram (or email) when internet is available** —
  extend the existing redacted run_reports pipeline (2.0.0-alpha) with an online
  delivery step: render a small Markdown summary (host/port/vuln counts, action
  success/fail tallies — same shape as the /api/stats snapshot the web dashboard
  uses) and send it as a Telegram sendDocument attachment once Bjorn detects
  internet access. Default to counts/errors only, matching the run_reports
  redaction policy already in place — including raw cracked credentials or stolen
  files should be an explicit opt-in config flag, not the default, since this adds
  a third-party transit hop for that data. Connectivity check: either a periodic
  lightweight socket check (simple, small delay) or a NetworkManager dispatcher
  script for instant on-connect firing (matches the existing nmcli dependency,
  more moving parts) — needs a decision. Needs send throttling (per-SSID or
  per-time-window) so a flapping connection doesn't spam the channel. Telegram
  preferred over email for this specifically: HTTPS-only (SMTP ports 587/465 are
  commonly blocked on public/hotel/corporate Wi-Fi — exactly the networks this
  device roams onto), simpler bot-token auth vs. SMTP credential management, and
  pairs directly with an n8n Telegram Trigger for downstream automation/analysis
  of incoming reports. Send the .md as a document attachment with a plain caption
  rather than MarkdownV2-formatted message text — avoids MarkdownV2's escaping
  requirements for `_ * `` [` entirely. Email as a config-swappable fallback
  channel via stdlib smtplib (no new dependency), for networks where Telegram
  itself is blocked.

  - **Bettercap integration (Pwnagotchi-style), opt-in and off by default** — 📋 **scoped: see [`BETTERCAP_PLAN.md`](BETTERCAP_PLAN.md)** for the phased implementation plan (managed-mode MVP + dedicated web panel; monitor mode deferred). Run bettercap (GPL-3.0, single Go binary, same "external process via subprocess" pattern already used for `nmap`/`nmcli`, so no new licensing exposure) as its own managed process via a new systemd unit alongside the existing `bjorn.service`, driven by a new `bettercap_client.py` that follows Pwnagotchi's own `pwnagotchi/bettercap.py` template — a thin REST client against bettercap's `api.rest` module (HTTP Basic Auth; note it defaults to weak `user`/`pass` credentials and needs the same "don't ship this open" treatment as Bjorn's own endpoints) polling or websocket-subscribing `/api/events` and feeding discoveries into the existing `netkb.csv`/stats pipeline as a new data source rather than a separate silo. Ships with only the managed-mode capabilities active — ARP spoofing, MITM, traffic sniffing on whatever network Bjorn is already joined to via `nmcli` — since those need no monitor mode or packet injection and are safe on the current hardware as-is; genuinely new capability over today's port-scan-and-bruteforce model. The 802.11 monitor-mode/deauth/WPA-handshake-capture piece (the actual Pwnagotchi headline feature) stays disabled until the user opts in from the web config, both because it's the flakier hardware path and because monitor mode and managed/connected mode are mutually exclusive on the same radio — running it on `wlan0` would knock Bjorn off its own network (web UI, Telegram reporting, its own scanning) the moment it activated, so enabling it requires a second wireless interface, never `wlan0`. New config keys `bettercap_monitor_enabled` (default `false`) and `bettercap_monitor_iface` (default unset); the config page lists present wireless interfaces as a dropdown (via `iw dev`/`netifaces`, already a dependency) instead of free text, plus a "test monitor mode support" button that runs `iw phy <phy> info` against the selected interface and checks for `monitor` in its supported modes before the user commits to it, and `config_validation.py` fail-fasts at startup — enabled but the configured interface missing or lacking monitor support logs clearly and falls back to disabled rather than crashing or silently no-op'ing. Worth noting for whoever picks a dongle: the onboard chip needs the nexmon firmware patch to enter monitor mode at all, and the Zero 2 W specifically has a currently-open, unresolved nexmon crash-on-injection bug (~50-200 packets before it dies) — the older Zero W's onboard chip is reportedly more reliable for this despite being the weaker board — which is exactly the kind of unreliability this whole opt-in/second-interface design is meant to keep away from Bjorn's own connectivity.

 **Inventory — a fleet of purpose-built ESP32 satellites commanded by Bjorn** — fresh custom
  firmware (not a fork of Marauder's own codebase) reusing its proven WiFi/BLE attack
  techniques (deauth, beacon spam, BLE spam, handshake capture) but architected around a
  wireless command channel from the start, since Marauder's own remote-control path (the
  Flipper Zero companion protocol) is wired serial and doesn't fit a wireless fleet. Hybrid
  dual-radio command design: BLE is the always-on, low-bandwidth control channel — a satellite
  stays reachable over BLE to receive new orders and report short status/results no matter what
  its WiFi radio is doing, so command delivery never competes with an active attack. WiFi/MQTT
  is the bulk-data channel, used before/after a task (not during) to push heavier payloads —
  full task configs, captured PCAPs/handshakes — since BLE's throughput is too limited for that.
  A satellite commits to an assigned task until completion or timeout once started — no
  mid-task interruption — which is what makes the BLE-always-reachable design sufficient instead
  of needing to interrupt an in-progress WiFi operation. Raid mode targets true synchronized
  simultaneous action (e.g. multi-point deauth across channels to defeat channel-hopping
  defenses) — this needs more than "send each device a command whenever": a scheduled
  wall-clock start time and task parameters get pushed to all satellites ahead of time over
  BLE, and each begins independently at that moment, rather than relying on command-delivery
  latency to line up. Devices join the inventory via a runtime pairing handshake rather than
  fixed build-time identity (worth flagging even though not asked for: no revocation mechanism
  is in scope yet, which is worth revisiting given a lost or compromised unit is a lost or
  compromised attack tool, not just a lost gadget). Discovered devices (APs by BSSID, BLE
  peripherals) feed into the existing netkb.csv/stats pipeline rather than a separate model —
  needs schema work, since netkb.csv's current columns (IPs, Ports) assume IP-layer hosts and
  don't natively fit wireless-layer discoveries; likely needs either nullable IP/Port fields for
  wireless-only entries or a device-type column to distinguish IP host vs. WiFi AP vs. BLE
  device within the same table.
