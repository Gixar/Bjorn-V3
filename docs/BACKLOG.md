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
| #190 / #160 | Wi-Fi APs not shown / no SSID switch in WebUI | Backend works (`scan_wifi` returns `{networks, current_ssid}`, `connect_wifi` takes `{ssid, password}`). The gap is front-end render / runtime (`iwlist wlan0` needs sudo + wlan0). Needs the running UI on the Pi to diagnose. |
| ~~#130 / #81~~ | ~~404 / error executing a manual attack~~ | ✅ **FIXED** — real cause was `index.html` fetching `/recent_logs` (nonexistent) right after the attack; changed to `/get_logs`. The dead `/manual.html` route was removed. The manual-attack UI already lives in `index.html`. |
| #155 | Web server not showing | Overlaps #16 (port hopping) — re-test after the SO_REUSEADDR fix; if still failing, check the systemd unit + firewall. |
| #122 | Installed but no Display *or* WebUI (most-commented) | Multi-cause: partly #16 (port), partly EPD init failing on the panel. Re-test after the port fix; if the display is still dead, check `epd_type` + wiring. Pi-only. |
| #113 | Waveshare **V4 unreadable** display | Affects the **default** `epd_type: "epd2in13_V4"` — reported as unreadable/garbled since May 2025. Likely a refresh-mode / LUT or rotation issue in the vendor driver. Needs the actual V4 panel to diagnose. |
| #68 | `usb0` IP not assigned | USB-gadget networking — `install_bjorn.sh::configure_usb_gadget` + the systemd-networkd config. Pi-only. |

## New capabilities (extend the offensive/recon surface — feeds P3-1 module contract)
- **wpa-sec / Pwnagotchi network import** (from `LOCOSP/BjornWpaSecHarvester`): pull cracked Wi-Fi creds from wpa-sec.stanev.org, dedupe, inject via `nmcli`. Pre-populates known creds instead of blind brute-force. New standalone action; needs network + `nmcli`.
- **Scan all network interfaces** (#133): `actions/scanning.py::get_network()` currently uses the single default gateway (`netifaces.gateways()['default']`). Change to return a list of networks (all interfaces with an AF_INET address) and loop `scan_network_and_write_to_csv` per network. Medium; needs a multi-interface host to verify.
- **BadUSB / HID mode** (#129): the installer already sets up a USB gadget (`configure_usb_gadget`); add an HID keyboard profile + a payload runner as a standalone action. Larger; hardware-only.
- **SNMP enumeration** and **HTTP service fingerprinting**: new recon modules against the P3-1 `b_class/b_module/b_port/execute()` contract (HTTP fingerprint is already the PRD's P3-5 example).

## Hardware / display
- **Waveshare 2.13" B/C tri-color** (#166): add `resources/waveshare_epd/epd2in13bc.py` from the vendor driver, then an `epd2in13bc` case in `shared.py::initialize_epd_display` and `KNOWN_EPD_TYPES` in `config_validation.py`. Needs the vendor driver + the actual panel to verify.

## Quality-of-life
- ~~**In-WebUI log viewer**~~ (from `BjornCocaine`): ✅ **DONE** — added `web/logs.html` + `web/scripts/logs.js` + a "Logs" nav entry (`common.js`) + `logs` in `_PAGES` (`webapp.py`). The colorize/escape renderer was extracted to `common.js` (`colorizeLogLine`/`renderLogsInto`) and shared with the home console. WebUI-only; re-check rendering on the Pi.
- **Static IP assignment** (#26, done upstream): port their dhcpcd/NetworkManager static-IP config + a WebUI toggle.
- ~~**Proxmox / headless-VM deployment**~~ (#138): ✅ **DONE (docs)** — added `docs/INSTALL_VM.md` (set `epd_type: "mock"`, which installer steps are Pi-only). End-to-end verification on a real hypervisor still open.

## AI / learning (overlaps §4a + P-AI — keep lazy)
- **Anonymized mission-data export** (the `infinition/Bjorn-cortex` framing): our run-reports already do the redacted-export half. Adopting Cortex's `.csv.gz` shape would make us swarm-compatible later **without** committing to the heavy VPS/TensorFlow stack. YAGNI until there's a Cortex to feed — revisit only if we join a swarm.

## Performance (deferred — full analysis in PRD §10)

Done in v2.2.0-alpha: **L1** (nmap port scan), **L2** (MAC from nmap), **P6** (removed scan
sleeps/race), **L4** (nmcli Wi-Fi scan). Still deferred (mostly safe code changes, held back to
keep each pass to one testable area):

- ~~**P1**~~ — ✅ **DONE** — brute-force connectors (SSH/Telnet/SQL/SMB/FTP/RDP) no longer hardcode 40 threads; new `bruteforce_threads` config key (0 = auto → `min(8, cpu*4)`), validated non-negative in `config_validation.py`.
- **P2** — `import pandas` at module top in ~10 files; on ARMv6 that's ~2–5 s + 50–80 MB each. Replace with stdlib `csv` in the connectors and `display.py` (they only read + count/dedupe); lazy-import elsewhere. Biggest memory win on a 512 MB Zero.
- ~~**P3**~~ — ✅ **DONE** — `execute_action`/`execute_standalone_action` and the vuln loop no longer call `write_data` per action; `run()` now batches to one `netkb.csv` write per cycle branch (active + idle). `write_data` itself (atomic temp-file + fsync merge) is unchanged. Trade-off: mid-cycle results lost on a crash — actions just re-run next cycle. Needs the Pi to verify end-to-end.
- ~~**P4**~~ — ✅ **DONE** — removed the duplicate nested action loop that `run()` ran inline after `process_alive_ips()`; the single `process_alive_ips()` call now handles it.
- **P5** — `display.py` re-reads 3 CSVs via pandas on every refresh; cache counts, recompute on scan events.
- ~~**L3**~~ — ✅ **DONE** — vuln-scan flags now config-driven: timing was already `nmap_scan_aggressivity`; added `vuln_scan_sv` and `vuln_scan_vulners` bools (both default True) so `-sV` and the internet-dependent `vulners.nse` are optional. Args built conditionally in `nmap_vuln_scanner.py`; both validated as bools.

## Ideas from Pwnagotchi (adjacent project — full analysis in PRD §11)

Done: **PG-1** (`epd_type: "auto"`, v2.3.0-alpha); **PG-2/PG-3/PG-4** (v2.4.0-alpha — atomic
netkb writes + `TimeoutStopSec`; opt-in `battery.py` PiSugar monitor + low-charge shutdown;
`/run` heartbeat + systemd watchdog restart). Deferred:

- **PG-5 — plugin system** (lifecycle + UI + web hooks): widen the P3-1 module contract from attack-modules-only to features generally (folded into P3-1 scope, not separate work).
- **PG-6 — GPS tagging of findings**: stretch (Bjorn is LAN-stationary); cheap only if a GPS is attached.

## Reference forks
- `HackCocaine/BjornCocaine` — screen-agnostic WebUI-first, LOGS button, multi-Pi.
- `LOCOSP/BjornWpaSecHarvester` — wpa-sec/Pwnagotchi import.
- `infinition/Bjorn-cortex` — swarm-AI training hub (heavyweight).
- `PierreGode/Ragnar` — the predecessor project.

## Future changes ideas.

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

  - **Bettercap integration (Pwnagotchi-style), opt-in and off by default** — run bettercap (GPL-3.0, single Go binary, same "external process via subprocess" pattern already used for `nmap`/`nmcli`, so no new licensing exposure) as its own managed process via a new systemd unit alongside the existing `bjorn.service`, driven by a new `bettercap_client.py` that follows Pwnagotchi's own `pwnagotchi/bettercap.py` template — a thin REST client against bettercap's `api.rest` module (HTTP Basic Auth; note it defaults to weak `user`/`pass` credentials and needs the same "don't ship this open" treatment as Bjorn's own endpoints) polling or websocket-subscribing `/api/events` and feeding discoveries into the existing `netkb.csv`/stats pipeline as a new data source rather than a separate silo. Ships with only the managed-mode capabilities active — ARP spoofing, MITM, traffic sniffing on whatever network Bjorn is already joined to via `nmcli` — since those need no monitor mode or packet injection and are safe on the current hardware as-is; genuinely new capability over today's port-scan-and-bruteforce model. The 802.11 monitor-mode/deauth/WPA-handshake-capture piece (the actual Pwnagotchi headline feature) stays disabled until the user opts in from the web config, both because it's the flakier hardware path and because monitor mode and managed/connected mode are mutually exclusive on the same radio — running it on `wlan0` would knock Bjorn off its own network (web UI, Telegram reporting, its own scanning) the moment it activated, so enabling it requires a second wireless interface, never `wlan0`. New config keys `bettercap_monitor_enabled` (default `false`) and `bettercap_monitor_iface` (default unset); the config page lists present wireless interfaces as a dropdown (via `iw dev`/`netifaces`, already a dependency) instead of free text, plus a "test monitor mode support" button that runs `iw phy <phy> info` against the selected interface and checks for `monitor` in its supported modes before the user commits to it, and `config_validation.py` fail-fasts at startup — enabled but the configured interface missing or lacking monitor support logs clearly and falls back to disabled rather than crashing or silently no-op'ing. Worth noting for whoever picks a dongle: the onboard chip needs the nexmon firmware patch to enter monitor mode at all, and the Zero 2 W specifically has a currently-open, unresolved nexmon crash-on-injection bug (~50-200 packets before it dies) — the older Zero W's onboard chip is reportedly more reliable for this despite being the weaker board — which is exactly the kind of unreliability this whole opt-in/second-interface design is meant to keep away from Bjorn's own connectivity.
