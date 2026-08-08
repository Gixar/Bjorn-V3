# Backlog — ideas from community forks & upstream issues

Sourced from the MIT-licensed Bjorn ecosystem (reuse is clean with attribution in
`CHANGELOG.md`). These are **not yet built** — most need the Pi, a running WebUI, a live
network, or a vendor driver to build and verify properly, so they're tracked here rather than
shipped blind. Each entry names the concrete change so it's ready to pick up.

Already fixed this cycle (see `CHANGELOG.md`): #16 port hopping, #147 installer apt abort,
#152 EPD option-count prompt. Already covered by the v2 baseline: run-without-display (#11 →
`epd_type: "mock"`), dependency modernization (P1-1/P1-2).

## Re-review 2026-08-03 — everything still open, ranked by priority ÷ time

Full pass over this file against the code on `main` (2.5.0-alpha). Two entries were **stale** and
have been corrected in place: credential reuse (#4 below) shipped in `7f854cf`, and the
HTTPFingerprint "misses 443-only hosts" note was disproven by Wave 2 (both :80 and :443 captured).

**Tier 1 — shipped in this pass (Wave 3, all no-hardware):**

| # | Item | Time |
|---|---|---|
| 1 | Dead `web_increment ` config key (trailing space) — nothing ever read it → deleted | ~0 |
| 2 | `match_server` tech-gating for web templates — cuts wasted requests on a Pi Zero | S |
| 3 | BLE tracker detection from manufacturer data / service UUIDs (was name-only) | S |
| 4 | SMTP fallback delivery channel — last open piece of the reporting item | S |

**Tier 2 — next, medium:**

| # | Item | Time | Why this order |
|---|---|---|---|
| 5 | ~~netkb `device_type` column~~ | — | **Dropped as a prerequisite (Wave 4).** BLE, and now Wi-Fi, both landed cleanly in their own CSVs. Two precedents say the separate-file shape is right; unifying into netkb stays YAGNI until something actually needs one query across IP + wireless entries. |
| 6 | Responder LLMNR/NBT-NS/mDNS poisoning | M | Biggest new offensive capability that needs no new radio. Bulk of the work is process lifecycle + parsing (detail below). |
| 7 | PCAP capture + offline exfil | M | Now has a delivery pipeline to land in (Telegram/SMTP both exist) **and** a monitor-mode radio. |
| 8 | Defensive "canary" mode | M | Reuses the web/report stack; lowest urgency of the four. |

## Re-review 2026-08-04 — a monitor-mode dongle changes the Tier 3/4 gating

A USB Wi-Fi dongle supporting **all modes** is now on hand. That retires the "needs a second radio"
blocker which was the dominant cost on wardriving (#7) and the Bettercap monitor phase — and it
overturns this file's own advice on both:

- **"Don't build a separate monitor stack — extend bettercap's `wifi.recon`"** assumed bettercap
  already existed. It doesn't; it's still an unbuilt **L**. So the real comparison was *airodump
  (subprocess + CSV parse)* vs *build bettercap first, then parse anyway*. airodump-ng won and
  shipped as Wave 4; Bettercap stays scoped in `BETTERCAP_PLAN.md` for the interactive/MITM
  capabilities airodump can't do.
- **Wardriving (#7) is done** — `wifi_aps.csv` + `wifi_clients.csv` *is* the wardriving log. It was
  never an L, and never needed Bettercap Phase 4. **GPS tagging and a map view are dropped, not
  deferred** — no GPS module, and Bjorn is carried rather than driven (the same reasoning that
  killed PG-6). Nothing remains on this item.

## Wave 4 — implemented 2026-08-04 (needs the dongle to verify)

1. **Standalone-action scheduling fixed first** — adding a 5th standalone action surfaced two
   compounding orchestrator bugs that would have made `WiFiScan` never run: the idle loop `break`ed
   on the first success (and a *disabled* action returns success), and a recorded success latched
   the action off permanently because `retry_success_actions` defaults to False. Every standalone
   action ran **once per netkb lifetime**. Now `run_standalone_actions()` gives each a turn per idle
   window and the success gate no longer applies to them (they self-throttle); the failed-retry
   backoff is kept. Very likely the real cause of the Wave 2 "BLE never got a turn" note. Also
   revives `WpaSecImport` / `SNMPEnum` / `TelegramReport`. Covered by `test_standalone_actions.py`.
2. **`WiFiScan` action** — timed `airodump-ng` capture on the second radio → `wifi_aps.csv` +
   `wifi_clients.csv`, merged by BSSID / station MAC with `FirstSeen` preserved. The CSV parser
   handles airodump's two-tables-in-one-file format and its truncated trailing row (it flushes every
   second and we stop it by timeout).
3. **`monitor_mode.py` guard** — refuses any interface holding the **default route**, keyed on the
   routing table rather than the name `wlan0` (names aren't stable across dongles/reboots). Avoids
   `airmon-ng` because its standard companion `check kill` would kill Bjorn's own uplink. One
   acquisition point, so the mutex has an obvious home when a second consumer arrives.
4. **`/wifi` page + Telegram dataset** — config (with the uplink shown but disabled in the dropdown),
   AP and client tables, a "test monitor mode" button; both CSVs added to `compile_targets`.
   Installer provisions `aircrack-ng` + `iw`.

**On-Pi verification still needed:** that the dongle enumerates and enters monitor mode, that
airodump actually captures, and — most importantly — that the uplink guard refuses the onboard radio
*without* dropping connectivity. Test the guard before enabling the scan.
**→ First attempt 2026-08-05 blocked on a missing driver — see below.**

## On-Pi diagnostic — 2026-08-05 23:44 (`bjorn_diag.sh`, running 2.5.0-alpha)

A full system pull. **The device was several commits behind** (`action_planner missing — stock
load-order orchestrator`), so some of this was already fixed in the repo; what follows is what the
scan surfaced that was *not*.

**Fixed in response (see CHANGELOG):**
1. **The run report was lying.** `WiFiScan: success=4` for an action that had never completed a
   capture — every disabled/throttled path returned `'success'`. New `'skipped'` outcome: no netkb
   mark, no run-report entry, doesn't count as work. This is the one that matters: the diagnostic
   was *reassuring* about a dead feature, which is worse than no diagnostic.
2. **A failed acquire burned the full 15-minute Wi-Fi interval** (`_last_scan` set before the
   attempt), so the `wlan1 is not a wireless interface` error at 23:27:49 locked out retries until
   23:42:49. The clock now starts only on a real capture.
3. **`lsof | wc -l` every 10s** in the systemd fd watchdog — expensive on a Pi Zero (service CPU
   was 3m39s over 27min) and it answered the wrong question. Now `/proc/$MAINPID/fd`.
4. **No RTC → `boot 1970-01-09`, uptime 18min vs. service 27min.** A status written pre-NTP is
   stamped ahead of everything after it, which `retry_wait_remaining` honoured literally. A future
   timestamp is now treated as runnable now.
5. **`rustscan_batch_size: 0` is now memory-aware auto** (1500 on a Pi Zero). Precautionary: the
   thin port results that prompted it turned out to be phones/IoT that legitimately answer nothing.

**Not a Bjorn bug:**
- `wlan1 is not a wireless interface` — correct behaviour. The dongle had been moved to a different
  USB port; interface names follow probe order, so the saved `wifi_scan_iface` pointed at nothing.
  `/wifi` now says so instead of rendering a blank dropdown. **Note for the Pi Zero 2 W: only the
  inner micro-USB carries data — the outer one is power-only.**
- `pysmb NOT IMPORTABLE` — a bug in `bjorn_diag.sh`, not in Bjorn: pysmb's import name is `smb`.
  It is in `requirements.txt` and `smb_connector.py.log` exists, so it imported fine.

**Confirmed healthy:** service + heartbeat fresh, 8.7G/28G disk, 39°C, `throttled=0x0`, SPI and I2C
OK, all six external tools present (nmap 7.93, rustscan 2.4.1, bluetoothctl 5.66, snmpget 5.9.3),
web server listening, and the Wave 4 standalone fix visibly working — every standalone action takes
a turn each idle window in the orchestrator log.

## Wave 4 on-Pi verification — 2026-08-05: second radio now present, Bjorn side still untested

Pi Zero 2 W, dongle = TP-Link Archer T2U Nano `2357:011e`, Realtek **RTL8811AU**.

**✅ Driver resolved.** RTL8811AU has no in-tree driver on this image (a mainline gap, not a
misconfiguration), so USB enumerated the adapter while `iw dev` showed only the onboard `phy#0` and
`dmesg` had no Realtek line at all. Fixed with the out-of-tree DKMS driver
`morrownr/8821au-20210708`, which supports monitor mode and injection. `iw dev` now reports
**`phy#1` / `wlan1`** (`24:2f:d0:d9:b3:71`) alongside the onboard radio.

> **Trap worth remembering for anyone repeating this:** installing `linux-headers-rpi-v7` also
> *upgrades the kernel* (here 6.12.93 → 6.12.96) and rewrites `kernel7.img`. `install-driver.sh`
> then builds against the **running** 6.12.93, DKMS's autoinstall hook for 6.12.96 having already
> fired before the module was registered — so the reboot lands on a kernel with no module and
> `wlan1` silently doesn't appear. `sudo dkms autoinstall -k $(uname -r)` after the reboot fixes it.
> It cannot recur: the module is registered with DKMS now, so later kernel upgrades rebuild it.
> Also note `raspberrypi-kernel-headers` is the wrong (legacy) package on this image — it pulls a
> 6.1.21 header tree, 193 MB, useless here.

**✅ Guard verified on-Pi, 2026-08-05** — the Wave 4 design decision that mattered most, confirmed
against a real second radio:
- `POST /wifi_monitor_test {"iface":"wlan0"}` → **refused**, with the default-route message. The
  uplink stayed up throughout (the same request path the scan uses, so this exercises
  `check_usable()` exactly as `acquire()` would).
- `POST /wifi_monitor_test {"iface":"wlan1"}` → accepted, *"supports monitor mode and is safe to
  use"*. That answer comes from `iw phy phy1 info`, so it also confirms the out-of-tree RTL8811AU
  driver really does advertise monitor mode rather than merely loading.
- `GET /wifi_ifaces` → `[{"wlan1", uplink:false}, {"wlan0", uplink:true}]`, so the dropdown greys
  out the right radio.

~~**Still to verify:** `airodump-ng` actually captures into `wifi_aps.csv` / `wifi_clients.csv`, and
`release()` returns `wlan1` to managed mode afterwards without disturbing `wlan0`.~~
✅ **Both confirmed 2026-08-07 — Wave 4 is fully verified.** See the sweep below.

- **`iw` is present** (`/usr/sbin/iw`), so the guard's binary check passes and
  `check_usable()` reaches its uplink test rather than short-circuiting on a missing binary. Worth
  noting because "`iw` not found" is *not* a passing guard result.
- **Lesson on ordering:** the guard's checks are read-only (`ip route show default`, `iw dev`), so
  the refusal test costs nothing and is best run *while the second radio is still absent* — a guard
  bug found then cannot take the uplink with it. Here it was run after the driver landed, which
  worked out, but the free window had already closed.
- **Unrelated confirmations from the same pull:** `usb0` still holds `172.20.2.1/24` with
  `NO-CARRIER` (#68 fix holding across reboots — still needs a plugged-in host for the lease test),
  and `wlan0` is on `192.168.1.35/24`, SSID `Kiwifi`, channel 2.

**Tier 3 — blocked on hardware, a target, or a live WebUI** (do opportunistically when the Pi is out):
~~RTL8811AU driver~~ ✅ 2026-08-05 · ~~`WiFiScan` capture + release~~ ✅ 2026-08-07 ·
~~`rustscan_batch_size` tuning~~ ✅ 2026-08-07 (auto passed; re-check against a port-rich host) ·
~~#176/#155/#122 re-tests~~ ✅ 2026-08-07 (#176's GUI *save* path still needs one manual comma edit) ·
~~BLE on-Pi confirmation~~ ✅ 2026-08-07 · **#113 V4 panel — not testable on this device, it runs
`epd2in13_V3`** · CVE + credential-reuse end-to-end (need a vulnerable/crackable host) · HTTP
fingerprint / web templates / SNMP (need a host with those services) · wpa-sec inject (needs an API
key) · Telegram/SMTP delivery (neither channel configured) · usb0 plugged-host test ·
`Thread-1` exception in `epd_test.py` (only if it recurs).

**Tier 4 — large.** **Bettercap (`BETTERCAP_PLAN.md`) → Evil Twin (#8) → ESP32 fleet is now the
declared next priority** (decided 2026-08-07), once the pocket-carry proactivity work is on the Pi;
each depends on the one before it. Still deferred behind them: Bluetooth PAN · BadUSB (a reversal of
a past decision, needs a call before code) · tri-color panel (YAGNI, no panel) · Cortex export
(YAGNI, no swarm).
*(Wardriving (#7) left this tier in Wave 4 — shipped as `WiFiScan`, and it never needed Bettercap.)*

**Dropped, do not revisit:** GPS tagging and the wardriving map view (PG-6) · `device_type` netkb
column (two separate-file precedents make it unnecessary) · Cortex `.csv.gz` export · PG-5 plugin
system (folded into the P3-1 module contract) · **web UI authentication** (decided 2026-08-05 —
single-user device on an operator-controlled network; see the security-review section above).

## Tier-0 verification sweep — 2026-08-07 (12 PASS, 0 FAIL)

Every "needs the Pi" item run in one pass via `scripts/bjorn_verify.sh` (it drives the existing web
API rather than re-implementing any action, so it verifies the real code path). Unlike
`bjorn_diag.sh` it *acts* — real capture, real benchmark.

> **Now tracked in the repo** (2026-08-08) and extended with **section 8**, covering everything
> merged since this sweep: the collect-by-default flips (BLE / Wi-Fi / RustScan, and that the
> engine actually *selected* is rustscan rather than the toggle merely being on), the Stage A
> radio-ownership rule (two overlapping captures must produce a clean skip and **no new ERROR**),
> Bettercap plumbing (panel reachable, unit present but **not** enabled, generated password in sync
> between the unit and the config), and the never-yet-run Unreleased wave (planner, idle-notice
> volume, offline mode, per-page file groups, help page, comment themes). It was untracked before,
> which is how it drifted from the code it inspects.

**✅ Closed — Wave 4 is done, end to end:**
- **`airodump-ng` captures.** 4 APs / 7 clients into `wifi_aps.csv` / `wifi_clients.csv` from a 30s
  capture on `wlan1`. The two-tables-in-one-file parser works on real airodump output.
- **`release()` restores the radio.** `wlan1` back to `type managed`, NetworkManager managing it
  again (`nmcli state=disconnected`), and the uplink untouched: default route still `wlan0`, web
  still 200 throughout. The guard also re-refused `wlan0` on the same run.
- **`rustscan_batch_size` at auto (→1500 on this board) drops nothing.** 7 hosts / 41 ports: nmap
  54.25s, rustscan 2.01s, **26.94× faster, 3 open ports found by both**. *Caveat kept deliberately:*
  3 open ports is a thin sample, so this says "auto is not obviously dropping ports", not "auto is
  proven at scale". Re-run the benchmark against a host with many open ports before treating the
  batch value as settled. **→ RustScan was made the default engine on 2026-08-07 on the strength of
  this run; the thin-sample caveat above is the one thing still open on it.**
- **#155 web server** reachable (200 on :8000). **#122 framebuffer** renders (`/screen.png`, 2.1 KB).
  **#176 portlist** round-trips from the API as a JSON array — only the GUI *save* path is untested.
- **BLE recon confirmed on hardware** — `ble_devices.csv` written and fresh.
- **#68 usb0** still holds `172.20.2.1/24` with `NO-CARRIER` across reboots.

**Newly learned, worth recording:**
- **This Pi runs `epd2in13_V3`, not the `epd2in13_V4` default — so #113 cannot be diagnosed on this
  device at all.** The most-reported display bug needs a V4 panel that isn't here; it is not a
  "check it next time the Pi is out" item, it is blocked on buying hardware.
- **The deployed tree is not a git checkout**, as designed — `build_info` is the only commit stamp,
  which is exactly why `e2a22c7` added it. Any script asking "what commit is running" must read it.
- **Two bugs in the verification script itself, both worth knowing because they produce
  *confident wrong answers*, not errors:** (1) deriving the repo path from the script's own location
  breaks the moment the script is `scp`'d to `~` — every CSV read a nonexistent path and reported
  "feature missing"; now resolved from the systemd unit's `WorkingDirectory`. (2) Python's
  `csv.writer` emits `\r\n`, so the benchmark's last CSV field carried a CR and bash's `-eq` failed
  on it — a passing comparison was reported as "no comparable row". Anything parsing Bjorn's CSVs
  in shell needs `tr -d '\r'`.

**Still open (all "needs a target or a config", none a defect):** HTTP fingerprint / web templates /
SNMP / credential reuse — no rows, and this LAN offers 3 open ports total across 7 hosts, so there is
nothing to fingerprint. CVE enrichment has 2 vuln files but no confirmed signature match yet.
Telegram/SMTP and wpa-sec are unconfigured. usb0 lease still needs a plugged-in host.

## Security review of `b624337` — 2026-08-05 (2 findings, neither fixed yet)

Automated review of the pushed commit. Both are recorded here rather than patched on the spot;
the first is a real defect in new code and should be Tier 1.

1. ~~**[Tier 1, S] SMTP fallback can deliver cracked credentials — and the mailbox password — over
   an unencrypted connection.**~~ ✅ **FIXED 2026-08-05** — the send is now refused rather than
   downgraded, and `SMTP_SSL` gets an explicit verifying context (its stdlib default skipped
   certificate verification). A plain LAN relay is no longer usable; that case would need an
   explicit opt-in key. Original finding below.
   `telegram_client.py::send_email` treats `SMTPNotSupportedError`
   from `starttls()` as benign and continues on the plaintext socket (the comment reasons about a
   LAN relay), then still calls `smtp.login(user, password)` and sends the payload. Two exposures
   in one path: the report itself, which carries every cracked credential when
   `telegram_include_creds` is on, and the user's own SMTP password. Telegram is HTTPS-only, so the
   fallback is strictly weaker than the channel it stands in for — and it is reached exactly when
   the network is hostile enough to have blocked Telegram. *Fix:* refuse to send when the
   connection is not encrypted, rather than silently downgrading; if the LAN-relay case is worth
   keeping, it needs its own explicit opt-in key, not a silent `pass`.
2. ~~**[Tier 3, M–L] The unauthenticated web UI serves secrets via `/load_config`.**~~
   ❌ **WON'T FIX — decided 2026-08-05.** The finding is accurate: the config endpoint returns the
   whole JSON, `telegram_bot_token` / `smtp_password` / `wpasec_api_key` included, to anyone who can
   reach port 8000. It is also **pre-existing and systemic rather than new** — the same server
   offers Reboot/Shutdown, manual attacks, and pages listing cracked credentials and stolen loot
   outright, so masking one endpoint would fix nothing while implying the rest were safe. Adding
   real auth means auth + session + every page, and the project doesn't want it: Bjorn is a
   single-user device on a network its operator controls. **Do not revisit** unless that
   deployment assumption changes. *(The Wave 4 `load_config` default-merge did not widen this:
   unset keys are empty strings, and a key that has ever been saved was already in the file.)*

## Wave 3 — implemented 2026-08-03 (no hardware required)

1. **Dead `web_increment ` key removed** — the long-known trailing-space key was never read
   anywhere in the codebase, so this was a dead default, not a rename: dropped from
   `shared.py::get_default_config` and `config/shared_config.json`. Existing installs keep the
   stale key in their saved JSON; it stays inert.
2. **`match_server` template gating** — `config/web_templates.json` templates take an optional
   `match_server` list; `WebTemplateScan` reads the parent action's `http_fingerprints.csv` for the
   host's `Server` header and skips templates whose tech doesn't match (case-insensitive). Fails
   **open**: no `match_server`, or no known Server header → the template still fires. `apache-status`
   is gated to `["apache"]` as the first user. Closes the ponytail note on that file.
3. **BLE tracker detection from the advertisement** — two-stage now: the name heuristic first, then
   (only for devices the name didn't flag) `bluetoothctl info <mac>`, matched against finder-network
   service UUIDs (Apple Find My `fd44`, Samsung SmartTag `fd5a`, Tile `feed`/`feec`) and Apple
   manufacturer data `0x004c` whose payload type is `0x12` (offline finding). Google Fast Pair
   (`fe2c`) is deliberately **not** a signature — headphones advertise it too. New `TrackerType`
   column in `ble_devices.csv` + the `/ble` table shows how each was detected. Closes the BLE
   follow-up.
4. **SMTP fallback delivery channel** — `telegram_client.py` gained `send_email()` (stdlib
   `smtplib`/`EmailMessage`; port 465 = implicit SSL, else STARTTLS when offered) and a `_deliver()`
   that tries Telegram then falls back to SMTP, so a network that blocks Telegram still delivers.
   Config: `smtp_enabled/host/port/user/password/to` (comma-separated recipients), validated in
   `config_validation.py`, editable on the `/telegram` page. `TelegramReport` now runs when *either*
   channel is enabled, and the "Send test message" button tests whichever is configured. The delta /
   rate-floor logic is unchanged and shared by both channels. Closes the "email fallback" sub-item.
   *(The module keeps its `telegram_client.py` filename — renaming it would churn three importers
   for no behavior change.)*

Needs the Pi to confirm 2–4 end-to-end; the pure logic in each is covered by tests
(`test_web_template_scan.py`, `test_ble_scan.py`, `test_telegram.py`).

## Wave 0 verification — on-Pi results (2026-08-02, v2.5.0-alpha, Pi Zero armv7l)

Clean reinstall of 2.5.0-alpha, checked against a real LAN (source: install/verify log pull).

**✅ Confirmed working on hardware:**
- **RustScan on 32-bit armv7 + full-port mode** — `ps` shows `rustscan -a … -r 1-65535 -g --no-config`
  running (binary provisioned on armv7l); both full-port (`-r 1-65535`) and curated-list (41 ports)
  paths observed.
- **Engine log line** — `scanning.py.log`: `Port discovery engine: rustscan (8 hosts, 41 ports)`.
- **P1 idle spam** — `journalctl -u bjorn | grep -ci idle` = **0**; one "idling 180s" per window.
- **Self-scan guard** — `Excluding own IPs from scan: ['192.168.1.35']` each scan.
- **Coins/stats overhaul** — `data/stats.json` = `{hwm:{hosts:10,attacks:17,…}, coins:95, level:1}`;
  monotonic model + math correct (10×1 + 17×5 = 95; `floor(√(95/25))` = 1), persisted to disk.
- **wpa-sec import** — no-op path confirmed: `wpasec_api_key not set; skipping` (correct).
- **Manual NmapVulnScanner attack** — runs, no 500 (the `bc535da` special-case holds).
- Clean baseline: service active, SPI OK, no journal/app/install errors.

**⚠️ New issues found this pass (tracked in the bugs table below):**
- Manual attack with **NetworkScanner** → 500 `Action class NetworkScanner not found`.
- **usb0 has no IP** even when UP (`NO-CARRIER`, state `DOWN`, no `inet`) — #68 still unproven.
- **`epd_test.py --all` all-fail with `GPIO busy`** because `bjorn.service` holds the pins.

**⏳ Unconfirmed (need a suitable target):**
- **CVE enrichment** — the only open host is a ZTE router whose services nmap can't CPE-identify
  ("2 services unrecognized"), so the CPE-only matcher had nothing to match (correct behavior, but
  unproven). → consider a `-sV` service-line fallback for CPE-less consumer gear.
- **Credential reuse** — no crackable SSH/FTP/… host on the LAN, so no crack occurred to replay.
- **wpa-sec inject** — needs an API key + previously-cracked networks.
- **#68 usb0** — retest with a host physically plugged into the USB port.

## Wave 2 verification — on-Pi results (2026-08-03, fresh 2.5.0-alpha install)

Full reinstall of the latest code, checked against the LAN.

**✅ Confirmed on hardware:**
- **Installer provisions `snmp`** (5 pkgs) and all 6 new actions register
  (HTTPFingerprint, WebTemplateScan, SNMPEnum, WpaSecImport, BLEScan, TelegramReport).
- **HTTP fingerprinting** — `http_fingerprints.csv` captured **both :80 and :443** of the ZTE
  router (Server header, status 200) — HTTPS with a self-signed cert works.
- **nuclei WebTemplateScan** — ran as a child of HTTPFingerprint; no findings on that host (nothing
  exposed) = correct, no false positives.
- **SNMP enum** — ran successfully; `snmpget` present; no SNMP host answered (empty, correct).
- **#68 usb0** — `ip addr show usb0` now shows `inet 172.20.2.1/24` **even with NO-CARRIER**; the
  `ConfigureWithoutCarrier=yes` fix works.
- **epd_test GPIO-busy fix** — with the service stopped (per the new hint) all 5 drivers init'd
  without error.
- Clean baseline: service active, no journal/app/install errors, memory healthy.

**⏳ Unconfirmed (no error, needs conditions):**
- **BLE recon** — enabled + initialized, but didn't get a standalone-action turn in the short
  window; let it run longer, then check `ble_devices.csv` / `/ble`.
- **Telegram** — not configured (no bot token) — needs a token to test send/delta.
- **CVE end-to-end** / **credential reuse** — still need a vulnerable / crackable host.

**⚠️ Noticed:**
- `Exception in thread Thread-1:` printed during `epd_test.py` after the epd2in13 / epd2in13_V3 runs
  (non-fatal — each finished with "ran without error"); full traceback was cut off. Investigate if it
  recurs.
- ~~`'web_increment '` config key still has a trailing space~~ — ✅ **FIXED (Wave 3)** — the key was
  never read anywhere, so it was deleted rather than renamed.

## Bugs still open (need the WebUI/Pi to reproduce + verify)
| Ref | Issue | Likely fix / pointer |
|---|---|---|
| #176 | Can't enter comma-separated ports in GUI Settings | **Appears already resolved** in current code — `web/scripts/config.js` renders `portlist` as a text input and `saveConfig` splits on commas into an array. Re-test in the UI; no code change identified. |
| ~~#190 / #160~~ | ~~Wi-Fi APs not shown / no SSID switch in WebUI~~ | **Appears already resolved** — `config.js::scanWifi` renders `data.networks`, marks `current_ssid`, and click-to-connect POSTs `{ssid, password}`; backend uses `nmcli` (not the old `iwlist`). Only the on-Pi runtime (sudo/nmcli perms on `wlan0`) remains — re-test on the device. |
| ~~#130 / #81~~ | ~~404 / error executing a manual attack~~ | ✅ **FIXED** — real cause was `index.html` fetching `/recent_logs` (nonexistent) right after the attack; changed to `/get_logs`. The dead `/manual.html` route was removed. The manual-attack UI already lives in `index.html`. |
| #155 | Web server not showing | Overlaps #16 (port hopping) — re-test after the SO_REUSEADDR fix; if still failing, check the systemd unit + firewall. |
| #122 | Installed but no Display *or* WebUI (most-commented) | Multi-cause: partly #16 (port), partly EPD init failing on the panel. Re-test after the port fix; if the display is still dead, check `epd_type` + wiring. Pi-only. |
| #113 | Waveshare **V4 unreadable** display | Affects the **default** `epd_type: "epd2in13_V4"` — reported as unreadable/garbled since May 2025. Likely a refresh-mode / LUT or rotation issue in the vendor driver. Needs the actual V4 panel to diagnose. |
| ~~#68~~ | ~~`usb0` IP not assigned~~ | ✅ **FIXED + confirmed on-Pi (2026-08-03).** After a reinstall with `ConfigureWithoutCarrier=yes` + `IgnoreCarrierLoss=yes` in `/etc/systemd/network/10-usb0.network`, `ip addr show usb0` shows `inet 172.20.2.1/24` even with `NO-CARRIER` (nothing plugged in). Remaining: plug into a host to confirm the DHCP lease + `http://172.20.2.1:8000/`. |
| ~~**NEW**~~ | ~~Manual attack with **NetworkScanner** → 500~~ | ✅ **FIXED** — `serve_netkb_data_json` now filters the manual-attack dropdown to actions the handler can run per host (port-based connectors + special-cased `NmapVulnScanner`, via `port not in (0, None)`), so NetworkScanner / IDLE / standalone log actions are no longer offered and can't trigger the "class not found" error. |
| ~~**NEW**~~ | ~~`epd_test.py --all` fails with `GPIO busy` while the service runs~~ | ✅ **FIXED** — `scripts/epd_test.py` now checks `systemctl is-active bjorn.service` up front and prints a "stop bjorn.service first" hint, and repeats it on any `busy` error before the traceback; `TROUBLESHOOTING.md` leads with stopping the service. |

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
- ~~**wpa-sec / Pwnagotchi network import**~~ (from `LOCOSP/BjornWpaSecHarvester`): ✅ **DONE** (Wave 1 #4) — opt-in standalone action `WpaSecImport` fetches cracked Wi-Fi keys from wpa-sec.stanev.org (stdlib urllib) and injects them into NetworkManager as low-priority autoconnect profiles, deduped against `crackedpwd/wifi_wpasec.csv`. No-op unless `wpasec_api_key` set; throttled by `wpasec_interval`. Remote SSID/PSK sanitized at the trust boundary. Needs the Pi + internet to verify end-to-end.
- ~~**Scan all network interfaces**~~ (#133): ✅ **DONE** — `get_network()` → `get_networks()` returns one IPv4Network per interface subnet (all AF_INET addrs, deduped, loopback/link-local skipped). `scan()` loops every subnet and **accumulates** hosts into a single `update_netkb` write with the union of alive MACs — writing per-network would make each subnet mark the others' hosts dead. Dropped the dead (never-printed) `table` builder while there. Needs a multi-interface host to verify end-to-end.
- ~~**SNMP enumeration**~~: ✅ **DONE (Wave 2)** — standalone `SNMPEnum` action iterates alive netkb hosts and probes UDP/161 via `snmpget` (SNMP isn't TCP-discoverable, so it's not port-gated), recording sysDescr/sysName to `snmp_enum.csv`. `snmp_communities` config; installer provisions `snmp`; graceful no-op if `snmpget` missing. Needs the Pi + an SNMP host to confirm.
- ~~**HTTP service fingerprinting**~~ (PRD P3-5): ✅ **DONE (Wave 2)** — `HTTPFingerprint` action (`actions/http_fingerprint.py`) GETs each open web port, records status / `Server` / `X-Powered-By` / `<title>` to `data/output/scan_results/http_fingerprints.csv`. Stdlib `urllib`; `b_port=80`, fingerprints all web ports per host. Feeds the nuclei item below. **Confirmed on-Pi (Wave 2):** both :80 and :443 of the ZTE router were captured, self-signed cert and all — the earlier "misses 443-only hosts" note applies only to a host exposing 443 *without* 80, which hasn't been seen in practice; no https sibling module needed.

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
- ~~**Coins / stats overhaul**~~ — ✅ **DONE** (Wave 1 #3) — `stats_engine.py`: monotonic high-water-mark score persisted to `data/stats.json`, rebalanced weights, RPG level curve, coin-breakdown on the dashboard. Server-side history skipped (the live session chart already trends) — see [`COINS_STATS_PLAN.md`](COINS_STATS_PLAN.md). Original diagnosis kept below. Today `shared.py::update_stats()` recomputes `coinnbr`/`levelnbr`
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

1. ~~**Offline CVE enrichment**~~ *(searchsploit / nuclei-cves)* — ✅ **DONE (Wave 1 #1)**; parses
   `nmap -sV` CPE lines against the bundled `config/cve_signatures.json`, **plus a service-line
   fallback** (added after Wave 0) that reads `product version` from the plain `-sV` line for
   CPE-less consumer gear (e.g. the ZTE router that returned "2 services unrecognized"). Garbage
   products match no signature, so the fallback only adds hits. Still needs a real vulnerable host
   to confirm an end-to-end match on-Pi.
2. **Responder-style LLMNR/NBT-NS/mDNS poisoning** *(Responder / Impacket)* — **M.** Passive
   NetNTLM-hash capture on the joined LAN → loot file for offline cracking. See effort detail below.
3. ~~**nuclei-style templated web checks**~~ *(ProjectDiscovery nuclei)* — ✅ **DONE (Wave 2)** —
   `WebTemplateScan` action, a child of `HTTPFingerprint`, fires bundled JSON templates
   (`config/web_templates.json`) at each web port; hits → `web_template_findings.csv`. Matchers:
   `status` + `body_contains`, plus the optional `match_server` tech gate added in Wave 3. JSON not
   YAML (stdlib, no pyyaml dep). Needs the Pi to confirm end-to-end.
4. ~~**Credential reuse / auto-lateral chaining**~~ *(CrackMapExec pattern)* — ✅ **DONE (Wave 1 #2,
   `7f854cf`)** — `credential_pool.py`: every connector records a crack into a shared
   `crackedpwd/known_creds.csv` pool and tries that pool **first** on the next host, so a cred cracked
   on one host/protocol is auto-replayed across all the others. Read fresh per attack, so reuse works
   within the same cycle. `credential_reuse` config key (default on). *(This entry was stale — it was
   still listed as open through Wave 2.)* Still needs a crackable host on the LAN to confirm a real
   replay end-to-end.
5. **PCAP capture + offline exfil** *(tcpdump / bettercap sniff)* — **M.** Rotating capture on the
   joined network, delivered via the planned Telegram/report pipeline. Extends the Bettercap
   managed-mode **sniff** capability already scoped in [`BETTERCAP_PLAN.md`](BETTERCAP_PLAN.md).
6. ~~**BLE recon + tracker detection**~~ *(Flipper/Marauder BLE, OpenHaystack/AirGuard)* —
   ✅ **DONE (Wave 2)** — opt-in `BLEScan` standalone action does a timed `bluetoothctl` discovery →
   `ble_devices.csv` (MAC, name, tracker flag, first/last seen), with a `/ble` web page (config +
   results table). **Decision:** kept in its own file, **not netkb** — non-IP wireless entries don't
   fit the netkb IP+Ports schema. *(Wave 4 confirmed this call — `WiFiScan` landed the same way, and
   the unified `device_type` column was dropped as a prerequisite rather than built.)*
   **Follow-up closed (Wave 3):** tracker
   detection now also reads BLE manufacturer data / service UUIDs via `bluetoothctl info <mac>`, not
   just the name — see Wave 3 #3. Needs the Pi + nearby BLE devices to confirm.
7. ~~**Passive Wi-Fi survey / wardriving**~~ *(Kismet / Pwnagotchi)* — ✅ **DONE (Wave 4)** —
   `WiFiScan` logs APs (BSSID/ESSID/channel/privacy/signal) and their clients to
   `wifi_aps.csv`/`wifi_clients.csv` via airodump-ng on the dongle, with a `/wifi` panel. **Not**
   built on Bettercap Phase 4 as recommended below — that advice assumed bettercap existed; it
   doesn't, and airodump's CSV output made this a parse job instead of a daemon-integration job.
   GPS tagging and a map view are **dropped** (see PG-6), so nothing remains here. Original analysis
   kept below only for the monitor-mode caveats, which still apply.
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

**#7 Passive Wi-Fi survey / wardriving — ✅ shipped in Wave 4; estimate and recommendation were both
wrong.** Kept as a short post-mortem, since the file argued the opposite of what was built:
- *The estimate* ("M on top of Bettercap Phase 4, else L") assumed the only route to AP data was
  bettercap's `wifi.recon`. airodump-ng writes a plain CSV, so it was an **S–M parse job** — the
  "don't build a separate monitor stack" advice was reasoning from a dependency that didn't exist
  yet. Lesson: check whether the thing you're told to extend has actually been built.
- *Still true — the hardware caveat:* monitor mode needs a second radio, **never the uplink**
  (enforced by `monitor_mode.py`). The onboard Zero 2 W chip needs the nexmon patch and has an open
  crash-on-injection bug, so the USB dongle is the only sane path. This is why the radio, not the
  code, was always the real cost.

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

  - ✅ **DONE (Wave 2 — Telegram v1; email still deferred)** — `TelegramReport` standalone action +
  `telegram_client.py` + a `/telegram` web page. Auto-sends the **raw target dataset** (netkb +
  fingerprints + web findings + SNMP + vulns + optional creds, as a JSON document) to a bot **only
  when the data changed** (sha256 delta) past a `telegram_min_interval` floor. Web page configures
  the bot and has Send-test / Send-now buttons. Config: `telegram_enabled/bot_token/chat_id/
  min_interval/include_creds`. **Email/SMTP fallback added in Wave 3** (`smtp_enabled/host/port/user/
  password/to`, stdlib `smtplib`, tried when Telegram is unset or fails) — this item is now complete
  pending on-Pi confirmation. Original note kept below.
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
