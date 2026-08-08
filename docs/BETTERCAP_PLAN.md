# Bettercap integration + Handshake Hunter — implementation plan

Status: **planned, not started.** Scoped from the `docs/BACKLOG.md` Bettercap entry, extended
2026-08-07 to absorb the Pwnagotchi-style hunting PRD. **This file is the single authority** — the
standalone `PWNAGOTCHI_MODE_PRD.md` described a device that doesn't match this codebase (see
Corrections below) and should not be implemented from directly.

Default posture: **entirely off** — nothing runs, and nothing is enabled at install, until the user
turns it on from the web UI.

Grounded in Bjorn's existing patterns: external processes driven via `subprocess` (nmap/nmcli),
systemd units built in `install_bjorn.sh`, the `netkb.csv` + `shared.py` helper pipeline
(`netkb_targets` / `append_csv_rows` / `dedupe_csv`), config keys validated in
`config_validation.py`, FastAPI routes in `webapp.py` / `utils.py`, and the monitor-mode guard and
lock in `monitor_mode.py`.

---

## Corrections applied to the PRD

| PRD said | Reality in this repo | Consequence |
|---|---|---|
| Monitor mode via `airmon-ng`, "already proven" | `monitor_mode.py:12` **deliberately refuses `airmon-ng`** — its companion `airmon-ng check kill` kills NetworkManager/wpa_supplicant, i.e. Bjorn's uplink. The verified path (on-Pi 2026-08-07) is `iw dev <if> set type monitor` via `acquire()`/`release()` | Use `monitor_mode.acquire()`. Never shell `airmon-ng` |
| `pwnagotchi_mon_iface: "wlan1mon"` | `iw` does **not** rename the interface. There is no `*mon` device | Key deleted. One iface name throughout |
| "Extend the existing Bettercap systemd unit" | **Bettercap does not exist in this repo at all.** This file was an unbuilt plan | Stage B *builds* it. Same trap `BACKLOG.md` post-mortem'd on wardriving: check that the thing you're extending was built |
| New web endpoint + zip download for loot | `/module_files/{group}` + `/module_file/{group}/{key}` already exist, taking a **whitelist key, never a path** | Register a `handshakes` group. No new endpoint, no path parameter |
| "Every handshake → +N coins" | `stats_engine` is a **high-water mark over counts**, not an event ledger (`update(path, counts)`) | Add a `handshakes` category + weight; feed it a unique count |
| Faces / moods subsystem on e-Paper | `comment.py` + `comment_info_ratio` already rotate status lines and themed comments per action | Add a theme + status line. No new display subsystem |
| `pwnagotchi_min_rssi: -80` validated normally | `_NONNEG_INT_KEYS` rejects negatives | Needs its own branch, like `wifi_scan_channel` |
| `pwnagotchi_handshake_dir` as a config key | Every other output path is derived in `SharedData` | Derive it. One less path to validate |
| Auto-start "when no management Wi-Fi" | `offline_mode.py` **already owns that state** via `run_offline_cycle()` | The hunter is a *consumer* of that decision, never a second decider |
| Loot dir contains a `README.md` | Nothing reads it | Dropped |

### Two gaps the PRD did not cover

1. **The radio already has two consumers and a mutex.** `monitor_mode._radio_lock` is non-blocking,
   added when the web "Scan now" button became the second consumer alongside scheduled `WiFiScan`.
   A hunter holds the radio for *hours*. And as of `c5b2b44` **`wifi_scan_enabled` is on by
   default**, so without Stage A every cycle logs a Wi-Fi scan error while hunting.
2. **Hunting can strand Bjorn offline forever.** `offline_mode.py` warns that nmcli cannot associate
   an interface still in monitor mode and *fails quietly*. If the hunter holds the only free radio,
   `wifi_autojoin` silently stops working, Bjorn never rejoins, and the loot it just captured is
   never delivered. Hence the radio contract below, and the hard single-radio refusal.

---

## Naming

**Decided 2026-08-07: `bettercap_pwn_*`.** (The PRD used `pwnagotchi_*`.) One daemon, one key
prefix, one web page, one entry in `config.js::PAGE_OWNED_KEYS`. It also stays accurate — the
capability is Bettercap's, and the mode is not a Pwnagotchi.

This is not a cosmetic choice: the prefix is what routes keys away from the generic config form to
their owning page, and `tests/test_web_pages.py::test_every_hidden_key_is_settable_on_its_page`
fails if a prefixed key has no field on that page. Renaming later means touching every key, the
page, the JS and the test at once.

---

## The radio contract (load-bearing — read before Stage C)

One physical radio, now up to three consumers: scheduled `WiFiScan`, the web "Scan now" button, and
the hunter. `monitor_mode.py` is the single acquisition point and stays so.

- **The hunter takes the lock for its whole session**, not per capture. It is the long-lived
  consumer; everything else must degrade gracefully around it, not the reverse.
- **A blocked consumer is `'skipped'`, not `'failed'`.** A held lock is a normal state, not an
  error — the same distinction Wi-Fi default-on already needed for missing hardware.
- **The hunter refuses to start with fewer than two radios.** With one radio it would own the only
  path back online. Checked against `monitor_mode.wireless_ifaces()`, not a config value.
- **Reconnect outranks hunting.** `run_offline_cycle()` order is recon → reconnect; the hunter
  releases the radio before the reconnect attempt and re-acquires after. A hunter that cannot be
  interrupted is a hunter that never delivers.
- **Managed-mode Bettercap and the hunter are mutually exclusive** — one profile active at a time.

---

## Architecture

```
                     ┌──────────────── Bjorn.py ────────────────┐
                     │ orchestrator │ display │ web │ poller    │
                     └───────┬───────────────────────┬──────────┘
   run_offline_cycle() ──────┘                       │
   (owns "are we offline?")                          │ REST, 127.0.0.1
            │                                        ▼
            │  start/stop           bettercap.service (systemd)
            ▼                        managed profile  OR  pwn profile
   bettercap_pwn.py  ──── monitor_mode.acquire(iface, owner="pwn") ────► one radio
            │
            ▼  watches the handshake dir
   data/output/handshakes/  ──►  index.json  ──►  stats_engine counts
                            └─►  /module_files/handshakes  (web + Telegram)
```

Bettercap stays an **external process** managed by systemd — the same relationship Bjorn has with
nmap/nmcli. The poller is a **data source**, not an orchestrator action, so it does not join
`actions.json` / the `b_class` contract. The hunter *is* a controller, started and stopped by
`run_offline_cycle()`.

---

## Implementation steps

Each step is meant to be one sitting, independently mergeable, and green on `pytest tests/` before
the next. **Stage A ships today and needs no Bettercap** — do it first regardless of when the rest
happens, because it fixes a real per-cycle error the moment any long-lived consumer appears.

### Stage A — radio ownership (no new dependency, ~1 session)

| # | Step | Files | Done when |
|---|---|---|---|
| A1 | `acquire(iface, owner="scan")` records the holder; add `holder()` returning the owner or `""`. Lock stays non-blocking. | `monitor_mode.py` | `holder()` reports the owner while held, `""` after `release()` |
| A2 | A blocked acquire is distinguishable from a refused one: return `(False, detail, reason)` where reason ∈ `busy` / `unsafe` / `missing`. | `monitor_mode.py` | Existing callers still work on the 2-tuple or are updated in the same commit |
| A3 | `WiFiScan` returns `'skipped'` on `busy` (no netkb mark, no run-report row, log at INFO naming the holder) and keeps `'failed'` + ERROR on `unsafe`/`missing` with a configured iface. | `actions/wifi_scan.py` | A held lock produces no error line and no failed-retry backoff |
| A4 | Test both paths. | `tests/test_monitor_mode.py`, `tests/test_wifi_scan.py` | Second consumer gets `busy`; uplink still refused; `release()` frees the lock in `finally` |

### Stage B — Bettercap exists (managed mode, ~2–3 sessions)

| # | Step | Files | Done when |
|---|---|---|---|
| B0 | **Spike, no commit.** `apt install bettercap` on the Pi; run with `api.rest on`; curl `/api/session` and `/api/events`. **Pin the exact event JSON for AP / client / handshake events** — it varies by version. Save a real response as a test fixture. | — | A fixture file exists in `tests/fixtures/` |
| B1 | `BettercapClient(base_url, user, password)`: `session()`, `events(since)`, and pure `parse_hosts(events)`. No threads, no SharedData. | `bettercap_client.py`, `tests/test_bettercap_client.py` | Fixture in → expected netkb rows out, with no daemon running |
| B2 | Poller thread started in `Bjorn.py` only when `bettercap_enabled`; **batches** events into the existing once-per-cycle netkb write (mirror the P3 discipline — never write per event); stops on the existing stop-flag. | `Bjorn.py`, `bettercap_client.py` | Disabled → thread never starts; enabled → hosts merge by MAC |
| B3 | Config keys + validation. `config_validation.py` gains **string-key validation** (present + `str`), which it does not have today. | `shared.py`, `config_validation.py`, `tests/test_config_validation.py` | Defaults keep everything off; a missing key fails fast with a clear message |
| B4 | Web panel: `web/bettercap.html` + `web/scripts/bettercap.js`, `bettercap` in `_PAGES`, nav entry, `bettercap_` in `PAGE_OWNED_KEYS`, and `GET /bettercap_status` (reachable / running / version). Password masked with the existing reveal control. | `webapp.py`, `utils.py`, `web/*`, `web/scripts/common.js` | `test_every_hidden_key_is_settable_on_its_page` passes |
| B5 | Installer: optional block (like RustScan) — `apt install bettercap`, write `bettercap.service` with a **generated** password bound to `127.0.0.1`, land it in both unit and config. Do **not** `systemctl enable` unless enabled. Non-fatal if unavailable. Teardown in `uninstall_bjorn.sh`. | `install_bjorn.sh`, `uninstall_bjorn.sh` | `--dry-run` reports presence; a decline leaves no unit behind |

### Stage C — the hunter (monitor mode, ~2–3 sessions)

| # | Step | Files | Done when |
|---|---|---|---|
| C1 | `bettercap_pwn.py` controller skeleton: `can_start(shared_data)` → `(ok, reason)`, `start()`, `stop()`, `status()`. **`can_start` refuses when fewer than two wireless interfaces exist**, when the only free radio is the uplink, or when managed-mode Bettercap is active. Pure guard logic, testable without hardware. | `bettercap_pwn.py`, `tests/test_bettercap_pwn.py` | Single-radio refusal is covered by a test |
| C2 | Radio + daemon lifecycle: `start()` takes `monitor_mode.acquire(iface, owner="pwn")`, launches the pwn profile, and `stop()` releases in a `finally` after the radio is back to managed. Handshake output dir derived in `SharedData` (`data/output/handshakes/raw/YYYY-MM-DD/`). | `bettercap_pwn.py`, `shared.py`, caplet `config/bjorn-pwn.cap` | `stop()` leaves `iw dev` reporting `type managed` and `holder()` empty |
| C3 | Handshake watcher: scan the output dir, dedupe by `(BSSID, kind)`, maintain `index.json` (bssid, essid, kind, path, first_seen). Parsing is pure and fixture-tested; no live capture needed. | `bettercap_pwn.py`, `tests/test_bettercap_pwn.py` | Re-running over the same files adds no duplicate entries |
| C4 | **Offline integration.** `run_offline_cycle()` starts the hunter after wireless recon and **stops it before `reconnect_best()`**, then restarts it if still offline. No new "am I offline" logic anywhere. | `orchestrator.py`, `offline_mode.py` | Auto-join still works with the hunter enabled — the acceptance test that matters most |
| C5 | Epoch loop: recon → pick targets → assoc/deauth → sleep `bettercap_pwn_epoch`. Rule-based selection only (RSSI floor, unseen-BSSID first, per-BSSID cooldown). | `bettercap_pwn.py` | One epoch runs end to end on the Pi and writes at least one PCAP |

### Stage D — visible, downloadable, rewarded (~1–2 sessions)

| # | Step | Files | Done when |
|---|---|---|---|
| D1 | Register a `handshakes` group in `_file_groups()` (index + logs + the day's PCAPs). No new endpoint. | `utils.py` | Files download from the page via key, not path |
| D2 | Coins: add `"handshakes"` to `stats_engine.WEIGHTS` (suggest **20** — above `attacks`, below `creds`) and feed `update_stats()` a unique count from `index.json`. Note: `_merge_hwm` seeds from current counts on first run, so an existing capture set seeds rather than awards progressively. | `stats_engine.py`, `shared.py`, `tests/test_stats_engine.py` | Coins rise on a new handshake and never fall |
| D3 | e-Paper: a `bettercap_pwn` comment theme + a status line in `comment.py::status_lines` (`"3 handshakes on my belt"`). No face subsystem. | `comment.py`, `resources/comments.json` | The theme exists, so it doesn't fall back to IDLE and log a warning |
| D4 | Telegram/SMTP: add `index.json` to `compile_targets`. Delivery is already deferred while offline via `b_needs_internet`, which is correct here — you hunt offline and report when you land. | `actions/telegram_report.py` | Dataset includes handshakes on the first cycle back online |
| D5 | Panel: live status (running / epoch / APs / clients / handshakes), enable toggle, force-epoch button. Backgrounded like the Wi-Fi "Scan now" button — an epoch must not hold an HTTP request open. | `web/bettercap.html`, `web/scripts/bettercap.js`, `utils.py` | Toggling off stops the daemon and frees the radio |

### Stage E — smarter (optional, only after D is real)

| # | Step | Notes |
|---|---|---|
| E1 | Target scoring | Reuse the `action_planner.py` shape — pure functions over dicts, weighted signals, a reason string on the display. Do **not** write a second scorer. |
| E2 | Personality knobs in the UI | Only the ones E1 proves matter. |
| E3 | hashcat conversion | `hcxpcapngtool`, **on demand** from the panel, not a background job — SD wear and Pi Zero CPU. |
| E4 | Learning | Explicitly out of scope until E1's rule-based version is measured. The A2C net was already a PRD non-goal. |

---

## Config keys

Managed mode (Stage B):

| Key | Type | Default | Purpose |
|---|---|---|---|
| `bettercap_enabled` | bool | `false` | master switch — poller + service |
| `bettercap_api_url` | str | `http://127.0.0.1:8081` | REST endpoint (localhost only) |
| `bettercap_user` | str | `bjorn` | api.rest Basic-Auth user |
| `bettercap_pass` | str | *(generated at install)* | api.rest Basic-Auth password |
| `bettercap_arp_spoof` | bool | `false` | ARP spoofing (off = passive recon) |
| `bettercap_sniff` | bool | `false` | passive traffic sniff |

Hunter (Stage C) — all default off/inert:

| Key | Type | Default | Purpose |
|---|---|---|---|
| `bettercap_pwn_enabled` | bool | `false` | master switch for the hunter |
| `bettercap_pwn_iface` | str | `""` | radio to hunt on; blank = pick any non-uplink radio, same rule as `offline_mode.pick_scan_iface()` |
| `bettercap_pwn_when_offline` | bool | `true` | hunt during offline cycles (the only automatic trigger) |
| `bettercap_pwn_epoch` | int | `120` | seconds per epoch |
| `bettercap_pwn_deauth` | bool | `true` | send deauth to speed up handshakes |
| `bettercap_pwn_associate` | bool | `true` | associate for PMKID |
| `bettercap_pwn_min_rssi` | int | `-80` | **negative — needs its own validation branch**, `_NONNEG_INT_KEYS` will reject it |
| `bettercap_pwn_channels` | list | `[]` | empty = hop |
| `bettercap_pwn_cooldown` | int | `900` | seconds before re-targeting the same BSSID |

Handshake directory is **derived in `SharedData`**, not configured.

---

## Security

- Bettercap's `api.rest` ships weak default `user`/`pass`. The installer generates a random password
  and binds to `127.0.0.1` only. Document rotation.
- Deauth is an active attack. The existing authorized-use posture in `README.md` and `/help` covers
  it; the hunter panel should repeat the warning inline, as the manual-attack panel does.
- No new file-serving surface: loot goes through the existing whitelist-key endpoint.

---

## Acceptance criteria

1. All switches off → zero behavior change, no bettercap process, `pytest tests/` green.
2. Managed mode on a Pi already on Wi-Fi → bettercap hosts appear in `netkb.csv` within one cycle.
3. `api.rest` bound to localhost with a generated, non-default password.
4. **With the hunter enabled and Bjorn offline, `wifi_autojoin` still rejoins a saved network.**
   This is the one that catches the stranding bug — test it before trusting an unattended run.
5. With the hunter holding the radio, `WiFiScan` logs no errors and records no failures.
6. A captured handshake appears in `index.json`, raises coins, shows on the panel and the e-Paper,
   and downloads from the page.
7. Single-radio device → the hunter refuses to start, with a reason shown in the UI.
8. Disable + reboot → daemon stops, radio returns to `type managed`, uplink unaffected.

---

## Risks

| Risk | Mitigation |
|---|---|
| Event schema drift | Pinned in B0 against the installed version, with a saved fixture |
| Hunter starves `WiFiScan` | Stage A makes a held lock a clean skip, not an error |
| Hunter strands Bjorn offline | C4 ordering + the two-radio refusal + acceptance criterion 4 |
| Pi Zero load / thermal | Configurable epoch, batched event handling, no per-event writes |
| SD wear | Handshakes written by bettercap directly; `index.json` rewritten only on change (mirror `stats_engine._atomic_write`) |
| nexmon instability | Second radio required; the RTL8811AU + `morrownr/8821au` path is the known-good one on this device (see `BACKLOG.md`) |
| Managed vs pwn conflict | `can_start()` refuses when the other profile is active |

## Effort

Stage A: ~1 session, ships now. Stage B: 2–3. Stage C: 2–3, most risk in C4. Stage D: 1–2.
Stage E: open-ended, do not start it before D is real on hardware.
