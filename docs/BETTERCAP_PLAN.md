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

### Stage A — radio ownership ✅ **DONE 2026-08-07**

| # | Step | Files | Done when |
|---|---|---|---|
| A1 | ✅ `acquire(iface, owner="scan")` records the holder; `holder()` returns the owner or `""`. Lock stays non-blocking. | `monitor_mode.py` | `holder()` reports the owner while held, `""` after `release()` |
| A2 | ✅ A blocked acquire is distinguishable from a refused one: `(ok, detail, reason)` with `reason ∈ BUSY / UNSAFE / FAILED`. | `monitor_mode.py` | The one caller (`wifi_scan.py`) updated in the same commit |
| A3 | ✅ `WiFiScan` returns `'skipped'` on `BUSY` (no netkb mark, no run-report row, INFO naming the holder) and keeps `'failed'` + ERROR otherwise. | `actions/wifi_scan.py` | A held lock produces no error line and no failed-retry backoff |
| A4 | ✅ Tests for both paths. | `tests/test_wifi_scan.py` | Second consumer gets `BUSY`; uplink still refused; a non-owner cannot release |

**Deviations from the plan as written, all deliberate:**
- Reasons are `BUSY` / `UNSAFE` / `FAILED`, not `busy`/`unsafe`/`missing`. `FAILED` (a command
  broke mid-configuration) is the real third case; splitting "missing `iw`" from "not a wireless
  interface" would have added a distinction no caller consumes — both already arrive as an
  `UNSAFE` detail string from `check_usable()`.
- Tests went into `tests/test_wifi_scan.py`, where the monitor-mode guard tests already live,
  rather than a new `tests/test_monitor_mode.py`.
- **One fix the plan missed:** `release()` freed the lock unconditionally, so any consumer could
  hand back a radio another was mid-capture on — and drop its lock doing so, the exact interleaving
  the lock exists to prevent. Harmless while both consumers were the same 30-second capture;
  a latent bug the moment a second owner label exists. `release(iface, owner)` now ignores a
  non-owner. Covered by `test_a_non_owner_cannot_release_the_radio`.

### Stage B — Bettercap exists (managed mode, ~2–3 sessions)

| # | Step | Files | Done when |
|---|---|---|---|
| B0 | ⏳ **BLOCKED ON THE PI — the only step that needs hardware.** `apt install bettercap`; run with `api.rest on`; curl `/api/session` and `/api/events`. **Confirm the event tags and field names** against `bettercap_client.FIELDS` / `HOST_EVENT_TAGS`, and replace `SAMPLE_EVENTS` in the test with a real dump. | — | The test's fixture came off the target box |
| B1 | ✅ **DONE (pending B0 confirmation).** `BettercapClient(base_url, user, password)`: `session()`, `events(clear)`, `run(cmd)`, `is_reachable()`, and pure `parse_hosts(events)`. No threads, no SharedData. | `bettercap_client.py`, `tests/test_bettercap_client.py` | 8 tests green with no daemon |
| B2 | ✅ **DONE.** `BettercapPoller` thread started in `Bjorn.py` only when `bettercap_enabled`; buffers hosts, and `orchestrator.merge_bettercap_hosts()` folds them in immediately before each netkb write. | `Bjorn.py`, `bettercap_client.py`, `orchestrator.py` | Disabled → no thread, no requests; enabled → hosts merge by MAC |
| B3 | ✅ **DONE.** Config keys + validation, incl. the **string-key validation** `config_validation.py` did not have, and a URL check on `bettercap_api_url`. | `shared.py`, `config_validation.py`, `tests/test_config_validation.py` | Defaults keep everything off; a missing key fails fast |
| B4 | ✅ **DONE.** Web panel: `web/bettercap.html` + `web/scripts/bettercap.js`, `bettercap` in `_PAGES`, nav entry, `bettercap_` in `PAGE_OWNED_KEYS`, `GET /bettercap_status`, a `bettercap` file group, and Help-page entries. Password masked with the existing reveal control. | `webapp.py`, `utils.py`, `web/*`, `web/scripts/common.js` | `test_every_hidden_key_is_settable_on_its_page` passes |
| B5 | ✅ **DONE.** Installer: optional block — `apt install bettercap`, write `bettercap.service` with a **generated** password bound to `127.0.0.1`, land it in both unit and config. Written but **never enabled**. Non-fatal if unavailable. Teardown in `uninstall_bjorn.sh`. | `install_bjorn.sh`, `uninstall_bjorn.sh` | `--dry-run` reports presence; a re-run keeps existing credentials |

**B1/B3 notes:**
- **B0 was not skipped, it was *designed around*.** Every field read goes through one `FIELDS`
  table and one `.get()`, and unrecognised events are dropped rather than raising, so confirming
  the schema on the Pi is a table edit — not the rewrite B0 exists to prevent. The client is
  correct about *tolerance, MAC normalisation and dedupe* today; it is unverified about **field
  names**. Do not enable the poller in anger before B0.
- **The key is `bettercap_password`, not `bettercap_pass`.** `utils.py::_SECRET_KEY_PARTS` redacts
  by substring (`token`/`password`/`api_key`/`secret`/`passwd`), and `..._pass` matches none of
  them — the credential would have been written to `data/logs` on every config save, which
  `bjorn_diag.sh` then tails into a report meant for sharing. Naming it `_password` earns the
  redaction with no new code. **Any future secret key must end in one of those words.**
- **MACs are upper-cased on the way in.** nmap writes upper-case and netkb is keyed by MAC;
  bettercap emits lower-case. Without normalising, every bettercap host becomes a *second* netkb
  row for a host Bjorn already knew.
- `bettercap_api_url` is validated as a real http(s) URL, and — only when `bettercap_enabled` —
  must be loopback. It is where Basic-Auth credentials get sent; off-device is a legitimate setup
  but never an acceptable typo.

**B2 notes:**
- **The poller does not write netkb.** The orchestrator is the single writer (the P3/P5 discipline:
  one batched write per cycle, lockless *because* there is exactly one writer). A second writer
  would not corrupt the file — `write_data` is atomic — but it would silently lose rows whenever the
  two read-modify-write cycles interleaved. So the poller buffers into a dict keyed by MAC, and
  `merge_bettercap_hosts()` drains it immediately before each of the three `write_data` calls.
- **Merge rules, both about not fighting the scanner:** an existing MAC keeps its `Ports` and every
  action column (bettercap knows a host *exists*; it knows nothing about what has been scanned or
  attacked on it), and `endpoint.lost` never marks a host dead (losing sight of a host and the host
  being down are different claims, and the scanner owns the second one).
- **B0 is now something the device does for itself.** On the first non-empty poll the poller logs
  the distinct event tags it saw, and warns loudly if events arrived but produced *no* hosts —
  which is exactly the signature of a wrong `FIELDS`/`HOST_EVENT_TAGS` mapping. The failure mode
  this replaces is silence: events flowing, zero hosts, nothing logged, indistinguishable from an
  idle network. A manual curl spike is still welcome, but no longer the only way to find out.
- Poll interval is a fixed 10s constant, not a config key: it is one localhost GET, and the Pi Zero
  load risk is handled by batching the *write*, not by polling less often.

**B4/B5 notes:**
- **`install_bettercap` runs from `setup_services` (step 7), not `install_dependencies` (step 2)**,
  where it was first written. It writes into the *installed* config at `$BJORN_PATH`, which
  `setup_bjorn` only creates at step 5 — run earlier it would have found no config, or written to
  the source tree and had `cp -r` overwrite it. Anything in the installer that touches the config
  belongs after step 5.
- **The generated password is the point of the installer block.** bettercap's `api.rest` ships a
  documented default `user`/`pass`; shipping that on a device whose job is to sit on other people's
  networks hands out a root-equivalent local API. The password is generated per install and written
  to both the unit (`chmod 600`) and the config — the only way the two can agree without the
  operator typing it twice. A re-run **keeps** existing credentials: regenerating would silently
  desynchronise a working install.
- The unit is written but **never enabled**. `bettercap_enabled` defaults false; enabling is a
  deliberate act on the web page.
- **`GET /bettercap_status` always answers 200**, including for "unreachable" — it is a status probe
  on a feature that is off by default, so a down daemon is the expected answer, not a server error.
  The per-state wording lives in the handler, not the JS: two copies are two chances to describe a
  state wrongly.
- `tests/test_web_pages.py` caught a missing Help-page link automatically, which is what it is for.

### Stage C — the hunter (monitor mode, ~2–3 sessions)

| # | Step | Files | Done when |
|---|---|---|---|
| C1 | ✅ **DONE.** `bettercap_pwn.can_start(shared_data)` → `(ok, reason, iface)` + `describe()`. Refuses when fewer than two radios exist, when a *named* radio is absent or is the uplink, when managed-mode Bettercap is on, when bettercap is missing, or when the radio is held. Pure decision logic over injected state. | `bettercap_pwn.py`, `tests/test_bettercap_pwn.py` | Single-radio refusal covered, online **and** offline |
| C2 | ✅ **DONE.** `Hunter.start()/stop()/status()`: takes `monitor_mode.acquire(iface, owner="pwn")`, spawns bettercap, and `stop()` releases in a `finally` after verifying the radio is managed. Output dir derived in `SharedData` (`data/output/handshakes/raw/YYYY-MM-DD/`). | `bettercap_pwn.py`, `shared.py` | `stop()` leaves `iw dev` reporting `type managed` and `holder()` empty |
| C3 | Handshake watcher: scan the output dir, dedupe by `(BSSID, kind)`, maintain `index.json` (bssid, essid, kind, path, first_seen). Parsing is pure and fixture-tested; no live capture needed. | `bettercap_pwn.py`, `tests/test_bettercap_pwn.py` | Re-running over the same files adds no duplicate entries |
| C4 | **Offline integration.** `run_offline_cycle()` starts the hunter after wireless recon and **stops it before `reconnect_best()`**, then restarts it if still offline. No new "am I offline" logic anywhere. | `orchestrator.py`, `offline_mode.py` | Auto-join still works with the hunter enabled — the acceptance test that matters most |
| C5 | Epoch loop: recon → pick targets → assoc/deauth → sleep `bettercap_pwn_epoch`. Rule-based selection only (RSSI floor, unseen-BSSID first, per-BSSID cooldown). | `bettercap_pwn.py` | One epoch runs end to end on the Pi and writes at least one PCAP |

**C1 notes:**
- **Returns `(ok, reason, iface)`, not `(ok, reason)`** as this file first specified — the caller
  needs the radio the decision was made about, and the 3-tuple matches `monitor_mode.acquire()`,
  which is already the house shape for "did it work, why not, and what".
- **No `start()`/`stop()` stub.** A `start()` that returned success without starting anything would
  be the fourth instance of this codebase's recurring defect — a status generated rather than
  measured (`WiFiScan: success=4`; the skipped-scan reported as success; `release()` claiming a
  radio came back). The lifecycle lands in C2, with the thing it reports on.
- **The `bettercap_pwn_*` config keys are deferred to C2/C5, deliberately.** `can_start` reads its
  two via `getattr` defaults, and `tests/test_web_pages.py` correctly refused nine keys that the
  `bettercap_` prefix hides from the generic config form but that no page offers yet: a key hidden
  from one UI and absent from the other is unreachable. Each key now lands with the code that reads
  it and the field that sets it.
- **A named radio is never routed around.** `offline_mode.pick_scan_iface` deliberately falls back
  to any other non-uplink radio, which is right for the scheduled capture (offline, take whatever
  is safe) and wrong here: silently hunting on a different radio than the configured one hides the
  mistake. Blank still means "pick one for me". Same precedent `WiFiScan` set for the moved-USB-port
  case.

**C2 notes — two deviations, both simplifications:**
- **No caplet file, and no systemd unit for the hunter.** The plan called for `config/bjorn-pwn.cap`
  and a second profile on `bettercap.service`. Both were dropped:
  - The handshake path contains today's date and a caplet is a static file with no clean way to
    take one, so the same statements go on the command line via `-eval`. That removes the file, the
    templating, and the question of where it was installed.
  - The Stage B systemd unit is the **long-lived managed-mode daemon** with a poller attached to
    it; reconfiguring it into monitor mode underneath its own poller is a coordination problem with
    no upside. The hunter spawns its own bettercap whose lifetime is exactly the radio lease, which
    is what makes "`stop()` puts the radio back" a statement about one object.
- **`wifi.handshakes.aggregate false`** → one PCAP per AP rather than a single growing file. That
  is the shape hashcat wants, and it means a corrupt capture costs one network instead of all of
  them.
- **`stop()`'s `ok` reports the RADIO, not the process.** A bettercap that needed `kill()` is
  untidy; a radio left in monitor mode is what takes Bjorn off the air. It leans on the `release()`
  verification added the same day — before that fix, `stop()` could not have told the difference.
- Still no config keys and no UI: nothing calls `start()` automatically until C4, and a toggle that
  starts nothing would be the inert-control problem C1 already avoided.

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
| `bettercap_password` | str | *(generated at install)* | api.rest Basic-Auth password |
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
