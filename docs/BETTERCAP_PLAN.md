# Bettercap integration — implementation plan

Status: **planned, not started.** Scoped from the `docs/BACKLOG.md` Bettercap entry.
Default posture: **entirely off** — nothing runs, and nothing is enabled at install, until the
user turns it on from the web UI.

Grounded in Bjorn's existing patterns: external processes driven via `subprocess` (nmap/nmcli),
systemd units built in `install_bjorn.sh`, the `netkb.csv` + `shared.py` helper pipeline
(`netkb_targets` / `append_csv_rows` / `dedupe_csv`), config keys validated in
`config_validation.py`, and FastAPI routes in `webapp.py` / `utils.py`.

## Scope boundary

- **In (MVP):** bettercap as a managed daemon on the network Bjorn is *already* joined to via
  `nmcli`; a thin REST client polls its events and feeds discovered hosts into `netkb.csv` / stats.
  Managed-mode only — ARP recon/spoof, MITM, passive sniff. No monitor mode, no extra hardware.
- **Deferred (Phase 4, opt-in):** 802.11 monitor mode / deauth / handshake capture. Hard-gated
  behind a **second radio** — monitor mode and managed mode are mutually exclusive on one radio, so
  running it on `wlan0` would knock Bjorn off its own network (web UI, scanning, reporting) the
  moment it activates. **Never `wlan0`.**

## Architecture

Bettercap runs as its **own systemd unit** (`bettercap.service`), not inside Bjorn's process —
the same "external process" relationship Bjorn already has with nmap/nmcli. Bjorn talks to it over
its REST API (`api.rest`, HTTP Basic Auth). A **poller thread** started in `Bjorn.py` (alongside
the display / orchestrator / web threads) subscribes to `/api/events`, normalizes hosts, and writes
them through the existing `shared.py` helpers. It is a **data source**, not an orchestrator action,
so it does **not** join `actions.json` / the `b_class` module contract.

```
bettercap.service ──REST (api.rest)──> bettercap_client.py  (poller thread in Bjorn.py)
                                              │ normalize + batch
                                              ▼
                                  shared.py: netkb_targets / append_csv_rows / dedupe_csv
                                              ▼
                                     netkb.csv + /api/stats   (web dashboard, unchanged)
```

## Phases

### Phase 0 — spike (no commit to main)
On a Pi already on Wi-Fi: `apt install bettercap`, run
`bettercap -eval "api.rest on; ..."`, curl `/api/session` and `/api/events`. **Pin the exact event
JSON shape for discovered hosts before writing any client.** Bettercap's JSON varies by version.

### Phase 1 — client + poller (the core)
- New `bettercap_client.py`: `BettercapClient(base_url, user, pass)` with `session()`, `events()`
  (poll or WebSocket), and `poll_loop(shared_data, stop_flag)` that maps host events → netkb rows
  via the `shared.py` helpers. Modeled on Pwnagotchi's `pwnagotchi/bettercap.py`.
- `Bjorn.py`: start the poller thread **only if** `bettercap_enabled`; clean shutdown via the
  existing stop-flag pattern.
- Schema: bettercap hosts carry IP + MAC → fit `netkb.csv` as-is. **No new column in MVP.** A
  `device_type` / `source` column is only needed once wireless-layer (non-IP) entries arrive in
  Phase 4.
- **Load discipline (Pi Zero):** a busy LAN fires many events — batch them into the existing
  once-per-cycle netkb write (mirror the P3 batching), never write per event.
- **Test:** `tests/test_bettercap_client.py` — feed a captured events JSON fixture, assert the
  right netkb rows come out. No live daemon needed; stub heavy imports like `tests/test_scan_engine.py`.

### Phase 2 — dedicated web config panel + config keys

**Config keys** (`shared.py` defaults + `config_validation.py`):

| Key | Type | Default | Purpose |
|---|---|---|---|
| `bettercap_enabled` | bool | `false` | master switch — poller + service |
| `bettercap_api_url` | str | `http://127.0.0.1:8081` | REST endpoint (localhost only) |
| `bettercap_user` | str | `bjorn` | api.rest Basic-Auth user |
| `bettercap_pass` | str | *(generated at install)* | api.rest Basic-Auth password |
| `bettercap_arp_spoof` | bool | `false` | managed-mode ARP spoofing (off = passive recon only) |
| `bettercap_sniff` | bool | `false` | managed-mode passive traffic sniff |
| `bettercap_monitor_enabled` | bool | `false` | **Phase 4** — 802.11 monitor mode |
| `bettercap_monitor_iface` | str | *(unset)* | **Phase 4** — wireless iface (never `wlan0`) |

`config_validation.py` currently validates bools and non-negative ints; add **minimal string-key
validation** (present + `str`) for the URL/creds/iface keys, plus the Phase-4 fail-fast:
`bettercap_monitor_enabled` true but iface missing/unsupported/`wlan0` → log clearly and fall back
to disabled, never crash.

**Dedicated panel** — a self-contained **Bettercap** panel, not just switches auto-rendered on the
generic config page (its behavior is richer than a flat key/value list: live status, credentials,
a monitor-mode capability probe). Follow the existing panel/page patterns already in the web app
(the manual-attack collapsible panel in `index.html` / `dashboard.js`, and the config page's
`config.html` / `config.js`). Two viable homes — **pick one in Phase 2**:
- a new nav page `web/bettercap.html` + `web/scripts/bettercap.js` + `bettercap` in `webapp.py`'s
  `_PAGES` (mirrors how the Logs page was added), **or**
- a collapsible **Bettercap** section on the existing config page.
Recommended: a **dedicated page** — it keeps the live-status polling and the monitor-mode probe out
of the generic config-save flow.

Panel contents:

```
┌── Bettercap ───────────────────────────────────────────────┐
│ Status:  ● running / ○ stopped / ⚠ unreachable   [refresh]  │  <- GET /bettercap_status
│                                                             │
│ [ ] Enable Bettercap                    (bettercap_enabled) │
│ API URL   [ http://127.0.0.1:8081 ]     (bettercap_api_url) │
│ User      [ bjorn ]                      (bettercap_user)    │
│ Password  [ •••••••• ] [reveal]          (bettercap_pass)   │  <- masked, like Wi-Fi pw
│                                                             │
│ Managed mode (safe on current radio):                       │
│   [ ] ARP spoofing                    (bettercap_arp_spoof) │
│   [ ] Passive sniff                   (bettercap_sniff)     │
│                                                             │
│ ── Monitor mode (Phase 4 — needs a 2nd radio) ────────────  │
│   [ ] Enable monitor mode        (bettercap_monitor_enabled)│
│   Interface [ wlan1 ▾ ]          (bettercap_monitor_iface)  │  <- dropdown from iw dev/netifaces
│   [ Test monitor support ]                                  │  <- iw phy <phy> info -> "monitor"
│   ⚠ wlan0 is refused (would drop Bjorn's own connection)    │
│                                                             │
│                                   [ Save ]  [ Restart bettercap ]
└─────────────────────────────────────────────────────────────┘
```

- **Save** reuses the existing config-save endpoint (validated server-side); enabling/disabling
  starts/stops the poller + `bettercap.service`.
- **Status** polls a new lightweight `GET /bettercap_status` (`utils.py`) — reachable / running /
  version — so the panel shows live state without touching the config-save path.
- Password field masked with the same reveal control the Wi-Fi password already uses; never render
  the stored password in plaintext on load.
- Monitor-mode block is **visually disabled** until Phase 4 lands (the keys exist but do nothing yet).

### Phase 3 — installer provisioning
- `install_bjorn.sh`: new **optional** block (like the RustScan one) — `apt install bettercap`
  (skip if declined), write `/etc/systemd/system/bettercap.service` (`cat >` pattern,
  `ExecStart=bettercap -eval "api.rest on; ..."` with a **randomly generated** password bound to
  `127.0.0.1`), and land that password in both the unit and Bjorn's config. **Do not**
  `systemctl enable` unless enabled. Non-fatal if bettercap is unavailable, exactly like RustScan.
  `--dry-run` reports presence.
- `uninstall_bjorn.sh`: stop / disable / remove `bettercap.service` (guarded, like the other units).

### Phase 4 — monitor mode (separate PR, opt-in)
Uses the Phase-2 keys/panel block. Dropdown of present wireless ifaces (`iw dev` / `netifaces`);
"Test monitor support" runs `iw phy <phy> info` and checks for `monitor`. Fail-fast in
`config_validation.py`. **Refuses `wlan0`.** Hardware note for whoever picks a dongle: the onboard
chip needs the nexmon patch to enter monitor mode; the Zero 2 W has a currently-open
crash-on-injection nexmon bug (~50–200 packets), so a second interface is required, not `wlan0`.

## New / touched files

| File | Change |
|---|---|
| `bettercap_client.py` | **new** — REST client + poller thread |
| `Bjorn.py` | start poller thread when `bettercap_enabled` |
| `shared.py` | config defaults (table above) |
| `config_validation.py` | new bool keys + minimal string-key validation + Phase-4 fail-fast |
| `web/bettercap.html` | **new** — dedicated panel page |
| `web/scripts/bettercap.js` | **new** — panel logic (status poll, save, monitor probe) |
| `webapp.py` | `bettercap` in `_PAGES`; `GET /bettercap_status` route |
| `utils.py` | `bettercap_status` handler; creds masking on config load |
| `web/scripts/common.js` | "Bettercap" nav entry |
| `install_bjorn.sh` / `uninstall_bjorn.sh` | provision / teardown `bettercap.service` |
| `tests/test_bettercap_client.py` | **new** — fixture-driven parser test |
| `CHANGELOG.md` | entry under the next version |

## Security

- Bettercap's `api.rest` ships **weak default `user`/`pass`** — the installer must generate a random
  password and never ship the default. Bind `api.rest` to `127.0.0.1` only.
- Same "don't expose this" treatment as Bjorn's own endpoints; document password rotation.

## Risks / open questions

- **Event schema** must be pinned in Phase 0 (varies by bettercap version).
- **Pi Zero load** — batch events into the once-per-cycle netkb write, never per-event.
- **Credential handling** — generated password must reach both the service unit and Bjorn config.
- **Dedupe** — bettercap-discovered and nmap-discovered hosts must merge by MAC in netkb (the
  `shared.py` helpers already do this).

## Acceptance criteria (MVP)

1. `bettercap_enabled: false` → zero behavior change, no bettercap process, tests green.
2. Enabled on a real Pi already on Wi-Fi → bettercap-discovered hosts appear in `netkb.csv` and the
   web dashboard within one scan cycle.
3. `api.rest` bound to localhost with a non-default, generated password.
4. Disable + reboot → poller and service stop cleanly.
5. The Bettercap panel shows live status and saves all managed-mode keys; the monitor-mode block is
   present but inert until Phase 4.

## Effort

Phases 1–3 (MVP incl. the dedicated panel): **~2–3 focused sessions**, most risk front-loaded into
the Phase 0 spike. Phase 4 (monitor mode) is a comparable second effort and its own PR.
