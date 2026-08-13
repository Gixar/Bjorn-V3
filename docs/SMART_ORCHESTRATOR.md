# Smarter orchestrator — scored work selection

> Status: **shipped** — `action_planner.py`, wired into `orchestrator.py::process_alive_ips`.
> Goal: Bjorn uses *all* of its tools automatically, does the most promising work first, and can
> say **why** it picked something — with no cloud LLM on a Pi Zero.

> **V2 update:** the static score is now a cold-start prior. With
> `smart_planner_enabled: true`, Bjorn blends it with local success and duration history. See
> [`SMART_PLANNER_V2.md`](SMART_PLANNER_V2.md) for persistence, backoff, rollback and evaluation.

## What was wrong

The orchestrator walked `self.actions` in **load order** and `break`ed on the first success per
host. Four consequences:

| Symptom | Cause |
|---|---|
| SSH always ran before SMB/RDP/… however promising the other target looked | fixed iteration order |
| A steal action only ran if it happened to follow its parent in the same pass | nested parent→child `break` |
| Standalone recon (BLE, Wi-Fi, SNMP, wpa-sec, reporting) only ran once the whole net was idle | gated behind `failed_scans_count` |
| The e-Paper showed an action name and an IP, nothing about why | no rationale to show |

Wave 1's credential reuse and offline CVE enrichment made individual *tools* smarter. This makes
the **scheduler** smarter.

## How it works

Each cycle, `Planner.collect()` scores every eligible `(host, action)` pair and every standalone
action; `Planner.select()` picks the work set; the orchestrator executes it. Ranking and execution
stay separate, so all of the scoring is testable without SharedData, netkb or hardware.

**Score components** (`score_host_action`):

| Signal | Weight | Why |
|---|---|---|
| Parent action already succeeded | +55 | loot is unlocked *now*; collect it before it goes stale |
| Never tried | +45 | unknown beats known |
| Known CVEs on this host | +35 | read from `vulnerability_summary.csv` |
| Looks like an appliance | +18…+30 | NAS / camera / admin panel / router, from `http_fingerprints.csv` |
| Retry due after a failure | +20 | ahead of a re-check, behind fresh work |
| High-value port | +8…+28 | 22 / 445 / 3389 / 3306 lead; see `HIGH_VALUE_PORTS` |
| Open-port count | +1 per port, capped at 12 | a rich host is a better target |
| Action class run in the last 6 picks | −8 | mild anti-monopoly |
| Per-action base | 8–40 | steals outrank the brute-force that unlocks them |

**Selection rules** (`Planner.select`):

- Up to `planner_max_host_actions` (default 4) host actions per cycle.
- **One action class per cycle**, so twenty SSH boxes cannot fill the window with SSH.
  Parent-ready child actions are exempt — several unlocked steals should all be collected.
- A standalone action every `planner_standalone_every` cycles (default 3), *while host work
  remains*, plus whenever nothing else was chosen.
- `idle_boost` rises with consecutive fruitless scans, so recon that needs no target takes over as
  host work dries up.

## Service-aware weights

`load_service_hints()` reads the `Server` / `X-Powered-By` / `<title>` that `HTTPFingerprint`
already banked and boosts hosts that look like an appliance rather than a generic web server: NAS
+30, camera +28, admin panel +26, router +22, embedded +20, printer +18. These are the classes that
ship with default credentials *and* hold something worth having. A host exposing several web ports
keeps its strongest hint. The reason line names the class, e.g. `SSHBruteforce@10.0.0.1 - NAS - :22`.

Matching is case-insensitive substring against an unambiguous list (`SERVICE_HINTS`) — a false
positive here quietly reorders the whole attack queue, which is why "nginx" earns nothing and
`axis` is absent (Apache Axis is a SOAP library, not a camera). It is a starting list; tune it
against what a real LAN turns up.

## Adaptive idle interval

`plan_idle_seconds()` sizes the sleep after a scan that found nothing, pulling in two directions:

- **Back off** as fruitless scans accumulate — `scan_interval x min(4, failed_scans)`. An exhausted
  network does not become interesting by being asked four times a minute, and each pass costs CPU
  and SD writes. Capped at 4x so a device walked onto the LAN is still noticed reasonably soon.
- **Wake early** when the only thing standing between Bjorn and real work is a retry window.
  `collect()` records `next_retry_wait` — the soonest a blocked action becomes runnable — and the
  sleep is cut to it, with a 30 s floor so a nearly-expired window can't become a busy loop.

Only blocks that actually expire count. A success with `retry_success_actions` off never becomes
runnable, and a closed port is structural, not temporal; neither shortens the wait.

Set `adaptive_scan_interval: false` to go back to a flat `scan_interval`.

## Two rules that must not be broken

1. **Standalone actions get no success gate.** `retry_success_actions` defaults to `False`, which is
   correct for a *host* action ("don't re-attack a box you already cracked") and wrong for a
   recurring job — one success would retire `BLEScan`/`WiFiScan`/`TelegramReport` for the lifetime
   of the netkb. That was the Wave 4 fix; `is_standalone_eligible()` only applies the *failed*
   backoff. The failed backoff stays: self-throttling covers success, not breakage.
2. **The diversity exemption is keyed on having a satisfied parent, not on a score threshold.** An
   ordinary never-tried SSH on a multi-port host scores 95, the same as a parent-ready steal, so a
   threshold high enough to admit steals readmits the monopoly the rule exists to prevent.

## What this trades away

A parent unlocked *during* a cycle no longer has its child run immediately after it in that same
cycle. The child becomes eligible on the next one, where "parent ok" (+55) puts it at the top. One
cycle of latency — and a cycle with work does not sleep.

## Interaction

- `bjornstatustext2` shows the reason: `StealFilesSSH@192.168.1.10 - parent ok - :22`
- Idle states read `thinking...` / `resting...` instead of blank
- Logs: `Planner chose: <reason> (score=N)`

## Config

All are optional; defaults are fine.

```json
"smart_planner_enabled": true,
"planner_max_host_actions": 4,
"planner_standalone_every": 3
```

Validated as **>= 1**: `planner_standalone_every` is a modulus, and 0 host actions would mean never
attacking anything. `Planner.sync_config()` re-reads them every cycle, so a change takes effect
without a restart, like every other setting. Setting `smart_planner_enabled` to `false` restores
the original static score and retry behavior without deleting the history learned by the Pi.

## Not built (next levers)

- **CPE-based weights** — the offline CVE enrichment already parses `nmap -sV` CPEs; a specific
  product+version could weigh more precisely than a `Server` header substring.
- **An LLM proposing value adjustments or annotations** (PRD P-AI), falling back to this planner. It belongs
  *between* cycles, never in the attack loop: scanning and attacking stay deterministic and local.
