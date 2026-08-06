# Smarter orchestrator — scored work selection

> Status: **shipped** — `action_planner.py`, wired into `orchestrator.py::process_alive_ips`.
> Goal: Bjorn uses *all* of its tools automatically, does the most promising work first, and can
> say **why** it picked something — with no cloud LLM on a Pi Zero.

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

Both optional; defaults are fine.

```json
"planner_max_host_actions": 4,
"planner_standalone_every": 3
```

Validated as **>= 1**: `planner_standalone_every` is a modulus, and 0 host actions would mean never
attacking anything. `Planner.sync_config()` re-reads them every cycle, so a change takes effect
without a restart, like every other setting.

## Not built (next levers)

- **Service-aware weights** from HTTP fingerprints / CPE — prefer hosts that look like routers, NAS
  or cameras once fingerprint data exists.
- **Adaptive `scan_interval`** — shorter while high-score candidates remain, longer once exhausted.
- **An LLM proposing the next-action list** (PRD P-AI), falling back to this planner. It belongs
  *between* cycles, never in the attack loop: scanning and attacking stay deterministic and local.
