# Coins / stats overhaul — implementation plan

Status: **planned, not started.** Scoped from the `docs/BACKLOG.md` "Coins / stats overhaul" item.
Pure software — no hardware, no new dependency.

## Problem (current state)

The score is a **live gauge derived from mutable counts**, end to end:

- `display.py` recomputes the category counts each tick by reading files/CSV — `crednbr` (cracked
  passwords), `datanbr` (files stolen), `zombiesnbr`, `attacksnbr`, `networkkbnbr` (all known hosts),
  `vulnnbr` (from `netkb` / vuln summary). The netkb-derived ones are change-gated on
  `data_generation` (P5); the cheap file counts stay per-tick.
- `shared.py::update_stats()` then derives the score as a **flat linear function of those live
  counts**:
  ```python
  coinnbr = networkkbnbr*5 + crednbr*5 + datanbr*5 + zombiesnbr*10 + attacksnbr*5 + vulnnbr*2
  levelnbr = networkkbnbr*0.1 + crednbr*0.2 + datanbr*0.1 + zombiesnbr*0.5 + attacksnbr + vulnnbr*0.01
  ```

Consequences: the score **can drop** (a `clear_files`, a cleaned netkb, hosts going offline all
lower a count → lower coins), nothing is **durably earned**, coins/level **reset to 0 on restart**
(`shared.py:354-361`), and levels are a **flat multiplier** with no progression.

## Design — monotonic high-water-mark accumulator (the lazy correct model)

**Don't** hook every achievement site in the connectors/scanner (a large, fragile change).
**Instead** reuse the counts `display.py` already computes and make the *derivation* monotonic and
persistent:

- Keep a **high-water mark per category** in a persisted `data/stats.json`. Each update:
  `hwm[cat] = max(hwm[cat], current_count[cat])` — marks only ever rise, even across a `clear_files`
  or a netkb reset, because the persisted value wins.
- `coins = Σ hwm[cat] * weight[cat]` — monotonic by construction (sum of non-decreasing terms).
- `level = curve(coins)` — a rising threshold curve, not a flat multiplier.
- Persist `{hwm, coins, level, history}` after each update; load it at startup so the score
  survives restarts.

This is a change to **one place** (a new `update_stats()` body + a tiny persistence helper), reuses
the existing per-category counts, and needs **no connector/scanner edits**. It keeps the P5
change-gated cheapness (the counts are still only recomputed when `data_generation` bumps).

### `data/stats.json` shape
```json
{
  "version": 1,
  "hwm": { "hosts": 9, "creds": 2, "data": 5, "zombies": 0, "attacks": 3, "vulns": 0 },
  "coins": 95,
  "level": 3,
  "history": [ {"t": "20260802_1140", "coins": 80}, {"t": "20260802_1210", "coins": 95} ]
}
```
`history` is a bounded ring (e.g. last 200 points) for the trend chart — appended only when `coins`
changes, so an idle Bjorn doesn't grow it.

## Phases

### Phase 1 — monotonic, persistent core (the substance)
- `shared.py`: on init, **load** `data/stats.json` (seed `hwm`/`coins`/`level`; default all-zero on
  first run). Rewrite `update_stats()` to the high-water-mark model above and **save** after
  computing. Add a small `_load_stats()` / `_save_stats()` pair (atomic write — reuse the existing
  `netkb.csv` temp→fsync→replace pattern, so a power loss can't corrupt it; PG-2 discipline).
- **Weights + curve** live as named constants (see Phase 3) so tuning is a one-line edit.
- `display.py` unchanged — it still reads `coinnbr`/`levelnbr` off `shared_data` and draws them.
- **Migration / existing installs:** first run with no `stats.json` seeds `hwm` from the current
  live counts, so nobody's score visibly resets to 0 at upgrade; from then on it only rises.
- **Test:** `tests/test_stats.py` — feed increasing then *decreasing* counts, assert coins never
  drop; assert reload from a `stats.json` restores the total; assert the level curve thresholds.

### Phase 2 — richer stats in the web UI
- `utils.py::get_stats_snapshot()` already returns the totals; extend it with the **per-category
  breakdown** (`hwm` + each category's coin contribution) and the **recent history** for a trend.
- `webapp.py`: the existing `/api/stats` + `/ws/stats` carry the richer payload (additive — old
  fields stay, so nothing breaks).
- `web/stats.html` + `web/scripts/stats.js`: add a **breakdown view** (per-category earned totals +
  what earned the last coins) and a **trend line** from `history`. Builds on the dashboard that
  already exists; no new page needed.

### Phase 3 — rebalanced weights (decision, then a constant)
Retune so rare achievements pay more than common ones. Starting proposal (finalize before coding):

| Category | Old weight | Proposed | Rationale |
|---|---|---|---|
| `hosts` (known) | 5 | 1 | a host merely appearing is cheap/common |
| `creds` (cracked) | 5 | 25 | the rare, high-value win |
| `data` (files stolen) | 5 | 15 | high value |
| `zombies` | 10 | 15 | — |
| `attacks` | 5 | 5 | — |
| `vulns` | 2 | 8 | — |

**Level curve:** replace the flat multiplier with rising thresholds. Lazy default —
`level = floor(sqrt(coins / K))` (a diminishing curve in one line, K tuned so early levels come
quick and later ones slow), or an explicit threshold table if a specific pacing is wanted.

## New / touched files

| File | Change |
|---|---|
| `shared.py` | load/save `stats.json`; monotonic HWM `update_stats()`; weights + curve constants |
| `data/stats.json` | **new** — persisted score (gitignored like other `data/` runtime files) |
| `utils.py` | richer `get_stats_snapshot()` (breakdown + history) |
| `webapp.py` | `/api/stats` + `/ws/stats` carry the richer payload (additive) |
| `web/stats.html`, `web/scripts/stats.js` | breakdown view + trend chart |
| `tests/test_stats.py` | **new** — monotonicity, persistence, curve |
| `CHANGELOG.md` | entry under the next version |

## Risks / open questions

- **Single writer:** `update_stats()` runs on the display thread; keep it the only writer of
  `stats.json` to stay lockless (same discipline as the P5 counters).
- **Pi Zero cost:** one small JSON write when `coins` changes (not per tick) — negligible; the
  history ring is bounded.
- **Weight/curve values** need a decision (Phase 3 table above is a starting point, not final).
- **Back-compat of the payload:** keep the existing `coins`/`level` fields in `/api/stats` so the
  current dashboard keeps working during the UI change.

## Acceptance criteria

1. Coins **never decrease** — a `clear_files` or a dropped host does not lower the score.
2. Score **survives a restart** (loaded from `stats.json`), and a fresh install seeds from current
   counts rather than showing 0.
3. Levels follow a **rising curve** (later levels need more coins than earlier ones).
4. The stats dashboard shows a **per-category breakdown + a trend**, not just totals.
5. Rare achievements (cred cracked, file stolen) contribute **more** per event than a host appearing.
6. `display.py` still renders coins/level unchanged; `tests/test_stats.py` green.

## Effort

**M (~2 sessions).** Phase 1 is the substance (monotonic model + persistence + migration + test);
Phase 2 is additive web work; Phase 3 is a values decision plus a constant. No hardware, no new
dependency — the most self-contained item in the backlog.
