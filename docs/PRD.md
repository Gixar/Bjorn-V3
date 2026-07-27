# PRD — Bjorn v2: Modernize, Harden, Extend

> **Status:** Draft for review · **Owner:** Andrés Freira · **Date:** 2026-07-26
> **Target:** Bjorn (autonomous RPi pentesting Tamagotchi), currently `v1.0.0 alpha 2`
> **Audience:** implementing agent(s); written to be human-verifiable before execution.

---

## 1. Summary

Bjorn is a "Tamagotchi-like" autonomous network scanner / vulnerability-assessment /
offensive-security tool for a Raspberry Pi Zero W with a 2.13" e-Paper HAT and a web UI.
It works, but the codebase is frozen at a **late-2024 snapshot** and is bit-rotting: its
GPIO dependency is deprecated on current Raspberry Pi OS, deps are stale, there is **no
test suite and no CI**, and setup is a single 500-line bash script with no verification.

This PRD makes Bjorn **useful today** without changing its security posture: it stays a
**full offensive red-team tool** (brute-force + exfil modules kept as-is). Work is phased
by priority:

| Phase | Theme | Priority | Goal in one line |
|-------|-------|----------|------------------|
| **P1** | Modernize & make it run | **Highest** | Runs reliably on 2026 Raspberry Pi OS + current hardware, with tests + CI. |
| **P2** | Defensive & learning value | Medium | Same tool also produces a home-network audit report + is a documented learning lab. |
| **P3** | New capabilities | Lower | New modules, better reporting/remote control, quality-of-life. |
| **P-AI** | AI agent layer (Claude API) | Spans P2–P3 | An LLM reasons over findings to prioritize attacks and write defensive audit reports. |
| ~~P4~~ | ~~Portability off the Pi~~ | Dropped | Out of scope for this PRD. |

**Non-goals:** removing/gating offensive modules; running headless off-Pi as a primary
target; rewriting in another language; changing the e-Paper/web UX paradigm.

---

## 2. Current State (verified from the repo)

**What exists**
- Entry point `Bjorn.py` → threads: `Display`, `Orchestrator`, `webapp` (Flask-style, port 8000).
- `orchestrator.py` — heuristic "brain": loads actions from JSON, runs scan → attack → steal cycle with retries and a 10-thread semaphore.
- `actions/` — modules: `scanning`, `nmap_vuln_scanner`, and connectors/stealers for FTP, SSH, SMB, RDP, Telnet, SQL (`*_connector.py`, `steal_files_*.py`, `steal_data_sql.py`).
- `shared.py` (32 KB), `utils.py` (37 KB), `display.py` (20 KB) — large god-modules holding config, netKB state, and rendering.
- `web/` — static HTML dashboard (`index`, `network`, `netkb`, `credentials`, `loot`, `config`).
- Config in `config/shared_config.json` (ports, blacklists, timings, `epd_type`).
- Install/uninstall/wifi-fix bash scripts.

**Concrete debt (the "make it run" problems)**
1. **`RPi.GPIO==0.7.1`** — deprecated on Raspberry Pi OS Bookworm and **non-functional on Pi 5** (Bookworm moved to `lgpio`/`gpiozero`). This is the single biggest "won't run today" risk.
2. **Pinned 2024 deps** (`numpy==2.1.3`, `Pillow==9.4.0`, `pandas==2.2.3`, `paramiko==3.5.0`, `pysmb`, `smbprotocol`, `pymysql`, `python-nmap`) — need a compatibility pass against current releases and against the current Pi OS Python.
3. **No tests** — zero coverage; refactors are unsafe. `.github/` has only `dependabot.yml` + `FUNDING.yml`, **no CI workflow**.
4. **OS coupling** — targets a specific image (`2024-10-22 bookworm`), assumes user/hostname `bjorn`, `nmcli` present, and a specific e-Paper revision (`epd2in13_V4`).
5. **Install script is unverified** — 500+ lines of bash, no dry-run, no idempotency guarantees, no post-install healthcheck.
6. **`debug_mode: true`** shipped as default in config; verbose logging on by default.
7. **God-modules** — `utils.py`/`shared.py` mix config, state, persistence, and business logic; hard to test.

---

## 3. Users & Scenarios

- **Primary — the operator (Andrés):** flashes a Pi, runs the installer, drops Bjorn on an **authorized** network (home lab / consented engagement), and monitors via e-Paper glance + web dashboard. Wants it to *just work* on today's hardware and to produce evidence he can review.
- **Secondary — the learner (Andrés):** uses Bjorn as a hands-on lab for his **AWS + Security** track (recon, service enumeration, credential hygiene, network defense). Wants the code readable and the findings explainable.
- **Tertiary — contributor:** adds an attack/recon module without reverse-engineering 37 KB of `utils.py`. Wants a documented module contract + a test to copy.

> ⚠️ **Authorized use only.** Bjorn performs intrusive actions (brute-force, exfiltration).
> This PRD keeps them fully enabled; it does **not** add scope-consent gating (per decision).
> Operator is responsible for authorization. A prominent legal/ethics banner stays in docs.

---

## 4. Requirements

### P1 — Modernize & make it run (highest priority)

| # | Requirement | Acceptance criteria |
|---|-------------|---------------------|
| P1-1 | **Replace deprecated GPIO stack** | e-Paper driver works on current Raspberry Pi OS (Bookworm+) and on Pi Zero 2 W / Pi 4 / Pi 5. Migrate `RPi.GPIO` → `gpiozero`+`lgpio` (or the Waveshare-supported path). Verified: display renders on real hardware or a documented mock. |
| P1-2 | **Dependency refresh** | `requirements.txt` re-pinned to current, mutually compatible versions that install cleanly on the current Pi OS Python; a `constraints`/lockfile captures the tested set. `pip install -r requirements.txt` succeeds in CI. |
| P1-3 | **Hardware-abstraction seam for the display** | `epd_helper.py`/`display.py` expose a driver interface with a **null/mock backend** so the app boots and runs the web UI on a non-Pi dev machine (for testing only — not a portability goal). App starts with `epd_type: "mock"`. |
| P1-4 | **Test suite (baseline)** | `tests/` with unit tests for orchestrator action-loading/retry logic, netKB state, config load/validate, and one connector using a mocked service. Target: smoke-level coverage of the orchestrator + at least one action path. `pytest` green. |
| P1-5 | **CI pipeline** | GitHub Actions workflow: lint (`pylint` config already present) + `pytest` + `pip install` on push/PR. Badge in README. |
| P1-6 | **Config safety defaults** | Ship `debug_mode: false`, sane logging defaults; document every key in `config/shared_config.json`. Invalid config fails fast with a clear message (validation at load). |
| P1-7 | **Installer hardening** | Installer is idempotent, has a `--dry-run`, checks prerequisites (OS version, HAT, `nmap`/`nmcli`), and runs a **post-install healthcheck** that confirms services start. Failure paths print actionable errors. |
| P1-8 | **Version + changelog** | Bump to a real `v2.0.0-alpha`, add `CHANGELOG.md`, tag the modernized baseline. |

### P2 — Defensive & learning value (added on top; offense stays)

| # | Requirement | Acceptance criteria |
|---|-------------|---------------------|
| P2-1 | **Audit/report output** | After a run, Bjorn emits a human-readable **network audit report** (hosts, open ports, services, weak/default creds found, exfil hits) as Markdown/HTML in `data/output/`. This reframes the same offensive results as a defensive finding list without disabling offense. |
| P2-2 | **Severity + remediation hints** | Each finding carries a severity and a one-line remediation ("Telnet open on X — disable/replace with SSH"). Static mapping table is fine (no external feed required). |
| P2-3 | **Learning-lab docs** | `docs/` explains, per module, *what it does, why it works, and how to defend against it* — tied to the operator's cert track (recon, enumeration, credential hygiene). Replaces/augments the current scattered `.md` files. |
| P2-4 | **Safe lab profile** | A config profile (`lab.json`) scoped to a single subnet/allowlist for practicing on an intentional-vuln host, kept separate from the default profile. |

### P3 — New capabilities (lower priority)

| # | Requirement | Acceptance criteria |
|---|-------------|---------------------|
| P3-1 | **Module contract + template** | Documented base interface every action implements (`b_class`, `b_module`, `b_port`, `execute()`), plus an `examples/` template module + its test. New module addable without touching core. |
| P3-2 | **Web UI auth** | The web dashboard (currently open on :8000) gets optional token/basic auth so loot/credentials pages aren't served unauthenticated on the LAN. |
| P3-3 | **Remote status / notifications** | Optional push of run summaries (e.g., webhook/ntfy) so the operator doesn't need to be on the LAN to see results. |
| P3-4 | **At-rest protection for loot** | Option to encrypt/redact `data/output/` credentials/loot; secrets never logged at default log level. |
| P3-5 | **New recon/attack module(s)** | At least one new module (e.g., HTTP service fingerprinting or SNMP enumeration) delivered against the P3-1 contract as the proof the extension path works. |

### P-AI — AI agent layer (Claude API)

Give Bjorn an LLM brain that reasons over what it has discovered, in plain language,
to **improve both sides**: on offense, decide *what to hit next and why*; on defense,
turn raw findings into an explained, remediation-ready audit report. This upgrades the
current static heuristic orchestrator (`orchestrator.py`) and the P2 report (P2-1) — it
does **not** replace them; it sits on top and degrades to them when offline.

**Architecture constraints (non-negotiable, driven by the hardware):**
- **Out-of-band, never in the hot loop.** LLM calls are cloud HTTP requests with seconds
  of latency and real cost — they run **asynchronously, between scan cycles**, and write
  advice back into the netKB. Scanning/attacking keeps running on the existing loop; the
  e-Paper stays a status glance. A Pi Zero W (ARMv6) cannot host a local model — this is
  API-only.
- **Graceful degradation.** No internet, no API key, or an API error → Bjorn falls back to
  the existing heuristic orchestrator with a logged warning. The AI layer is **additive**,
  never a hard dependency (ties to P1-1 "runs today").
- **Provider:** default to **Claude** (aligns with the operator's AWS + Claude CCA cert
  track). Model routing keeps cost sane: **`claude-haiku-4-5`** (~$1/$5 per Mtok) for
  routine per-host triage, **`claude-opus-4-8`** (~$5/$25 per Mtok) for deep attack-path
  reasoning and the final report. Not hard-wired — the model IDs live in config.

**The agent shape:** this is a *custom agent with your own tools* → **Claude API + tool
use** (the SDK Tool Runner or a manual loop), **self-hosted on the Pi** (Bjorn owns the
compute and the tools). It is **not** Managed Agents — that hosts the container and loop
on Anthropic's side, which is the wrong fit for an on-device tool that must run its own
scanners and gate its own actions. Bjorn's existing actions (`scanning`, connectors,
stealers, report) are exposed to the model as **tools**.

| # | Requirement | Acceptance criteria |
|---|-------------|---------------------|
| AI-1 | **Findings → advice (defensive, P2 tie-in)** | After a run, an LLM call turns the netKB into the P2-1 audit report: per-finding severity, a plain-English *why it matters*, and a concrete remediation. Structured Outputs (`output_config.format`) enforce a machine-parseable findings schema so the report renders deterministically. |
| AI-2 | **Attack-path reasoning (offensive)** | The agent reads the netKB (hosts/ports/services/vuln-scan output) and proposes a **prioritized next-action list** — which target/service to attempt next and why — replacing the static ordering in `orchestrator.py`. Output is structured (target, action, rationale, confidence). |
| AI-3 | **Tools = Bjorn actions, destructive ones gated** | Offensive actions (brute-force, exfil) are exposed as **dedicated, typed tools**, not an opaque bash tool, so the harness can enforce the target allowlist and the authorization gate **before** execution. The model proposes; the harness (not the model) decides whether a scoped, authorized target permits the call. Keeps the "authorized use only" posture from §3. |
| AI-4 | **Cost & key controls** | Per-run token budget + call cap in config; the netKB/system-prompt prefix is prompt-cached to cut repeat cost. API key loaded from env/`config` (**never** committed — enforced by existing `.gitignore`), redacted from logs. A run reports its estimated token spend. |
| AI-5 | **Offline/failure fallback** | With no connectivity or key, Bjorn runs exactly as it does today (heuristic orchestrator), logs that AI is disabled, and still produces the non-AI report. Verified by a test that stubs the API as unavailable. |

> ⚠️ **Scope guard.** The AI layer reasons over *Bjorn's own findings* to prioritize and
> explain authorized testing — target triage, output interpretation, remediation writing.
> It is not for generating novel exploits or evasion. Same authorization boundary as the
> rest of the tool; the operator owns consent.

### P-DEV — Collect → offline-improve → flash pipeline

Not a live agent. Bjorn already writes rotating logs (`logger.py` → `data/logs/`) and
result dirs (`data/output/{scan_results,vulnerabilities,crackedpwd,data_stolen,zombies}`)
— reuse those, don't replace them. What's missing is one thing purpose-built for *being
read by an LLM later*, and a habit around using it.

| # | Requirement | Acceptance criteria | Status |
|---|-------------|---------------------|--------|
| DEV-1 | **Run-report artifact** | `Orchestrator.write_run_report()` in `orchestrator.py` writes `data/output/run_reports/<run_id>.json` at each idle checkpoint (Bjorn's loop runs forever — there's no discrete "run" boundary, so the checkpoint is the natural substitute: once per completed scan pass, overwriting the same file for the process's lifetime). Contains: version, per-action success/fail counts, up to 5 truncated exception strings per action. **Never inlines credentials/loot/raw scanned strings.** | ✅ Done |
| DEV-1a | **LLM analysis connection** | `scripts/analyze_reports.py`: reads `data/output/run_reports/*.json`, prioritizes reports that had failures (a handful of clean ones kept as baseline), sends the redacted counts to Claude (`claude-opus-5`) with a single summarization call, writes the friction summary to `data/output/improvement_notes/<timestamp>.md`. Dev-machine tool (`scripts/requirements.txt`), not run on the Pi. Self-check: `tests/test_analyze_reports.py`. | ✅ Done |
| DEV-2 | **Export script** | One script (`scripts/export_reports.sh` or similar) tars `data/logs/` + `data/output/run_reports/` for pulling off the Pi via `scp`/`rsync` — no new dependency, no on-device network call. | Not started |
| DEV-3 | **Offline improvement workflow (documented, not automated)** | `docs/IMPROVEMENT_PROCESS.md`: pull the bundle to a dev machine → run DEV-1a for a friction summary → open a Claude Code session with that summary + repo → ask it to check `infinition/Bjorn` upstream and known forks for existing fixes to the same friction (MIT-licensed, so reuse with attribution in `CHANGELOG.md` is clean) → propose a patch → human reviews, runs CI (P1-5) + a mock-display smoke test → merge, bump version (P1-8) → build image → reflash. Triggered when friction actually accumulates, not on a fixed schedule. | Not started |

**Explicitly not doing:** no on-device code execution of LLM-proposed changes, no feeding
raw scan strings (attacker-influenced) into the improvement session — only the redacted
DEV-1 counts. The human applying the patch is the authorization gate, same posture as §3.

---

## 5. Milestones

1. **M1 — Boots on 2026 hardware** (P1-1, P1-2, P1-3, P1-6): GPIO migrated, deps refreshed, mock display, safe defaults. *Exit: `python Bjorn.py` starts on current Pi OS and on a dev box with mock display.*
2. **M2 — Trustworthy** (P1-4, P1-5, P1-7, P1-8): tests + CI green, installer hardened, versioned baseline. *Exit: green CI badge, clean install on a fresh image.*
3. **M3 — Defensible & teachable** (P2-1…P2-4): audit report + remediation + lab profile + learning docs. *Exit: a run produces a shareable audit report.*
4. **M4 — Extensible & safer surface** (P3-1…P3-5): module contract, web auth, notifications, loot protection, one new module. *Exit: a contributor adds a module using only the template + docs.*
5. **M-AI — AI brain** (AI-1…AI-5): async LLM layer over the netKB producing prioritized attack actions + an explained audit report, with authorization-gated tools and offline fallback. *Exit: a run with a key yields AI-ranked actions and a richer report; the same run with no key still completes on the heuristic path.*

---

## 6. Success Metrics

- **Runs today:** clean install + successful first scan on current Raspberry Pi OS on Pi Zero 2 W and Pi 4 (and mock-display boot on a dev box). *(P1)*
- **Safe to change:** CI green on every PR; core orchestrator + ≥1 action path covered by tests. *(P1)*
- **Produces evidence:** every run yields an audit report a human can act on. *(P2)*
- **Extensible:** a new module lands via the documented contract without core edits. *(P3)*
- **No regression in capability:** all existing offensive modules still function post-modernization. *(guardrail)*
- **AI adds signal, not a dependency:** with a key, AI-ranked actions and explained findings measurably improve on the static heuristic; with no key, the run still completes unchanged. *(P-AI)*

---

## 7. Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| GPIO/e-Paper migration breaks display on some HAT revisions | Keep old driver behind `epd_type`; add `mock`; test on real hardware before removing legacy path. |
| Dep upgrades break attack modules (paramiko/smb/pymysql API drift) | Pin via lockfile; cover each connector with a mocked-service test (P1-4) before/after upgrade. |
| Pi Zero W (ARMv6, single-core) too slow for refreshed deps | Recommend Pi Zero 2 W as baseline; document minimum spec; keep footprint lean. |
| Offensive tool + open web UI = accidental exposure | P3-2 web auth, P3-4 loot protection, `debug_mode:false` default, prominent authorization banner. |
| Scope creep back into "portability off the Pi" (dropped P4) | Mock display is for **testing only**; do not build a headless product target. |
| AI layer adds cost, latency, or a network dependency the Pi can't rely on | Async out-of-band calls only; per-run token/call budget (AI-4); hard offline fallback to the heuristic orchestrator (AI-5). |
| LLM proposes an action against an out-of-scope target | Harness enforces the allowlist + authorization gate on typed tools (AI-3) — the model never executes directly. |

---

## 8. Open Questions

1. Target hardware baseline for M1 — pin to **Pi Zero 2 W**, or must **original Pi Zero W (ARMv6)** stay supported? (Affects how aggressive the dep refresh can be.)
2. Is there a real intentional-vuln lab host available (e.g., Metasploitable/DVWA VM) for the P2-4 lab profile and connector tests, or should the PRD assume mocked services only?
3. Upstream intent: is this a **personal fork** to modernize, or a **proposal to send upstream** to `infinition/Bjorn`? (Affects versioning/branching and whether CHANGELOG targets the public project.)
4. AI layer: acceptable **per-run cost ceiling** (drives Haiku-vs-Opus routing and the AI-4 budget), and does the operator want AI decisions **auto-executed** (within the allowlist) or **surfaced for approval** in the web UI before Bjorn acts?

---

*Kept the existing offensive posture unchanged per decision. P2's "defensive" value is additive
(reporting + docs), not a de-scoping of the attack modules.*

---

## 9. Execution Plan (ponytail-lean)

Verified against the actual code (not just the PRD's description) before scoping this.
Two corrections that shrink the plan a lot:

> [!info] **P-DEV added below** — a "collect now, improve offline, flash later" pipeline.
> Came out of asking whether Bjorn could see its own logs and rewrite itself live (like an
> autonomous coding agent). Answer: not on-device — a Pi Zero running an offensive tool
> that also ingests untrusted network strings is exactly the setup where a self-modifying
> agent is a prompt-injection risk, not a feature. P-DEV is the safe version of that idea:
> collect good data now, run the actual improvement pass off-device (a Claude Code
> session, human-reviewed), flash a new version when it's ready. See §4a.

> [!important] **P1-1's "biggest risk" is already fixed in code.**
> `resources/waveshare_epd/epdconfig.py` already imports `gpiozero`, not `RPi.GPIO` — the
> driver-layer migration described in P1-1 is **done**. `RPi.GPIO==0.7.1` only survives as
> a stale, unused line in `requirements.txt` (grepped the whole repo: zero other hits).
> There is no "migrate the GPIO stack" work left — just delete the dead pin and declare
> the dependency the code already uses.

> [!important] **`epd_helper.py` already has the driver seam P1-3 asks for.**
> It loads `resources.waveshare_epd.{epd_type}` by name off config and duck-types the
> result (`init`, `getbuffer`, `display`/`displayPartial`, `Clear`). No new abstraction
> layer needed — a mock is just one more module in that same folder.

Only **P1** is planned below. P2 / P3 / P-AI are real ideas but speculative against a
tool that doesn't reliably boot yet — building report formats, module contracts, and an
LLM tool-use harness on top of an unverified base is the over-engineering ponytail exists
to catch. They're each one line at the bottom with a concrete trigger to revisit, not zero
lines — the PRD's phasing and priority order stays the reference when that trigger fires.

| Step | Diff | Ladder rung used | Status |
|------|------|-------------------|--------|
| 1. Drop dead GPIO pin | `requirements.txt`: remove `RPi.GPIO==0.7.1`, add `gpiozero` + `lgpio` (what `epdconfig.py` actually imports). | rung 2 — already in the codebase, just undeclared. | ✅ Done |
| 2. Refresh the rest of the pins | Bump `numpy`/`Pillow`/`pandas`/`paramiko`/`pysmb`/`smbprotocol`/`pymysql`/`python-nmap` to current versions in a venv on the target Pi OS Python; `pip freeze > requirements.txt` *is* the lockfile. | rung 3 — pip's own freeze, no pip-tools/poetry. | ⏳ Pi-gated (needs the Pi's Python) |
| 3. Mock display backend | New `resources/waveshare_epd/epdmock.py`: a class matching the existing duck-typed interface (no-op `init*`, `Clear`; `getbuffer`/`display*` just no-op or dump the PIL image to `data/output/` for a look). Set `epd_type: "mock"` to use it. | rung 2 — reuse the existing seam, don't build a new one. | ✅ Done (`mock` branch added in `shared.py`) |
| 4. Config safety defaults | Flip `debug_mode` to `false` in `config/shared_config.json`. Add one small startup function that checks required keys/types exist and raises a clear message if not — plain dict checks, no schema library. | rung 6/7 — one line + a few `if` checks. | ✅ Done (`config_validation.py`, wired into `load_config`) |
| 5. Baseline tests | `tests/` covering action retry logic and one connector path with a mocked service — plain `pytest`, dual-runnable as `python tests/test_*.py`. | rung 3 — stdlib mocks + a small stub helper cover it. | ✅ Done (retry_policy, config, mock EPD, ssh_connect) |
| 6. CI | One `.github/workflows/ci.yml`: `pylint` + `pytest`. Single job, single Python version (the one the target Pi OS ships) — no matrix until a second OS target is real. | rung 7, minimal. | ✅ Done (full `requirements.txt` install deferred to step 2) |
| 7. Installer hardening | Add a `--dry-run` flag (prints steps, runs nothing) and a healthcheck function (curl `:8000`, check the process is up) to the existing `install_bjorn.sh` — don't rewrite the 636 lines around it. | rung 2 — extend, don't replace. | ✅ Done (edited + syntax-checked here; reused existing `verify_installation`; full run Pi-gated) |
| 8. Version bump | `version.txt` → `2.0.0-alpha`, add `CHANGELOG.md`, tag. | rung 6, one line each. | ✅ Done (`git init` + `v2.0.0-alpha` tag) |
| 9. Run reports + analysis (DEV-1, DEV-1a) | **Done.** Orchestrator writes `data/output/run_reports/<run_id>.json` at each idle checkpoint — counts + exceptions, never raw creds/loot. `scripts/analyze_reports.py` turns those into a friction summary via one Claude API call. Cheap, reuses existing dirs, done alongside P1 rather than deferred — it's the data the §4a improvement process needs, and every day without it is a day of logs that weren't useful for that later. | rung 2 — extends the logging/output dirs that already exist; single LLM call, no agent/tool-use needed for a summarization task. | ✅ Done |

**Do whenever, it's cheap** (not gated on M1/M2):
- **DEV-2/DEV-3** — ✅ Done. `scripts/export_reports.sh` (bundle logs + run reports off the Pi) and `docs/IMPROVEMENT_PROCESS.md` (the offline loop). The workflow itself only gets *used* once enough run reports have piled up to be worth a pass.

**Skipped for now** (YAGNI — revisit only when its trigger fires, using the PRD's §4 as the spec when it does):
- **P2** (audit report, severity mapping, lab profile, learning docs) — revisit once M1/M2 above are green and someone actually runs a scan that needs a report to hand to someone.
- **P3** (module contract, web auth, notifications, loot encryption) — revisit when a second module or a non-LAN deployment is actually happening, not before.
- **P-AI** (Claude tool-use *live* agent, §4 as originally written) — revisit only after P2's static report exists and the §4a offline process feels too slow. Don't design the tool-calling harness against a report format that doesn't exist yet.

`utils.py`/`shared.py` god-modules: not touched here. Splitting them is a refactor with
no user-visible payoff until something in P1 actually needs to change inside them — do it
opportunistically per-step above, not as its own step.

---

## 10. Performance (target hardware: Pi Zero — ARMv6/v7, 512 MB, 1–4 cores)

Analysis of the hot paths against the constrained target. On a single-core ARMv6 Pi Zero W,
the two things that hurt most are **thread thrash** (spawning tens–hundreds of Python threads
for I/O-bound work) and **`pandas` imports** (~2–5 s and 50–80 MB each, in ~10 modules).
Real speedups need **on-Pi benchmarking** — none of this is measurable on a dev box.

### 10a. Modifying the Linux tools it shells out to

| # | Tool / call | Today | Change | Status |
|---|---|---|---|---|
| **L1** | **nmap** for ports | Not used — pure-Python `socket.connect` thread-per-port, `Semaphore(200)` (`scanning.py`) | One `nmap -sT -p<ports> <hosts>` process instead of hundreds of threads | ✅ Done (v2.2.0-alpha) |
| **L2** | **get-mac** (`gma`) | 5×2 s retry ARP lookup per host (`scanning.py::get_mac_address`) | Read MAC from the `nmap -sn` result (`nm[host]['addresses']['mac']`); ARP only as fallback | ✅ Done (v2.2.0-alpha) |
| **L3** | **nmap** timing/scripts | `-T2` + `-sV --script vulners.nse` (needs internet, heaviest op) | Config-driven timing; make `vulners.nse`/`-sV` optional | Backlog (`docs/BACKLOG.md`) |
| **L4** | **iwlist wlan0 scan** | Deprecated tool (`utils.py::scan_wifi`) | `nmcli -t -f SSID dev wifi` (already a dependency) | ✅ Done (v2.2.0-alpha) |

### 10b. Python / architecture

| # | Where | Problem | Fix | Status |
|---|---|---|---|---|
| **P1** | connectors (SSH/Telnet/SQL/SMB) | Hardcoded **40 threads** each | Config-driven, core-aware | Backlog |
| **P2** | ~10 modules | `import pandas` at module top | stdlib `csv` in connectors/`display.py`; lazy-import elsewhere | Backlog |
| **P3** | `shared.py::write_data` | Rewrites the whole `netkb.csv` after **every** action | Batch / write once per cycle | Backlog |
| **P4** | `orchestrator.py::run()` | `process_alive_ips()` then the same nested action loop again | Remove the duplicate | Backlog |
| **P5** | `display.py` | Re-reads 3 CSVs (via pandas) on every refresh | Cache counts; recompute on scan events | Backlog |
| **P6** | `scanning.py` | `time.sleep(5/7/0.1)` instead of `join()` — also a read-before-threads-finish race | Synchronous flow (moot once L1/L2 remove the threads) | ✅ Done (v2.2.0-alpha) |

**This pass implements L1, L2, P6, L4** (the scan-engine rewrite + Wi-Fi scan). It replaces the
Python socket port-scanner and the per-host ARP retry loop with nmap, and removes the fixed
sleeps. **Unverified off-device** — needs a real Pi + network to benchmark and confirm no
regression. P1–P5 and L3 stay in `docs/BACKLOG.md` (mostly safe code changes; deferred to keep
this pass focused on one testable area).
