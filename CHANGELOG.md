# Changelog

All notable changes to this project are documented here. This file also serves as the
process log for the PRD §9 (P1) modernization pass.

## [Unreleased]

### Added
- **`scripts/bjorn_doctor.sh`** — one read-only command that aggregates the whole health
  picture into a single report: version/OS/arch, SPI + `epd_type`, `bjorn.service` status,
  recent errors from **every** log location (`data/logs/*.log`, the systemd journal, and the
  newest `/var/log/bjorn_install/` log), and a map of where every log/loot/output file lives.
  Runs even when Bjorn won't start. Documented as the "start here" step in `TROUBLESHOOTING.md`.

## [2.3.0-alpha] — 2026-07-27

### Added
- **`epd_type: "auto"`** display driver selection (idea PG-1, from Pwnagotchi's multi-display
  support; PRD §11). At startup Bjorn tries the real-panel drivers in order and uses the first
  that initializes, logging each attempt — so it boots even if the configured driver errors or
  the HAT is absent. **Honest limit:** this keys off driver *init*, which can't tell V3 from V4
  (both init on the same panel with no render feedback); for a "inits but renders blank" panel,
  use `scripts/epd_test.py --all` (visual probe) to find the right one, then pin it.
- **PRD §11** — evaluated the Pwnagotchi ecosystem for transferable ideas; recorded graceful
  shutdown (PG-2), UPS awareness (PG-3), loop watchdog (PG-4), plugin system (PG-5), GPS tagging
  (PG-6) in `docs/BACKLOG.md`.
- **`scripts/epd_test.py`** — a standalone e-Paper diagnostic (run on the Pi). Checks SPI, then
  loads → inits → draws a visible test pattern → clears for a given `epd_type` (or `--all` to
  probe every driver in a fresh process each). Prints exactly which step fails, with traceback —
  the fastest way to find the driver that matches your HAT when the panel stays blank.

### Changed
- **e-Paper failures are now logged.** `epd_helper.py` logs through Bjorn's `Logger` (rich +
  data/logs/) with step-by-step init messages and full tracebacks (falls back to stdlib logging
  off-device so it stays importable in tests). `shared.py::initialize_epd_display` now logs an
  actionable blank-panel checklist (SPI enabled? epd_type correct? run epd_test.py) plus the
  traceback. Previously EPD errors went to a bare, unconfigured logger and were effectively
  swallowed.
- **Installer installs from the local repo instead of cloning from GitHub.** `install_bjorn.sh`
  now copies the repo it was run from (the folder the script lives in) into `/home/bjorn/Bjorn`
  — no network, works with a private repo. It only falls back to `git clone` when run standalone
  and `/home/bjorn/Bjorn` doesn't already exist. Fixes the private-repo clone failure (GitHub no
  longer supports git password auth). README/INSTALL updated to the "download repo → run installer
  inside it" flow.
- Installer prerequisite check no longer warns about `nmap` — it's installed in the dependency
  step, so pre-checking it always false-flagged on a fresh image (`nmcli`/`python3` are still
  checked, as they must pre-exist).

### Removed
- Dropped the public security-disclosure channel — deleted `SECURITY.md` and the issue-template
  "Security Reports" link. This fork is a private, personal-use repo; the inherited policy
  pointed vulnerability reports at the upstream author's email, so it was misleading rather than
  useful.

### Docs
- Repointed all install/self-references from upstream `infinition/Bjorn` to this fork
  (`Gixar/Bjorn-v2`): the README `wget` URL, the installer's `git clone`, `INSTALL.md`, the
  Contact/Star-History sections, and the issue-template links. Kept MIT attribution (LICENSE,
  original author) and the upstream Bjorn Detector reference. Noted the private-repo caveat for
  `wget`/`git clone`.

## [2.2.0-alpha] — 2026-07-26

### Changed (performance — target: Raspberry Pi Zero; see PRD §10)
- **Scan engine now uses nmap for port scanning** (L1): replaced the pure-Python socket
  scanner (a thread per host×port, throttled by a 200-thread semaphore) with a single
  `nmap -sT` process across all alive hosts. Deleted the dead `PortScanner` class + `socket`
  import.
- **Host MAC comes from the `nmap -sn` result** (L2): dropped the per-host 5×2 s ARP retry
  loop; `get-mac` is now a fallback only (and capped at ~2 s).
- **Removed the fixed `time.sleep(5/7/0.1)` scan delays** (P6): host discovery is now
  synchronous, which also fixes a read-before-threads-finish race.
- **Wi-Fi scan uses `nmcli` instead of the deprecated `iwlist wlan0 scan`** (L4).

> ⚠️ **Unverified off-device.** These change the core scan path and the Wi-Fi scan, and could
> only be `py_compile`-checked here (no nmap/network on the dev box). They need a real Pi + LAN
> to benchmark and confirm no regression before relying on them. Remaining perf items (P1–P5,
> L3) are tracked in `docs/BACKLOG.md`.

## [2.1.0-alpha] — 2026-07-26

### Fixed (from upstream/fork bug reports)
- **404 when executing a manual attack** (upstream #130 / #81, the most-upvoted open bug):
  after a manual attack, `web/index.html` fetched `/recent_logs`, which has no server route
  (the real endpoint is `/get_logs`) — the 404 users saw. Fixed the endpoint; removed the dead
  `/manual.html` route (the manual-attack UI already lives in `index.html`). *(Fix is against
  the verified server contract; not click-tested — needs the running WebUI to confirm.)*
- **Web server port hopping on restart** (upstream #16): `webapp.py` now uses a
  `ReusableTCPServer` with `allow_reuse_address = True` (SO_REUSEADDR), so a restart while the
  old socket is in TIME_WAIT rebinds :8000 instead of hopping to :8001+.
- **Installer aborted when one apt package was unavailable** (upstream #147, `libatlas-base-dev`
  removed in Debian trixie): `install_bjorn.sh` now warns and continues per-package instead of
  hard-failing the whole install.
- **Installer e-Paper prompt** (upstream #152): listed 5 display options but prompted "(1-4)";
  fixed to "(1-5)".

### Added
- `docs/BACKLOG.md`: tracked ideas mined from community forks and upstream issues (wpa-sec import,
  scan-all-interfaces, BadUSB, tri-color e-Paper, WebUI log viewer, Wi-Fi selection, etc.), each
  with a concrete implementation pointer. Most need the Pi/WebUI/hardware to build and verify.

## [2.0.0-alpha] — 2026-07-26

Modernization baseline. Executes the implementable subset of `docs/PRD.md` §9 (P1).
Hardware/OS-gated items (dependency refresh via `pip freeze` on the Pi, real e-Paper render,
full installer run) are prepared but must be verified on the target Raspberry Pi — see the
"Pi-gated" note below.

### Added
- **Mock e-Paper backend** (`resources/waveshare_epd/epdmock.py`) + a `"mock"` branch in
  `shared.py::initialize_epd_display`, so the app can run on a non-Pi dev box with
  `epd_type: "mock"` (testing only). (P1-3)
- **Fail-fast config validation** (`config_validation.py`, wired into `SharedData.load_config`):
  required keys/types are checked at startup and a clear `ValueError` lists every problem. (P1-6)
- **`retry_policy.py`** — the action retry-delay window decision, extracted from four
  copy-pasted blocks in `orchestrator.py` (one guard, all callers). (P1-4)
- **Baseline test suite** (`tests/`): retry policy, config validation, mock display, and one
  connector path (`SSHConnector.ssh_connect` with paramiko mocked). Each runs under pytest and
  as `python tests/test_*.py` with zero install. (P1-4)
- **CI** (`.github/workflows/ci.yml`): pytest + pylint (errors-only) on push/PR; badge in README. (P1-5)
- **Run reports + offline improvement path** (prior work this cycle): per-run redacted JSON
  reports (`Orchestrator.write_run_report`), `scripts/analyze_reports.py`,
  `scripts/export_reports.sh`, and `docs/IMPROVEMENT_PROCESS.md`. (PRD §4a DEV-1/1a/2/3)
- **Installer `--dry-run`** and an `nmap`/`nmcli`/`python3` prerequisite probe in
  `install_bjorn.sh`; reuses the existing `verify_installation` healthcheck. (P1-7)

### Changed
- `requirements.txt`: removed the dead `RPi.GPIO==0.7.1` pin (the e-Paper driver already uses
  `gpiozero`); added `gpiozero` + `lgpio`. Other pins flagged for a Pi `pip freeze`. (P1-1)
- `debug_mode` now defaults to `false` (in both `config/shared_config.json` and the in-code
  default). (P1-6)

### Pi-gated (not verified on this dev box — operator verifies on the Pi)
- **Dependency refresh** (P1-2): bump numpy/Pillow/pandas/paramiko/pysmb/smbprotocol/pymysql/
  python-nmap and re-pin via `pip freeze` on the target Pi OS Python; then `pip install -r
  requirements.txt` in CI.
- **Full installer run**, **real e-Paper render**, **clean install on a fresh image**.
