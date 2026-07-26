# Changelog

All notable changes to this project are documented here. This file also serves as the
process log for the PRD §9 (P1) modernization pass.

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
