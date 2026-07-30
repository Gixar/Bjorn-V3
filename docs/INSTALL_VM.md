# Headless / VM install (Proxmox, cloud, or any non-Pi Linux)

Bjorn normally targets a Raspberry Pi with a Waveshare e-Paper display. It also runs
headless on a plain Linux VM (Proxmox LXC/VM, a cloud instance, WSL, etc.): set the
display backend to `mock` and skip the Pi-only hardware steps. Everything works through
the web UI at `http://<host>:8000/`.

## 1. Set the display backend to `mock`

In `config/shared_config.json`:

```json
"epd_type": "mock"
```

`mock` is a real backend (see `KNOWN_EPD_TYPES` in `config_validation.py`) — the display
thread renders to an in-memory image served at `/screen.png` and on the **Screen** page
instead of driving a physical panel. No SPI, no e-Paper, no GPIO required.

> Use `"mock"` explicitly rather than `"auto"`. `auto` probes for a real panel and only
> falls back to mock when detection fails; being explicit avoids the probe on a machine
> that has no display hardware at all.

## 2. Skip the Pi-only installer steps

The `Manual Install` in [`INSTALL.md`](../INSTALL.md) has a few steps that only apply to
Pi hardware. On a VM, skip these:

| Step in INSTALL.md | Skip on VM? | Why |
|---|---|---|
| Step 1 — Activate SPI & I2C | **Skip** | Those buses drive the e-Paper panel; there's none. |
| Step 3.1 — Configure E-Paper Display Type | Replace with `epd_type: "mock"` above | No panel to select. |
| Step 7.3 — USB Gadget Configuration | **Skip** | USB-gadget networking is Pi-specific hardware. |
| Steps 2, 3, 4, 5, 6, 7.1, 7.2 | **Keep** | System deps, Bjorn install, file-descriptor limits, and the `bjorn.service` unit apply everywhere. |

The automatic installer (`install_bjorn.sh`, choice 1) still runs on a VM; the SPI/I2C and
USB-gadget blocks simply no-op or can be declined when they don't apply.

## 3. Run and reach the UI

Start `bjorn.service` (or run `python Bjorn.py` directly), then open:

```
http://<vm-ip>:8000/
```

Everything the Pi exposes is available: stats, network/NetKB, credentials, loot, config,
the mock **Screen** preview, and the **Logs** page.

## Notes / not-yet-verified

- Actions that need real network access to targets (scan, brute-force) work as normal —
  they use the VM's network interface, not any Pi hardware.
- Battery monitoring (`battery.py`, PiSugar) is Pi-only and stays disabled.
- This page documents the intended headless path; end-to-end verification on a specific
  hypervisor (Proxmox LXC vs. full VM) is still open — see `docs/BACKLOG.md` (#138).
