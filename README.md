# <img src="https://github.com/user-attachments/assets/c5eb4cc1-0c3d-497d-9422-1614651a84ab" alt="Bjorn" width="33"> Bjorn V3

![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=fff)
![Status](https://img.shields.io/badge/Status-Beta-blue.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![CI](https://github.com/Gixar/Bjorn-V3/actions/workflows/ci.yml/badge.svg)
![Tests](https://img.shields.io/badge/tests-281%20passing-brightgreen)

[![Reddit](https://img.shields.io/badge/Reddit-Bjorn__CyberViking-orange?style=for-the-badge&logo=reddit)](https://www.reddit.com/r/Bjorn_CyberViking)
[![Discord](https://img.shields.io/badge/Discord-Join%20Us-7289DA?style=for-the-badge&logo=discord)](https://discord.com/invite/B3ZH9taVfT)

<p align="center">
  <img src="https://github.com/user-attachments/assets/c5eb4cc1-0c3d-497d-9422-1614651a84ab" alt="Bjorn" width="150">
  <img src="https://github.com/user-attachments/assets/1b490f07-f28e-4418-8d41-14f1492890c6" alt="Bjorn e-Paper" width="150">
</p>

**Bjorn is a Tamagotchi-like autonomous network scanner and offensive-security appliance** that runs
on a Raspberry Pi with a 2.13" e-Paper HAT. Leave it on a network and it maps every host, probes
their services, brute-forces what it can, and pulls files off whatever opens — writing everything
into one knowledge base you read from a web UI.

**V3 makes it work in your pocket.** Earlier versions only did anything while attached to a LAN.
This one keeps collecting when there is no network at all: Bluetooth recon, an 802.11 survey, and
WPA handshake capture on a second radio, all running while it tries to find its way back online.

> ⚠️ **Authorized testing only.** Bjorn actively attacks the network it is on — it brute-forces
> credentials and copies files. Run it only on networks and devices you own or have written
> permission to test.

---

## 🙏 Standing on infinition's shoulders

**Bjorn is [__infinition__](https://github.com/infinition)'s creation, and this fork exists only
because the original is good.** Everything that makes Bjorn *Bjorn* came from
[infinition/Bjorn](https://github.com/infinition/Bjorn):

- **The idea** — a Tamagotchi that raids your network. Nobody else framed offensive tooling that way.
- **The personality** — the Viking on the e-Paper panel, the comments, the coins and levels. That is the reason people want one on their desk, and it is entirely theirs.
- **The architecture** — the `b_class` action-module contract, the `netkb.csv` knowledge base, and the scan → act → idle orchestrator loop. Every module this fork adds plugs into their design without changing it.
- **The attack chain** — SSH, FTP, SMB, Telnet, SQL and RDP brute-force plus the matching steal modules, and the nmap vulnerability scanner. This fork did not rewrite them; it feeds them better targets.
- **The installer, the e-Paper driver work, and the whole hardware story.**

This fork is **modernization and reach**, not reinvention. If you are new here, star
[the original](https://github.com/infinition/Bjorn) first — and the
[bjorn-detector](https://github.com/infinition/bjorn-detector) companion tool is theirs too.

### What this fork adds on top

| | infinition/Bjorn | Bjorn V3 |
|---|---|---|
| **Reach** | IP hosts on the one LAN it joined | **+ every subnet on every interface**, Bluetooth/BLE devices, 802.11 access points and clients, WPA handshakes |
| **Works offline** | Idles until a network appears | **Surveys the air, hunts handshakes, and auto-rejoins** — the pocket-carry feature |
| **Port discovery** | nmap | **RustScan by default — 29× faster** on a Pi Zero 2 W, with automatic nmap fallback |
| **Target selection** | Actions run in load order | **Scored planner** — ranks every (host, action) pair each cycle and shows *why* it chose |
| **Recon depth** | Port scan + nmap vuln scan | **+ HTTP fingerprinting, templated web checks, SNMP enum, offline CVE matching** |
| **Credentials** | Cracked per host | **Shared pool, replayed first on every other host and protocol** — one crack cascades |
| **Getting data out** | Read it on the device | **Telegram + SMTP auto-reporting, per-page dumps, one-click "everything in a zip"** |
| **Score** | Recomputed live, could drop to zero | **Monotonic high-water mark, persisted across restarts** |
| **Web UI** | 7 pages on `http.server` | **14 pages on FastAPI** + live WebSocket stats dashboard, log viewer, and a built-in `/help` |
| **Reliability** | — | Atomic netkb writes, systemd watchdog, fail-fast config validation, battery-aware shutdown |
| **Tests** | — | **281 tests + CI**, none requiring hardware |

In numbers: **17 → 24 action modules, 10 → 22 core modules, 7 → 14 web pages, 0 → 281 tests.**

---

## 📸 See it

<!-- ─────────────────────────────────────────────────────────────────────────
     SCREENCAPS GO HERE. Drag an image or GIF into a GitHub issue/PR comment to
     get a user-attachments URL, then paste it over each placeholder below.
     Suggested captures, in order of usefulness to a newcomer:
       1. The e-Paper panel showing live stats + a comment
       2. The web dashboard (/stats.html): coins, level, trend chart
       3. NetKB with a few cracked hosts
       4. A short GIF of a scan -> attack -> loot cycle in the live console
       5. The Wi-Fi survey page with APs and clients
     ───────────────────────────────────────────────────────────────────────── -->

| | |
|:--:|:--:|
| _**e-Paper panel** — screencap placeholder_ | _**Live stats dashboard** — screencap placeholder_ |
| _**NetKB / cracked hosts** — screencap placeholder_ | _**Wi-Fi survey** — screencap placeholder_ |

<p align="center"><em>Demo GIF placeholder — a full scan → attack → loot cycle.</em></p>

---

## 🌟 What it does

| Capability | What you get |
|---|---|
| **Host discovery** | Sweeps every subnet on every interface, not just the default gateway's. Merges into one `netkb.csv`; hosts are never dropped, only marked alive or dead. |
| **Port discovery** | **RustScan by default** — benchmarked at **29× faster than nmap** on a Pi Zero 2 W (1.65 s vs 48.39 s over 8 hosts), finding the same ports. Falls back to nmap automatically if the binary is missing or a run fails. |
| **Service fingerprinting** | HTTP `Server` / `X-Powered-By` / `<title>` per web port, then templated web checks (nuclei-style, JSON not YAML — no new dependency). |
| **Vulnerability matching** | Offline CVE enrichment from bundled signatures, with a service-line fallback for consumer gear nmap can't CPE-identify. |
| **Credential attacks** | SSH, FTP, SMB, Telnet, SQL, RDP. Anything cracked joins a shared pool and is **tried first** on every other host and protocol — one crack tends to cascade. |
| **Loot** | Files pulled off whatever opens, organised under `data/output/`. |
| **Bluetooth recon** | Timed BLE discovery, flagging Find My / SmartTag / Tile trackers from **advertisement data**, not just device names. |
| **Wi-Fi survey** | Passive AP + client survey via airodump-ng on a second radio, with band and channel control. |
| **Handshake hunting** | WPA handshake capture on a second radio while offline. Targets ranked, captures indexed, downloadable and worth coins. |
| **Reporting** | Auto-delivery to Telegram (HTTPS) with an SMTP fallback, only when the data actually changed. Plus one-click **"compile everything into a zip"**. |
| **Gamification** | Coins and RPG levels on a monotonic high-water mark — the score never drops, and survives restarts. |

### Offline mode — the pocket feature

With no default route, Bjorn stops sweeping a network it isn't on and instead:

1. **Surveys the air** — BLE and 802.11 recon need no target and work exactly as well offline.
2. **Hunts handshakes** — the idle wait between reconnection attempts is spent capturing, not sleeping.
3. **Tries to rejoin** — auto-joins a saved network that comes back in range.

The ordering is load-bearing: the radio is always handed back to managed mode before any
reconnection attempt, because `nmcli` cannot associate a monitor-mode interface and **fails
silently** if you try.

---

## 🧰 Hardware

| | Needed for |
|---|---|
| **Raspberry Pi Zero 2 W** (or any Pi) | Everything. Bjorn is tuned for the Zero 2 W's 512 MB. |
| **Waveshare 2.13" e-Paper HAT** | The screen. Set `epd_type: "mock"` to run headless without one. |
| **A second Wi-Fi radio (USB dongle)** | Wi-Fi survey and handshake hunting. **Never the uplink** — Bjorn refuses to monitor-mode the radio carrying its own connection, and refuses to hunt at all on a single-radio device. |
| Battery / PiSugar | Optional. Clean shutdown below a charge threshold. |

**Known-good dongle:** TP-Link Archer T2U Nano (Realtek RTL8811AU) with the out-of-tree
[`morrownr/8821au-20210708`](https://github.com/morrownr/8821au-20210708) DKMS driver — it supports
monitor mode and injection. The onboard Pi chip needs the nexmon patch and has an open
crash-on-injection bug, so a dongle is the only sane path.

---

## 🚀 Getting started

```bash
# 1. Get the code onto the Pi
git clone https://github.com/Gixar/Bjorn-V3.git Bjorn-V3
cd Bjorn-V3

# 2. Run the installer FROM INSIDE the repo — it installs this local copy
sudo chmod +x install_bjorn.sh && sudo ./install_bjorn.sh
# Choose 1 for automatic installation, then reboot.
```

Check what it would do first, changing nothing:

```bash
sudo ./install_bjorn.sh --dry-run
```

Then open **`http://<pi-ip>:8000/`**. Can't find the IP? The original author's
[bjorn-detector](https://github.com/infinition/bjorn-detector) finds any Bjorn on the network.

Full detail in the [Install Guide](INSTALL.md) · headless/VM setup in [`docs/INSTALL_VM.md`](docs/INSTALL_VM.md).

### First five minutes

1. **Join a network** — Config → Wi-Fi, pick an SSID. Ethernet and the USB gadget work with nothing to configure.
2. **Check the screen** — blank panel? Set `epd_type` to `auto`, or run `sudo python3 scripts/epd_test.py --all` with the service stopped to find the exact driver.
3. **Set the scope** — add anything you must never touch to `ip_scan_blacklist` / `mac_scan_blacklist` **before** starting.
4. **Start it** — Home → Start. The live console streams what it's doing.
5. **Turn on what you need** — each optional module is one checkbox on its own page.

Everything is explained in the built-in **`/help`** page on the device itself.

---

## 🔒 Defaults, and what's off

Bjorn is carried around, so the recon that needs no network is **on out of the box**:

| On by default | Off until you enable it |
|---|---|
| BLE recon | Telegram / SMTP reporting (needs a token) |
| Wi-Fi survey (no-op without a second radio) | wpa-sec import (needs an API key) |
| RustScan port discovery | Bettercap (needs installing) |
| Offline mode + auto-join | Handshake hunting |
| | ARP spoofing, traffic sniffing |
| | Joining *open* networks it has no profile for |

Nothing that needs a credential, transmits at a target, or ships data off-device is on unless you
turn it on.

---

## ✅ What's verified, and what isn't

This project distinguishes "the code is done" from "the hardware agrees", because they are
different claims.

**Confirmed on a Pi Zero 2 W:** RustScan at 29×, BLE recon, monitor-mode capture *and* release with
the uplink guard refusing the wrong radio, the scan→attack→idle planner, offline mode, the web UI,
the USB gadget, and the e-Paper pipeline.

**Implemented and unit-tested but never run on a radio:** the Bettercap integration and the
Handshake Hunter. All of it is off by default. Two version-specific unknowns (bettercap's event
schema and its handshake filenames) are each isolated to one place and **warn in the log** rather
than failing silently.

`scripts/bjorn_verify.py` runs the whole hardware checklist on the device and prints a
PASS/FAIL/SKIP report:

```bash
sudo /home/bjorn/Bjorn/scripts/bjorn_verify.py --save
```

---

## 🧭 Documentation

| Where | What |
|---|---|
| **`/help`** on the device | Settings reference, what every page does, troubleshooting table |
| [`INSTALL.md`](INSTALL.md) | Full install walkthrough |
| [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) | Start with `scripts/bjorn_diag.sh` |
| [`CHANGELOG.md`](CHANGELOG.md) | Every change, with the reasoning |
| [`docs/PRD.md`](docs/PRD.md) | Roadmap and design decisions |
| [`docs/BACKLOG.md`](docs/BACKLOG.md) | Open ideas, hardware findings, post-mortems |
| [`docs/BETTERCAP_PLAN.md`](docs/BETTERCAP_PLAN.md) | The Bettercap + Handshake Hunter plan |
| [`DEVELOPMENT.md`](DEVELOPMENT.md) | Adding your own attack module |

---

## 🔧 Extending it

Attack modules follow a small contract — drop a file in `actions/`, declare `b_class` / `b_port` /
`b_parent`, and the orchestrator picks it up, scores it against every host, and shows *why* it chose
it. See [`DEVELOPMENT.md`](DEVELOPMENT.md).

```bash
pytest tests/          # 281 tests, no hardware required
```

---

## 🤝 Contributing

New attack modules, bug fixes, docs and features all welcome — see
[Contributing](CONTRIBUTING.md), the [Code of Conduct](CODE_OF_CONDUCT.md) and the
[Development Guide](DEVELOPMENT.md).

Report issues via GitHub with reproduction steps, logs and context.
`sudo scripts/bjorn_diag.sh --save` produces exactly that, with secrets redacted.

## 📫 Credits

### The original

**[__infinition__](https://github.com/infinition) created Bjorn** —
[infinition/Bjorn](https://github.com/infinition/Bjorn). The concept, the Viking on the e-Paper
screen, the module architecture, the attack chain and the hardware work are all theirs, and this
fork inherits every one of them intact. Go star the original, join the
[Discord](https://discord.com/invite/B3ZH9taVfT) and
[r/Bjorn_CyberViking](https://www.reddit.com/r/Bjorn_CyberViking), and use their
[bjorn-detector](https://github.com/infinition/bjorn-detector) to find your Pi on the network.

If you want to support the person who built this thing, support them.

### This fork

[Gixar/Bjorn-V3](https://github.com/Gixar/Bjorn-V3) — pocket-carry recon, RustScan, the scored
planner, the offline mode, and the test suite. MIT, same as upstream.

### Also borrowed from the ecosystem (all MIT, with thanks)

- [`HackCocaine/BjornCocaine`](https://github.com/HackCocaine/BjornCocaine) — WebUI-first thinking, the Logs page
- [`LOCOSP/BjornWpaSecHarvester`](https://github.com/LOCOSP/BjornWpaSecHarvester) — wpa-sec import
- [`PierreGode/Ragnar`](https://github.com/PierreGode/Ragnar) — the predecessor project
- Adjacent projects that shaped features here: Pwnagotchi (display auto-detect, atomic writes, watchdog, battery), Kismet/airodump (the Wi-Fi survey), OpenHaystack/AirGuard (BLE tracker signatures), ProjectDiscovery nuclei (templated web checks), RustScan, and bettercap.

## 🌠 Stargazers

[![Star History Chart](https://api.star-history.com/svg?repos=Gixar/Bjorn-V3&type=Date)](https://star-history.com/#Gixar/Bjorn-V3&Date)

---

## 📜 License

MIT — see [LICENSE](LICENSE). Same license as the upstream project.
