# <img src="https://github.com/user-attachments/assets/c5eb4cc1-0c3d-497d-9422-1614651a84ab" alt="thumbnail_IMG_0546" width="33"> Bjorn

![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=fff)
![Status](https://img.shields.io/badge/Status-Development-blue.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![CI](https://github.com/Gixar/Bjorn-v2/actions/workflows/ci.yml/badge.svg)

[![Reddit](https://img.shields.io/badge/Reddit-Bjorn__CyberViking-orange?style=for-the-badge&logo=reddit)](https://www.reddit.com/r/Bjorn_CyberViking)
[![Discord](https://img.shields.io/badge/Discord-Join%20Us-7289DA?style=for-the-badge&logo=discord)](https://discord.com/invite/B3ZH9taVfT)

<p align="center">
  <img src="https://github.com/user-attachments/assets/c5eb4cc1-0c3d-497d-9422-1614651a84ab" alt="thumbnail_IMG_0546" width="150">
  <img src="https://github.com/user-attachments/assets/1b490f07-f28e-4418-8d41-14f1492890c6" alt="bjorn_epd-removebg-preview" width="150">
</p>

Bjorn is a « Tamagotchi like » sophisticated, autonomous network scanning, vulnerability assessment, and offensive security tool designed to run on a Raspberry Pi equipped with a 2.13-inch e-Paper HAT. This document provides a detailed explanation of the project.


## 🆕 What's New in v2 (this fork)

This is a modernized fork of [infinition/Bjorn](https://github.com/infinition/Bjorn), currently **`v2.1.0-alpha`**. It keeps the full offensive tool unchanged and adds a "runs today + safe to change" baseline. Full detail is in [`CHANGELOG.md`](CHANGELOG.md); the roadmap is in [`docs/PRD.md`](docs/PRD.md) and community ideas/bugs in [`docs/BACKLOG.md`](docs/BACKLOG.md).

> **Note:** `v2.1.0-alpha` is the current *verified* tag. `v2.2.0-alpha` adds a Pi-focused scan-engine rewrite (nmap-based port scan + MAC lookup, `nmcli` Wi-Fi scan) that is **not yet benchmarked on hardware** — see the performance section below and PRD §10.

**Baseline (2.0.0-alpha):**
- **Runs on a non-Pi dev box** — set `"epd_type": "mock"` in `config/shared_config.json` to boot without the e-Paper HAT (testing only, not a portability target).
- **GPIO stack unstuck** — dropped the dead `RPi.GPIO` pin; the e-Paper driver already uses `gpiozero` + `lgpio` (Raspberry Pi OS Bookworm+).
- **Fail-fast config** — an invalid `config/shared_config.json` now errors at startup with a clear message; `debug_mode` defaults to `false`.
- **Tests + CI** — `tests/` (retry logic, config validation, mock display, a mocked SSH connector) run under `pytest` or directly as `python tests/test_*.py`; GitHub Actions runs them on every push.
- **Run reports + offline improvement loop** — each run writes a redacted `data/output/run_reports/<id>.json` (counts and error text only, never credentials/loot). `scripts/export_reports.sh` + `scripts/analyze_reports.py` feed an offline, human-reviewed improvement process — see [`docs/IMPROVEMENT_PROCESS.md`](docs/IMPROVEMENT_PROCESS.md).
- **Hardened installer** — `sudo ./install_bjorn.sh --dry-run` checks prerequisites (OS, HAT, `nmap`/`nmcli`) and lists the steps without changing anything.

**Community bug fixes (2.1.0-alpha):**
- **Manual-attack 404** (upstream #130/#81, most-upvoted open bug) — the web UI fetched a nonexistent `/recent_logs` after an attack; fixed to `/get_logs`.
- **Web server port hopping** (#16) — the server now rebinds `:8000` on restart (SO_REUSEADDR) instead of drifting to `:8001`.
- **Installer resilience** (#147) — a package removed on newer Debian (e.g. `libatlas-base-dev` on trixie) no longer aborts the whole install; the e-Paper option prompt count was fixed (#152).

**Performance — Pi Zero focus (2.2.0-alpha, not yet hardware-benchmarked):**
- **nmap-based scan engine** — port scanning now runs as one `nmap -sT` process instead of a Python socket thread per host×port (was throttled by a 200-thread semaphore); each host's MAC is read from the `nmap -sn` result instead of a per-host 5×2 s ARP retry loop; fixed scan `sleep()`s removed. See [`docs/PRD.md`](docs/PRD.md) §10.
- **`nmcli` Wi-Fi scan** — replaces the deprecated `iwlist wlan0 scan`.

**Display robustness (2.3.0-alpha):**
- **`epd_type: "auto"`** — Bjorn tries the known Waveshare drivers in order and boots on the first that initializes, so a wrong/absent driver no longer stops it. (Idea from Pwnagotchi's multi-display support — see PRD §11.) It selects by driver *init*, so it can't tell a V3 panel from a V4; if the screen still shows nothing, run `sudo python3 scripts/epd_test.py --all` to see which driver actually renders, then set that exact `epd_type`.

> **Pi-gated (not yet verified on hardware):** dependency version refresh, real e-Paper render, a full installer run, **the 2.2.0-alpha scan-engine rewrite**, and the **2.3.0-alpha `auto` display detection** (all need a real Pi + LAN). See the CHANGELOG for the split between what's verified and what awaits the Pi.

## 📚 Table of Contents

- [What's New in v2](#-whats-new-in-v2-this-fork)
- [Introduction](#-introduction)
- [Features](#-features)
- [Getting Started](#-getting-started)
  - [Prerequisites](#-prerequisites)
  - [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage Example](#-usage-example)
- [Contributing](#-contributing)
- [License](#-license)
- [Contact](#-contact)

## 📄 Introduction

Bjorn is a powerful tool designed to perform comprehensive network scanning, vulnerability assessment, and data ex-filtration. Its modular design and extensive configuration options allow for flexible and targeted operations. By combining different actions and orchestrating them intelligently, Bjorn can provide valuable insights into network security and help identify and mitigate potential risks.

The e-Paper HAT display and web interface make it easy to monitor and interact with Bjorn, providing real-time updates and status information. With its extensible architecture and customizable actions, Bjorn can be adapted to suit a wide range of security testing and monitoring needs.

## 🌟 Features

- **Network Scanning**: Identifies live hosts and open ports on the network.
- **Vulnerability Assessment**: Performs vulnerability scans using Nmap and other tools.
- **System Attacks**: Conducts brute-force attacks on various services (FTP, SSH, SMB, RDP, Telnet, SQL).
- **File Stealing**: Extracts data from vulnerable services.
- **User Interface**: Real-time display on the e-Paper HAT and web interface for monitoring and interaction.

![Bjorn Display](https://github.com/infinition/Bjorn/assets/37984399/bcad830d-77d6-4f3e-833d-473eadd33921)

## 🚀 Getting Started

## 📌 Prerequisites

### 📋 Prerequisites for RPI zero W (32bits)

![image](https://github.com/user-attachments/assets/3980ec5f-a8fc-4848-ab25-4356e0529639)

- Raspberry Pi OS installed. 
    - Stable:
      - System: 32-bit
      - Kernel version: 6.6
      - Debian version: 12 (bookworm) '2024-10-22-raspios-bookworm-armhf-lite'
- Username and hostname set to `bjorn`.
- 2.13-inch e-Paper HAT connected to GPIO pins.

### 📋 Prerequisites for RPI zero W2 (64bits)

![image](https://github.com/user-attachments/assets/e8d276be-4cb2-474d-a74d-b5b6704d22f5)

I did not develop Bjorn for the raspberry pi zero w2 64bits, but several feedbacks have attested that the installation worked perfectly.

- Raspberry Pi OS installed. 
    - Stable:
      - System: 64-bit
      - Kernel version: 6.6
      - Debian version: 12 (bookworm) '2024-10-22-raspios-bookworm-arm64-lite'
- Username and hostname set to `bjorn`.
- 2.13-inch e-Paper HAT connected to GPIO pins.


At the moment the paper screen v2  v4 have been tested and implemented.
I juste hope the V1 & V3 will work the same.

### 🔨 Installation

The fastest way to install Bjorn is using the automatic installation script :

```bash
# 1. Get the code onto the Pi: download the repo ZIP from GitHub and unzip it
#    (or `git clone` if you have access). For a private repo this one-time
#    download is the ONLY GitHub step.
# 2. Run the installer from INSIDE the extracted repo folder — it installs that
#    local copy and does NOT clone from GitHub:
cd Bjorn-v2
sudo chmod +x install_bjorn.sh && sudo ./install_bjorn.sh
# Choose 1 for automatic installation. It may take a while (many packages/modules install).
# You must reboot at the end.
```

> **Note:** run the installer **from inside the downloaded repo** — it installs the local copy with no GitHub access. It only falls back to `git clone` if run standalone (e.g. a bare `wget` of just the script) and `/home/bjorn/Bjorn` doesn't already exist, which for a private repo would need a token.

For **detailed information** about **installation** process go to [Install Guide](INSTALL.md)

## ⚡ Quick Start

**Need help ? You struggle to find Bjorn's IP after the installation ?**
Use the original author's Bjorn Detector & SSH Launcher (a separate tool that works with any Bjorn install) :

[https://github.com/infinition/bjorn-detector](https://github.com/infinition/bjorn-detector)

![ezgif-1-a310f5fe8f](https://github.com/user-attachments/assets/182f82f0-5c3a-48a9-a75e-37b9cfa2263a)

**Hmm, You still need help ?**
For **detailed information** about **troubleshooting** go to [Troubleshooting](TROUBLESHOOTING.md)

**Quick Installation**: you can use the fastest way to install **Bjorn** [Getting Started](#-getting-started)

## 💡 Usage Example

Here's a demonstration of how Bjorn autonomously hunts through your network like a Viking raider (fake demo for illustration):

```bash
# Reconnaissance Phase
[NetworkScanner] Discovering alive hosts...
[+] Host found: 192.168.1.100
    ├── Ports: 22,80,445,3306
    └── MAC: 00:11:22:33:44:55

# Attack Sequence 
[NmapVulnScanner] Found vulnerabilities on 192.168.1.100
    ├── MySQL 5.5 < 5.7 - User Enumeration
    └── SMB - EternalBlue Candidate

[SSHBruteforce] Cracking credentials...
[+] Success! user:password123
[StealFilesSSH] Extracting sensitive data...

# Automated Data Exfiltration
[SQLBruteforce] Database accessed!
[StealDataSQL] Dumping tables...
[SMBBruteforce] Share accessible
[+] Found config files, credentials, backups...
```

This is just a demo output - actual results will vary based on your network and target configuration.

All discovered data is automatically organized in the data/output/ directory, viewable through both the e-Paper display (as indicators) and web interface.
Bjorn works tirelessly, expanding its network knowledge base and growing stronger with each discovery.

No constant monitoring needed - just deploy and let Bjorn do what it does best: hunt for vulnerabilities.

🔧 Expand Bjorn's Arsenal!
Bjorn is designed to be a community-driven weapon forge. Create and share your own attack modules!

⚠️ **For educational and authorized testing purposes only** ⚠️

## 🤝 Contributing

The project welcomes contributions in:

- New attack modules.
- Bug fixes.
- Documentation.
- Feature improvements.

For **detailed information** about **contributing** process go to [Contributing Docs](CONTRIBUTING.md), [Code Of Conduct](CODE_OF_CONDUCT.md) and [Development Guide](DEVELOPMENT.md).

## 📫 Contact

- **Report Issues**: Via GitHub.
- **Guidelines**:
  - Follow ethical guidelines.
  - Document reproduction steps.
  - Provide logs and context.

- **Original author**: __infinition__ — [infinition/Bjorn](https://github.com/infinition/Bjorn)
- **This fork**: [Gixar/Bjorn-v2](https://github.com/Gixar/Bjorn-v2)

## 🌠 Stargazers

[![Star History Chart](https://api.star-history.com/svg?repos=Gixar/Bjorn-v2&type=Date)](https://star-history.com/#Gixar/Bjorn-v2&Date)

---

## 📜 License

2024 - Bjorn is distributed under the MIT License. For more details, please refer to the [LICENSE](LICENSE) file included in this repository.
