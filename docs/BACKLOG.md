# Backlog — ideas from community forks & upstream issues

Sourced from the MIT-licensed Bjorn ecosystem (reuse is clean with attribution in
`CHANGELOG.md`). These are **not yet built** — most need the Pi, a running WebUI, a live
network, or a vendor driver to build and verify properly, so they're tracked here rather than
shipped blind. Each entry names the concrete change so it's ready to pick up.

Already fixed this cycle (see `CHANGELOG.md`): #16 port hopping, #147 installer apt abort,
#152 EPD option-count prompt. Already covered by the v2 baseline: run-without-display (#11 →
`epd_type: "mock"`), dependency modernization (P1-1/P1-2).

## Bugs still open (need the WebUI/Pi to reproduce + verify)
| Ref | Issue | Likely fix / pointer |
|---|---|---|
| #176 | Can't enter comma-separated ports in GUI Settings | **Appears already resolved** in current code — `web/scripts/config.js` renders `portlist` as a text input and `saveConfig` splits on commas into an array. Re-test in the UI; no code change identified. |
| #190 / #160 | Wi-Fi APs not shown / no SSID switch in WebUI | Backend works (`scan_wifi` returns `{networks, current_ssid}`, `connect_wifi` takes `{ssid, password}`). The gap is front-end render / runtime (`iwlist wlan0` needs sudo + wlan0). Needs the running UI on the Pi to diagnose. |
| ~~#130 / #81~~ | ~~404 / error executing a manual attack~~ | ✅ **FIXED** — real cause was `index.html` fetching `/recent_logs` (nonexistent) right after the attack; changed to `/get_logs`. The dead `/manual.html` route was removed. The manual-attack UI already lives in `index.html`. |
| #155 | Web server not showing | Overlaps #16 (port hopping) — re-test after the SO_REUSEADDR fix; if still failing, check the systemd unit + firewall. |
| #122 | Installed but no Display *or* WebUI (most-commented) | Multi-cause: partly #16 (port), partly EPD init failing on the panel. Re-test after the port fix; if the display is still dead, check `epd_type` + wiring. Pi-only. |
| #113 | Waveshare **V4 unreadable** display | Affects the **default** `epd_type: "epd2in13_V4"` — reported as unreadable/garbled since May 2025. Likely a refresh-mode / LUT or rotation issue in the vendor driver. Needs the actual V4 panel to diagnose. |
| #68 | `usb0` IP not assigned | USB-gadget networking — `install_bjorn.sh::configure_usb_gadget` + the systemd-networkd config. Pi-only. |

## New capabilities (extend the offensive/recon surface — feeds P3-1 module contract)
- **wpa-sec / Pwnagotchi network import** (from `LOCOSP/BjornWpaSecHarvester`): pull cracked Wi-Fi creds from wpa-sec.stanev.org, dedupe, inject via `nmcli`. Pre-populates known creds instead of blind brute-force. New standalone action; needs network + `nmcli`.
- **Scan all network interfaces** (#133): `actions/scanning.py::get_network()` currently uses the single default gateway (`netifaces.gateways()['default']`). Change to return a list of networks (all interfaces with an AF_INET address) and loop `scan_network_and_write_to_csv` per network. Medium; needs a multi-interface host to verify.
- **BadUSB / HID mode** (#129): the installer already sets up a USB gadget (`configure_usb_gadget`); add an HID keyboard profile + a payload runner as a standalone action. Larger; hardware-only.
- **SNMP enumeration** and **HTTP service fingerprinting**: new recon modules against the P3-1 `b_class/b_module/b_port/execute()` contract (HTTP fingerprint is already the PRD's P3-5 example).

## Hardware / display
- **Waveshare 2.13" B/C tri-color** (#166): add `resources/waveshare_epd/epd2in13bc.py` from the vendor driver, then an `epd2in13bc` case in `shared.py::initialize_epd_display` and `KNOWN_EPD_TYPES` in `config_validation.py`. Needs the vendor driver + the actual panel to verify.

## Quality-of-life
- **In-WebUI log viewer** (from `BjornCocaine`): a "LOGS" tab. `/get_logs` already exists (`webapp.py` → `serve_logs`); add a `logs.html` page + nav link. Pairs with our run-reports. Small-ish, WebUI-only to verify.
- **Static IP assignment** (#26, done upstream): port their dhcpcd/NetworkManager static-IP config + a WebUI toggle.
- **Proxmox / headless-VM deployment** (#138): our `epd_type: "mock"` already makes headless runs feasible — this is mostly a docs page (`docs/INSTALL_VM.md`) + confirming the installer's Pi-only steps are skippable.

## AI / learning (overlaps §4a + P-AI — keep lazy)
- **Anonymized mission-data export** (the `infinition/Bjorn-cortex` framing): our run-reports already do the redacted-export half. Adopting Cortex's `.csv.gz` shape would make us swarm-compatible later **without** committing to the heavy VPS/TensorFlow stack. YAGNI until there's a Cortex to feed — revisit only if we join a swarm.

## Reference forks
- `HackCocaine/BjornCocaine` — screen-agnostic WebUI-first, LOGS button, multi-Pi.
- `LOCOSP/BjornWpaSecHarvester` — wpa-sec/Pwnagotchi import.
- `infinition/Bjorn-cortex` — swarm-AI training hub (heavyweight).
- `PierreGode/Ragnar` — the predecessor project.
