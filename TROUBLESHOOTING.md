# 🐛 Known Issues and Troubleshooting

<p align="center">
  <img src="https://github.com/user-attachments/assets/c5eb4cc1-0c3d-497d-9422-1614651a84ab" alt="thumbnail_IMG_0546" width="98">
</p>

## 📚 Table of Contents

- [Current Development Issues](#-current-development-issues)
- [Troubleshooting Steps](#-troubleshooting-steps)
- [License](#-license)

## 🪲 Current Development Issues

### Long Runtime Issue

- **Problem**: `OSError: [Errno 24] Too many open files`
- **Status**: Partially resolved with system limits configuration.
- **Workaround**: Implemented file descriptor limits increase.
- **Monitoring**: Check open files with `lsof -p $(pgrep -f Bjorn.py) | wc -l`
- At the moment the logs show periodically this information as (FD : XXX)

## 🩺 Start here: `bjorn_diag.sh` (central diagnostics)

One read-only command gathers everything into a single report — version **and running commit**,
system health, service and process state, network, hardware (SPI/I2C), which external tools are
actually installed, a netkb/stats summary, config highlights, recent errors from **all** log
locations, recent orchestrator activity, and a map of where every log and output file lives. It
works even when Bjorn won't start.

```bash
sudo /home/bjorn/Bjorn/scripts/bjorn_diag.sh
# quick pass (skips the long log tails):
sudo /home/bjorn/Bjorn/scripts/bjorn_diag.sh --short
# save a timestamped copy under data/output/ to share or attach:
sudo /home/bjorn/Bjorn/scripts/bjorn_diag.sh --save
```

Read the top of the report first: it says how many commits behind upstream the checkout is. A
report from stale code describes a device you have already fixed.

Config values for `token` / `password` / `api_key` / `secret` keys are redacted, so the report is
safe to paste into an issue. Log tails are printed verbatim — worth a glance before sharing.

> Replaced `bjorn_doctor.sh`, which produced a smaller version of the same report. Two scripts
> meant two places to update, and the smaller one went stale.

Where Bjorn leaves things (the report prints this too):

| What | Location |
|------|----------|
| App logs (per module) | `data/logs/*.log` |
| Run reports (redacted) | `data/output/run_reports/*.json` |
| Loot / credentials / scan results | `data/output/{crackedpwd,data_stolen,scan_results,vulnerabilities,zombies}/` |
| netKB / live status | `data/netkb.csv`, `data/livestatus.csv` |
| Config | `config/shared_config.json` |
| Installer logs | `/var/log/bjorn_install/*.log` |
| Service journal | `journalctl -u bjorn.service` |

For a blank e-Paper specifically: **stop the service first** (it holds the display GPIO pins,
otherwise every driver fails with `GPIO busy`), then probe each driver:
`sudo systemctl stop bjorn && sudo python3 /home/bjorn/Bjorn/scripts/epd_test.py --all`
(restart with `sudo systemctl start bjorn` when done).

## 🛠️ Troubleshooting Steps

### Service Issues

```bash
#See bjorn journalctl service
journalctl -fu bjorn.service

# Check service status
sudo systemctl status bjorn.service

# View detailed logs
sudo journalctl -u bjorn.service -f

or

sudo tail -f /home/bjorn/Bjorn/data/logs/*


# Check port 8000 usage
sudo lsof -i :8000
```

### Display Issues

```bash
# Verify SPI devices
ls /dev/spi*

# Check user permissions
sudo usermod -a -G spi,gpio bjorn
```

### Network Issues

```bash
# Check network interfaces
ip addr show

# Test USB gadget interface
ip link show usb0
```

### Permission Issues

```bash
# Fix ownership
sudo chown -R bjorn:bjorn /home/bjorn/Bjorn

# Fix permissions
sudo chmod -R 755 /home/bjorn/Bjorn
```

---

## 📜 License

2024 - Bjorn is distributed under the MIT License. For more details, please refer to the [LICENSE](LICENSE) file included in this repository.
