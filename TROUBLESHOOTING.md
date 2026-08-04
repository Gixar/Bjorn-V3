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

## 🩺 Start here: `bjorn_doctor.sh` (central diagnostics)

One read-only command gathers everything into a single report — version, hardware (SPI),
service status, recent errors from **all** log locations, and a map of where every log and
output file lives. It works even when Bjorn won't start.

```bash
sudo /home/bjorn/Bjorn/scripts/bjorn_doctor.sh
# save it to share/attach:
sudo /home/bjorn/Bjorn/scripts/bjorn_doctor.sh > /tmp/bjorn_report.txt
```

Where Bjorn leaves things (the doctor prints this too):

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
