#shared.py
# Description:
# This file, shared.py, is a core component responsible for managing shared resources and data for different modules in the Bjorn project.
# It handles the initialization and configuration of paths, logging, fonts, and images. Additionally, it sets up the environment, 
# creates necessary directories and files, and manages the loading and saving of configuration settings.
# 
# Key functionalities include:
# - Initializing various paths used by the application, including directories for configuration, data, actions, web resources, and logs.
# - Setting up the environment, including the e-paper display, network knowledge base, and actions JSON configuration.
# - Loading and managing fonts and images required for the application's display.
# - Handling the creation and management of a live status file to store the current status of network scans.
# - Managing configuration settings, including loading default settings, updating, and saving configurations to a JSON file.
# - Providing utility functions for reading and writing data to CSV files, updating statistics, and wrapping text for display purposes.

import os
import re
import json
import importlib
import random
import time
import csv
import logging
import subprocess
import traceback
from PIL import Image, ImageFont
from logger import Logger
from epd_helper import EPDHelper
from config_validation import validate_config
import stats_engine


logger = Logger(name="shared.py", level=logging.DEBUG) # Create a logger object 

class SharedData:
    """Shared data between the different modules."""
    def __init__(self):
        self.initialize_paths() # Initialize the paths used by the application
        self.status_list = [] 
        self.last_comment_time = time.time() # Last time a comment was displayed
        self.default_config = self.get_default_config() # Default configuration of the application  
        self.config = self.default_config.copy() # Configuration of the application
        # Load existing configuration first
        self.load_config()

        # Update MAC blacklist without immediate save
        self.update_mac_blacklist()
        self.setup_environment() # Setup the environment
        self.initialize_variables() # Initialize the variables used by the application
        self.create_livestatusfile() 
        self.load_fonts() # Load the fonts used by the application
        self.load_images() # Load the images used by the application
        # self.create_initial_image() # Create the initial image displayed on the screen

    def initialize_paths(self):
        """Initialize the paths used by the application."""
        """Folders paths"""
        self.currentdir = os.path.dirname(os.path.abspath(__file__))
        # Directories directly under currentdir
        self.configdir = os.path.join(self.currentdir, 'config')
        self.datadir = os.path.join(self.currentdir, 'data')
        self.actions_dir = os.path.join(self.currentdir, 'actions')
        self.webdir = os.path.join(self.currentdir, 'web')
        self.resourcesdir = os.path.join(self.currentdir, 'resources')
        self.backupbasedir = os.path.join(self.currentdir, 'backup')
        # Directories under backupbasedir
        self.backupdir = os.path.join(self.backupbasedir, 'backups')
        self.upload_dir = os.path.join(self.backupbasedir, 'uploads')

        # Directories under datadir
        self.logsdir = os.path.join(self.datadir, 'logs')
        self.output_dir = os.path.join(self.datadir, 'output')
        self.input_dir = os.path.join(self.datadir, 'input')
        # Directories under output_dir
        self.crackedpwddir = os.path.join(self.output_dir, 'crackedpwd')
        self.datastolendir = os.path.join(self.output_dir, 'data_stolen')
        self.zombiesdir = os.path.join(self.output_dir, 'zombies')
        self.vulnerabilities_dir = os.path.join(self.output_dir, 'vulnerabilities')
        self.scan_results_dir = os.path.join(self.output_dir, "scan_results")
        # Handshake Hunter loot (docs/BETTERCAP_PLAN.md Stage C). Derived, not configurable: every
        # other output path is, and a configurable one is just another path to validate. The dated
        # subdirectory under raw/ is computed per capture, so it is not a fixed attribute.
        self.handshakes_dir = os.path.join(self.output_dir, "handshakes")
        # Directories under resourcesdir
        self.picdir = os.path.join(self.resourcesdir, 'images')
        self.fontdir = os.path.join(self.resourcesdir, 'fonts')
        self.commentsdir = os.path.join(self.resourcesdir, 'comments')
        # Directories under picdir
        self.statuspicdir = os.path.join(self.picdir, 'status')
        self.staticpicdir = os.path.join(self.picdir, 'static')
        # Directory under input_dir
        self.dictionarydir = os.path.join(self.input_dir, "dictionary")
        """Files paths"""
        # Files directly under configdir
        self.shared_config_json = os.path.join(self.configdir, 'shared_config.json')
        self.actions_file = os.path.join(self.configdir, 'actions.json')
        # Files directly under resourcesdir
        self.commentsfile = os.path.join(self.commentsdir, 'comments.json')
        # Files directly under datadir
        self.netkbfile = os.path.join(self.datadir, "netkb.csv")
        self.livestatusfile = os.path.join(self.datadir, 'livestatus.csv')
        # Files directly under vulnerabilities_dir
        self.vuln_summary_file = os.path.join(self.vulnerabilities_dir, 'vulnerability_summary.csv')
        self.vuln_scan_progress_file = os.path.join(self.vulnerabilities_dir, 'scan_progress.json')
        # Files directly under dictionarydir
        self.usersfile = os.path.join(self.dictionarydir, "users.txt")
        self.passwordsfile = os.path.join(self.dictionarydir, "passwords.txt")
        # Files directly under crackedpwddir
        self.sshfile = os.path.join(self.crackedpwddir, 'ssh.csv')
        self.smbfile = os.path.join(self.crackedpwddir, "smb.csv")
        self.telnetfile = os.path.join(self.crackedpwddir, "telnet.csv")
        self.ftpfile = os.path.join(self.crackedpwddir, "ftp.csv")
        self.sqlfile = os.path.join(self.crackedpwddir, "sql.csv")
        self.rdpfile = os.path.join(self.crackedpwddir, "rdp.csv")
        #Files directly under logsdir
        self.webconsolelog = os.path.join(self.logsdir, 'temp_log.txt')

    def get_default_config(self):
        """ The configuration below is used to set the default values of the configuration settings."""
        """ It can be used to reset the configuration settings to their default values."""
        """ You can mofify the json file shared_config.json or on the web page to change the default values of the configuration settings."""
        return {
            "__title_Bjorn__": "Settings",
            "manual_mode": False,
            "websrv": True,
            "debug_mode": False,
            "scan_vuln_running": False,
            "retry_success_actions": False,
            "retry_failed_actions": True,
            "blacklistcheck": True,
            "displaying_csv": True,
            "log_debug": True,
            "log_info": True,
            "log_warning": True,
            "log_error": True,
            "log_critical": True,
            
            "startup_delay": 10,
            "web_delay": 2,
            "stats_ws_interval": 2,  # seconds between /ws/stats pushes to the stats dashboard
            "screen_delay": 1,
            "comment_delaymin": 15,
            "comment_delaymax": 30,
            "comment_info_ratio": 3,   # every Nth comment slot shows live findings instead of a joke (0 = jokes only)
            "livestatus_delay": 8,
            "image_display_delaymin": 2,
            "image_display_delaymax": 8,
            "scan_interval": 180,
            "scan_vuln_interval": 900,
            "failed_retry_delay": 600,
            "success_retry_delay": 900,
            "adaptive_scan_interval": True,  # idle longer as scans stay fruitless, shorter when a retry window expires first
            "planner_max_host_actions": 4,   # host actions the planner runs per cycle (fairness window, not a cap on throughput)
            "planner_standalone_every": 3,   # force a standalone action every N cycles so recon isn't starved by host work
            "bruteforce_threads": 0,  # brute-force worker threads per connector; 0 = auto (core-aware, capped at 8)
            "credential_reuse": True,  # replay a cracked user:password across other hosts/protocols (tried first); shared pool in crackedpwd/known_creds.csv
            "wpasec_api_key": "",      # wpa-sec.stanev.org API key (secret, user-supplied); empty = wpa-sec import disabled
            "wpasec_interval": 3600,   # min seconds between wpa-sec fetches (throttle; 0 = every idle cycle)
            "ref_width" :122 ,
            "ref_height" : 250,
            "epd_type": "epd2in13_V4",

            # PG-3 battery/UPS awareness (opt-in; no-op without a PiSugar-style server).
            "battery_monitor_enabled": False,
            "battery_shutdown_percent": 10,
            
            
            "__title_lists__": "List Settings",
            "portlist": [20, 21, 22, 23, 25, 53, 69, 80, 110, 111, 135, 137, 139, 143, 161, 162, 389, 443, 445, 512, 513, 514, 587, 636, 993, 995, 1080, 1433, 1521, 2049, 3306, 3389, 5000, 5001, 5432, 5900, 8080, 8443, 9090, 10000],
            "mac_scan_blacklist": [],
            "ip_scan_blacklist": [],
            "snmp_communities": ["public", "private"],  # SNMP community strings tried by SNMPEnum (snmpget)
            "ble_scan_enabled": True,         # BLE recon via bluetoothctl — on by default: the BT radio is built into every supported Pi, needs no dongle, and is the only recon that keeps working with no uplink
            "ble_scan_duration": 10,          # seconds per BLE discovery scan
            "ble_scan_interval": 300,         # min seconds between BLE scans
            "ble_scan_interval_offline": 60,  # min seconds between BLE scans while there is NO uplink (carried around, the survey IS the work)
            "wifi_scan_enabled": True,        # 802.11 AP/client recon via airodump-ng — on by default, but a no-op unless a non-uplink radio is actually present
            "wifi_scan_iface": "",            # monitor-mode radio — MUST NOT be Bjorn's uplink (use a USB dongle)
            "wifi_scan_duration": 30,         # seconds per airodump-ng capture
            "wifi_scan_interval": 900,        # min seconds between Wi-Fi scans
            "wifi_scan_band": "bg",           # airodump --band: bg = 2.4GHz (its default), a = 5GHz, abg = both
            "wifi_scan_channel": 0,           # 0 = hop channels; a channel number locks to it (overrides band)
            "wifi_scan_interval_offline": 120,  # min seconds between Wi-Fi scans while there is NO uplink (survey is the only work left)
            "offline_mode_enabled": True,     # with no default route: pause IP scanning, run wireless recon, try to rejoin
            "offline_cycle_interval": 60,     # seconds between offline recon/reconnect cycles
            "wifi_autojoin": True,            # while offline, rejoin a saved network that comes back in range
            "wifi_autojoin_open": False,      # ALSO join open networks Bjorn has no profile for — off by default: joining someone's open AP is a posture decision, not a connectivity fix
            "telegram_enabled": False,        # auto-send raw target data to Telegram when it changes
            "telegram_bot_token": "",         # Telegram bot token (secret, user-supplied)
            "telegram_chat_id": "",           # Telegram chat/channel id to deliver to
            "telegram_min_interval": 300,     # rate floor (seconds) between auto-sends
            "telegram_include_creds": True,   # include cracked credentials in the sent dataset (third-party hop)
            "smtp_enabled": False,            # SMTP fallback channel, used when Telegram is unset or fails
            "smtp_host": "",                  # SMTP server hostname
            "smtp_port": 587,                 # 465 = implicit SSL, anything else = STARTTLS when offered
            "smtp_user": "",                  # SMTP login / From address
            "smtp_password": "",              # SMTP password (secret, user-supplied)
            "smtp_to": "",                    # recipient(s), comma-separated
            # Bettercap (docs/BETTERCAP_PLAN.md Stage B) — managed mode only: recon on the network
            # Bjorn has already joined. Entirely off until switched on; nothing is installed or
            # enabled at install time. The hunter's own keys (bettercap_pwn_*) arrive in Stage C.
            "bettercap_enabled": False,       # master switch — the poller thread AND bettercap.service
            "bettercap_api_url": "http://127.0.0.1:8081",  # api.rest endpoint; keep it on loopback
            "bettercap_user": "bjorn",        # api.rest Basic-Auth user
            "bettercap_password": "",             # api.rest Basic-Auth password (secret, generated at install)
            "bettercap_arp_spoof": False,     # active ARP spoofing (off = passive recon only)
            "bettercap_sniff": False,         # passive traffic sniff
            # Handshake Hunter (Stage C): monitor mode on a SECOND radio, during offline cycles.
            # Refuses to start on a single-radio device — it would hold the only path back online.
            "bettercap_pwn_enabled": False,   # hunt for handshakes while there is no uplink
            "bettercap_pwn_iface": "",        # radio to hunt on; blank = any non-uplink radio
            "steal_file_names": ["ssh.csv","hack.txt"],
            "steal_file_extensions": [".bjorn",".hack",".flag"],
            
            "__title_network__": "Network",
            "use_rustscan": True,        # port discovery via RustScan instead of nmap -sT — 27x faster on the Zero 2 W, same open ports; falls back to nmap if the binary is missing or a run fails
            "rustscan_batch_size": 0,    # RustScan -b socket batch; 0 = auto (memory-aware: 1500 on a Pi Zero, 4500 elsewhere)
            "rustscan_full_port": False, # RustScan sweeps all 65,535 ports (its strength) instead of the curated portlist; needs use_rustscan
            "nmap_scan_aggressivity": "-T2",
            "vuln_scan_sv": True,        # include nmap -sV (service/version detection) in the vuln scan
            "vuln_scan_vulners": True,   # run the vulners.nse CVE script (internet-dependent, heaviest step)
            "vuln_offline_cve": True,    # match -sV service versions against the bundled offline CVE DB (config/cve_signatures.json); no internet
            "portstart": 1,
            "portend": 2,
            
            "__title_timewaits__": "Time Wait Settings",
            "timewait_smb": 0,
            "timewait_ssh": 0,
            "timewait_telnet": 0,
            "timewait_ftp": 0,
            "timewait_sql": 0,
            "timewait_rdp": 0,
        }

    def update_mac_blacklist(self):
        """Update the MAC blacklist without immediate save."""
        mac_address = self.get_raspberry_mac()
        if mac_address:
            if 'mac_scan_blacklist' not in self.config:
                self.config['mac_scan_blacklist'] = []
            
            if mac_address not in self.config['mac_scan_blacklist']:
                self.config['mac_scan_blacklist'].append(mac_address)
                logger.info(f"Added local MAC address {mac_address} to blacklist")
            else:
                logger.info(f"Local MAC address {mac_address} already in blacklist")
        else:
            logger.warning("Could not add local MAC to blacklist: MAC address not found")



    def get_raspberry_mac(self):
        """Get the MAC address of the primary network interface (usually wlan0 or eth0)."""
        try:
            # First try wlan0 (wireless interface)
            result = subprocess.run(['cat', '/sys/class/net/wlan0/address'], 
                                 capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip().lower()
            
            # If wlan0 fails, try eth0 (ethernet interface)
            result = subprocess.run(['cat', '/sys/class/net/eth0/address'], 
                                 capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip().lower()
            
            logger.warning("Could not find MAC address for wlan0 or eth0")
            return None
            
        except Exception as e:
            logger.error(f"Error getting Raspberry Pi MAC address: {e}")
            return None



    def setup_environment(self):
        """Setup the environment with the necessary directories and files."""
        os.system('cls' if os.name == 'nt' else 'clear')
        self.save_config()
        self.generate_actions_json()
        self.delete_webconsolelog()
        self.initialize_csv()
        self.initialize_epd_display()
    

    # def initialize_epd_display(self):
    #     """Initialize the e-paper display."""
    #     try:
    #         logger.info("Initializing EPD display...")
    #         time.sleep(1)
    #         self.epd_helper = EPDHelper(self.config["epd_type"])
    #         self.epd_helper = EPDHelper(self.epd_type)
    #         if self.config["epd_type"] == "epd2in13_V2":
    #             logger.info("EPD type: epd2in13_V2 screen reversed")
    #             self.screen_reversed = False
    #             self.web_screen_reversed = False
    #         elif self.config["epd_type"] == "epd2in13_V3":
    #             logger.info("EPD type: epd2in13_V3 screen reversed")
    #             self.screen_reversed = False
    #             self.web_screen_reversed = False
    #         elif self.config["epd_type"] == "epd2in13_V4":
    #             logger.info("EPD type: epd2in13_V4 screen reversed")
    #             self.screen_reversed = True
    #             self.web_screen_reversed = True
    #         self.epd_helper.init_full_update()
    #         self.width, self.height = self.epd_helper.epd.width, self.epd_helper.epd.height
    #         logger.info(f"EPD {self.config['epd_type']} initialized with size: {self.width}x{self.height}")
    #     except Exception as e:
    #         logger.error(f"Error initializing EPD display: {e}")
    #         raise
    def initialize_epd_display(self):
        """Initialize the e-paper display."""
        try:
            logger.info("Initializing EPD display...")
            time.sleep(1)
            configured = self.config["epd_type"]
            if configured == "auto":
                self.epd_helper, epd_type = self._auto_detect_epd()
            else:
                epd_type = configured
                self.epd_helper = EPDHelper(epd_type)
                self.epd_helper.init_full_update()
            # Record the resolved type so the rest of the app (display, web) reads a concrete value.
            self.epd_type = epd_type
            self.config["epd_type"] = epd_type
            # V3/V4 render rotated; V2/2in7/mock do not.
            self.screen_reversed = epd_type in ("epd2in13_V3", "epd2in13_V4")
            self.web_screen_reversed = self.screen_reversed
            logger.info(f"EPD type: {epd_type} (screen_reversed={self.screen_reversed})")
            self.width, self.height = self.epd_helper.epd.width, self.epd_helper.epd.height
            logger.info(f"EPD {epd_type} initialized with size: {self.width}x{self.height}")
        except Exception as e:
            logger.error(f"Error initializing EPD display (epd_type={self.config.get('epd_type')!r}): {e}")
            logger.error(
                "Blank/absent panel checklist: (1) SPI enabled? `ls /dev/spidev*` should list a device "
                "— if not, enable it (sudo raspi-config -> Interface Options -> SPI, or add "
                "`dtparam=spi=on` to /boot/firmware/config.txt and reboot). (2) Does 'epd_type' match "
                "your HAT? (3) Run `sudo python3 scripts/epd_test.py --all` to probe each driver."
            )
            logger.error(traceback.format_exc())
            raise

    # Real-panel drivers tried, in order, when epd_type == "auto" ("mock" is never auto-picked).
    EPD_AUTODETECT_CANDIDATES = ["epd2in13_V4", "epd2in13_V3", "epd2in13_V2", "epd2in13", "epd2in7"]

    def _auto_detect_epd(self):
        """Try each candidate driver until one initializes; return (helper, epd_type).

        ponytail: init-based, not render-based. An e-Paper gives no signal that pixels actually
        appeared, so this confirms only that a driver *initialized without error* — it does NOT
        distinguish V3 from V4 (both init on the same panel). Value here is graceful degradation
        (Bjorn still boots if the configured driver errors or the HAT is absent) and first-boot
        convenience. If the auto-picked driver inits but the screen stays blank, run
        `sudo python3 scripts/epd_test.py --all` to find the one that visibly renders, then set
        that exact value as `epd_type` in config/shared_config.json.
        """
        last_error = None
        for candidate in self.EPD_AUTODETECT_CANDIDATES:
            helper = None
            try:
                logger.info(f"[epd auto] trying driver '{candidate}'...")
                helper = EPDHelper(candidate)
                helper.init_full_update()
                logger.info(f"[epd auto] selected '{candidate}' (first driver that initialized).")
                return helper, candidate
            except Exception as e:
                last_error = e
                logger.warning(f"[epd auto] '{candidate}' did not initialize: {e}")
                # Best-effort pin release so the next candidate can claim GPIO/SPI. Only reached
                # when a candidate fails; the common case (first driver works) never releases.
                if helper is not None:
                    try:
                        helper.epd.sleep()
                    except Exception:
                        pass
        raise RuntimeError(
            f"EPD auto-detect: no candidate driver initialized ({self.EPD_AUTODETECT_CANDIDATES}). "
            f"Last error: {last_error}"
        )

    @staticmethod
    def _auto_rustscan_batch(total_ram_mb=None):
        """A RustScan `-b` batch size this box can actually sustain. Pure enough to unit-test.

        Thresholds are deliberately coarse — the point is to stay well clear of the cliff, not to
        squeeze the last socket out of a Pi Zero. Anything with real memory keeps RustScan's own
        4500, so this only bites on the small boards where the failure mode actually shows up."""
        if total_ram_mb is None:
            try:
                total_ram_mb = (os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")) // (1024 ** 2)
            except (ValueError, OSError, AttributeError):
                return 4500  # not Linux / can't tell — leave RustScan's default alone
        if total_ram_mb < 640:      # Pi Zero / Zero 2 W
            return 1500
        if total_ram_mb < 1536:     # Pi 3 / Zero-class with more headroom
            return 3000
        return 4500                 # RustScan's own default

    def initialize_variables(self):
        """Initialize the variables."""
        # Resolve auto (0) brute-force thread count: core-aware, capped at 8 (IO-bound, so >cores is fine).
        if not getattr(self, "bruteforce_threads", 0):
            self.bruteforce_threads = min(8, (os.cpu_count() or 1) * 4)
        # Resolve auto (0) RustScan batch size: memory-aware. RustScan's own default is 4500
        # concurrent sockets, tuned for a laptop; a Pi Zero 2 W has ~425MB of RAM, and its
        # documented failure mode under too-aggressive batching is *silently dropped ports*, not an
        # error — so an over-large batch costs findings without ever announcing itself. Same
        # "0 = auto" contract as bruteforce_threads above; set a number to override.
        if not getattr(self, "rustscan_batch_size", 0):
            self.rustscan_batch_size = self._auto_rustscan_batch()
        self.should_exit = False
        self.display_should_exit = False
        self.orchestrator_should_exit = False 
        self.webapp_should_exit = False 
        self.bjorn_instance = None
        self.wifichanged = False
        self.bluetooth_active = False
        self.wifi_connected = False
        self.pan_connected = False
        self.usb_active = False
        self.bjornsays = "Hacking away..."
        self.bjornorch_status = "IDLE"
        self.bjornstatustext = "IDLE"
        self.bjornstatustext2 = "Awakening..."
        self.scale_factor_x = self.width / self.ref_width
        self.scale_factor_y = self.height / self.ref_height
        self.text_frame_top = int(88 * self.scale_factor_x)
        self.text_frame_bottom = int(159 * self.scale_factor_y)
        self.y_text = self.text_frame_top + 2
        self.targetnbr = 0
        self.portnbr = 0
        self.vulnnbr = 0
        self.crednbr = 0
        self.datanbr = 0
        self.zombiesnbr = 0
        self.coinnbr = 0
        self.levelnbr = 0
        self.networkkbnbr = 0
        self.attacksnbr = 0
        # Bumped once per completed network scan (scanning.py). The display threads read it to
        # skip re-parsing netkb/livestatus when nothing changed (P5). Single writer (scanner),
        # multiple readers → no lock needed; a stale read just recomputes one extra time.
        self.data_generation = 0
        self.show_first_image = True

    def delete_webconsolelog(self):
            """Delete the web console log file."""
            try:
                if os.path.exists(self.webconsolelog):
                    os.remove(self.webconsolelog)
                    logger.info(f"Deleted web console log file at {self.webconsolelog}")
                    #recreate the file

                else:
                    logger.info(f"Web console log file not found at {self.webconsolelog} ...")

            except OSError as e:
                logger.error(f"OS error occurred while deleting web console log file: {e}")
            except Exception as e:
                logger.error(f"Unexpected error occurred while deleting web console log file: {e}")

    def create_livestatusfile(self):
        """Create the live status file, it will be used to store the current status of the scan."""
        try:
            if not os.path.exists(self.livestatusfile):
                with open(self.livestatusfile, 'w', newline='') as csvfile:
                    csvwriter = csv.writer(csvfile)
                    csvwriter.writerow(['Total Open Ports', 'Alive Hosts Count', 'All Known Hosts Count', 'Vulnerabilities Count'])
                    csvwriter.writerow([0, 0, 0, 0])
                logger.info(f"Created live status file at {self.livestatusfile}")
            else:
                logger.info(f"Live status file already exists at {self.livestatusfile}")
        except OSError as e:
            logger.error(f"OS error occurred while creating live status file: {e}")
        except Exception as e:
            logger.error(f"Unexpected error occurred while creating live status file: {e}")


    def generate_actions_json(self):
        """Generate the actions JSON file, it will be used to store the actions configuration."""
        actions_dir = self.actions_dir
        actions_config = []
        try:
            for filename in os.listdir(actions_dir):
                if filename.endswith('.py') and filename != '__init__.py':
                    module_name = filename[:-3]
                    try:
                        module = importlib.import_module(f'actions.{module_name}')
                        b_class = getattr(module, 'b_class')
                        b_status = getattr(module, 'b_status')
                        b_port = getattr(module, 'b_port', None)
                        b_parent = getattr(module, 'b_parent', None)
                        actions_config.append({
                            "b_module": module_name,
                            "b_class": b_class,
                            "b_port": b_port,
                            "b_status": b_status,
                            "b_parent": b_parent
                        })
                        #add each b_class to the status list
                        self.status_list.append(b_class)
                    except AttributeError as e:
                        logger.error(f"Module {module_name} is missing required attributes: {e}")
                    except ImportError as e:
                        logger.error(f"Error importing module {module_name}: {e}")
                    except Exception as e:
                        logger.error(f"Unexpected error while processing module {module_name}: {e}")
            
            try:
                with open(self.actions_file, 'w') as file:
                    json.dump(actions_config, file, indent=4)
            except IOError as e:
                logger.error(f"Error writing to file {self.actions_file}: {e}")
            except Exception as e:
                logger.error(f"Unexpected error while writing to file {self.actions_file}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error in generate_actions_json: {e}")


    def initialize_csv(self):
        """Initialize the network knowledge base CSV file with headers."""
        logger.info("Initializing the network knowledge base CSV file with headers")
        try:
            if not os.path.exists(self.netkbfile):
                try:
                    with open(self.actions_file, 'r') as file:
                        actions = json.load(file)
                    action_names = [action["b_class"] for action in actions if "b_class" in action]
                except FileNotFoundError as e:
                    logger.error(f"Actions file not found: {e}")
                    return
                except json.JSONDecodeError as e:
                    logger.error(f"Error decoding JSON from actions file: {e}")
                    return
                except Exception as e:
                    logger.error(f"Unexpected error reading actions file: {e}")
                    return

                headers = ["MAC Address", "IPs", "Hostnames", "Alive", "Ports"] + action_names

                try:
                    with open(self.netkbfile, 'w', newline='') as file:
                        writer = csv.writer(file)
                        writer.writerow(headers)
                    logger.info(f"Network knowledge base CSV file created at {self.netkbfile}")
                except IOError as e:
                    logger.error(f"Error writing to netkbfile: {e}")
                except Exception as e:
                    logger.error(f"Unexpected error while writing to netkbfile: {e}")
            else:
                logger.info(f"Network knowledge base CSV file already exists at {self.netkbfile}")
        except Exception as e:
            logger.error(f"Unexpected error in initialize_csv: {e}")


    def load_config(self):
        """Load the configuration from the shared configuration JSON file."""
        try:
            logger.info("Loading configuration...")
            if os.path.exists(self.shared_config_json):
                with open(self.shared_config_json, 'r') as f:
                    config = json.load(f)
                self.config.update(config)
                validate_config(self.config)  # fail fast on a bad config before setup runs
                for key, value in self.config.items():
                    setattr(self, key, value)
                # Persist any default keys the saved file predates. The merge above has always
                # been in-memory only, so everything that reads the *file* — the web /load_config
                # form, save_configuration() — saw an incomplete config: a key added by an upgrade
                # stayed invisible in the UI until some unrelated save happened to rewrite the
                # file. Writing it back also restores the canonical key order (self.config starts
                # as a copy of the defaults), keeping the form's section titles grouped.
                # One write per upgrade, not per boot.
                missing = [k for k in self.config if k not in config]
                if missing:
                    logger.info(f"Config file missing {len(missing)} default key(s) {missing}; "
                                "writing the merged configuration back.")
                    self.save_config()
            else:
                logger.warning("Configuration file not found, creating new one with default values...")
                self.save_config()
                self.load_config()
                time.sleep(2)
        except FileNotFoundError:
            logger.error("Error loading configuration: File not found.")
            self.save_config()

    def save_config(self):
        """Save the configuration to the shared configuration JSON file."""
        logger.info("Saving configuration...")
        try:
            if not os.path.exists(self.configdir):
                os.makedirs(self.configdir)
                logger.info(f"Created configuration directory at {self.configdir}")
            try:
                with open(self.shared_config_json, 'w') as f:
                    json.dump(self.config, f, indent=4)
                logger.info(f"Configuration saved to {self.shared_config_json}")
            except IOError as e:
                logger.error(f"Error writing to configuration file: {e}")
            except Exception as e:
                logger.error(f"Unexpected error while writing to configuration file: {e}")
        except OSError as e:
            logger.error(f"OS error while creating configuration directory: {e}")
        except Exception as e:
            logger.error(f"Unexpected error in save_config: {e}")

    def load_fonts(self):
        """Load the fonts."""
        try:
            logger.info("Loading fonts...")
            self.font_arial14 = self.load_font('Arial.ttf', 14)
            self.font_arial11 = self.load_font('Arial.ttf', 11)
            self.font_arial9 = self.load_font('Arial.ttf', 9)
            self.font_arialbold = self.load_font('Arial.ttf', 12)
            self.font_viking = self.load_font('Viking.TTF', 13)

        except Exception as e:
            logger.error(f"Error loading fonts: {e}")
            raise

    def load_font(self, font_name, size):
        """Load a font."""
        try:
            return ImageFont.truetype(os.path.join(self.fontdir, font_name), size)
        except Exception as e:
            logger.error(f"Error loading font {font_name}: {e}")
            raise

    def load_images(self):
        """Load the images for the e-paper display."""
        try:
            logger.info("Loading images...")

            # Load static images from the root of staticpicdir
            self.bjornstatusimage = None
            self.bjorn1 = self.load_image(os.path.join(self.staticpicdir, 'bjorn1.bmp')) # Used to calculate the center of the screen
            self.port = self.load_image(os.path.join(self.staticpicdir, 'port.bmp'))
            self.frise = self.load_image(os.path.join(self.staticpicdir, 'frise.bmp'))
            self.target = self.load_image(os.path.join(self.staticpicdir, 'target.bmp'))
            self.vuln = self.load_image(os.path.join(self.staticpicdir, 'vuln.bmp'))
            self.connected = self.load_image(os.path.join(self.staticpicdir, 'connected.bmp'))
            self.bluetooth = self.load_image(os.path.join(self.staticpicdir, 'bluetooth.bmp'))
            self.wifi = self.load_image(os.path.join(self.staticpicdir, 'wifi.bmp'))
            self.ethernet = self.load_image(os.path.join(self.staticpicdir, 'ethernet.bmp'))
            self.usb = self.load_image(os.path.join(self.staticpicdir, 'usb.bmp'))
            self.level = self.load_image(os.path.join(self.staticpicdir, 'level.bmp'))
            self.cred = self.load_image(os.path.join(self.staticpicdir, 'cred.bmp'))
            self.attack = self.load_image(os.path.join(self.staticpicdir, 'attack.bmp'))
            self.attacks = self.load_image(os.path.join(self.staticpicdir, 'attacks.bmp'))
            self.gold = self.load_image(os.path.join(self.staticpicdir, 'gold.bmp'))
            self.networkkb = self.load_image(os.path.join(self.staticpicdir, 'networkkb.bmp'))
            self.zombie = self.load_image(os.path.join(self.staticpicdir, 'zombie.bmp'))
            self.data = self.load_image(os.path.join(self.staticpicdir, 'data.bmp'))
            self.money = self.load_image(os.path.join(self.staticpicdir, 'money.bmp'))
            self.zombie_status = self.load_image(os.path.join(self.staticpicdir, 'zombie.bmp'))
            self.attack = self.load_image(os.path.join(self.staticpicdir, 'attack.bmp'))

            """ Load the images for the different actions status"""
            # Dynamically load status images based on actions.json
            try:
                with open(self.actions_file, 'r') as f:
                    actions = json.load(f)
                    for action in actions:
                        b_class = action.get('b_class')
                        if b_class:
                            indiv_status_path = os.path.join(self.statuspicdir, b_class)
                            image_path = os.path.join(indiv_status_path, f'{b_class}.bmp')
                            image = self.load_image(image_path)
                            setattr(self, b_class, image)
                            logger.info(f"Loaded image for {b_class} from {image_path}")
            except Exception as e:
                logger.error(f"Error loading images from actions file: {e}")

            # Load image series dynamically from subdirectories
            self.image_series = {}
            for status in self.status_list:
                self.image_series[status] = []
                status_dir = os.path.join(self.statuspicdir, status)
                if not os.path.isdir(status_dir):
                    os.makedirs(status_dir)
                    logger.warning(f"Directory {status_dir} did not exist and was created.")
                    logger.warning(f" {status} wil use the IDLE images till you add some images in the {status} folder")

                for image_name in os.listdir(status_dir):
                    if image_name.endswith('.bmp') and re.search(r'\d', image_name):
                        image = self.load_image(os.path.join(status_dir, image_name))
                        if image:
                            self.image_series[status].append(image)

            if not self.image_series:
                logger.error("No images loaded.")
            else:
                for status, images in self.image_series.items():
                    logger.info(f"Loaded {len(images)} images for status {status}.")


            """Calculate the position of the Bjorn image on the screen to center it"""
            self.x_center1 = (self.width - self.bjorn1.width) // 2
            self.y_bottom1 = self.height - self.bjorn1.height

        except Exception as e:
            logger.error(f"Error loading images: {e}")
            raise

    def update_bjornstatus(self):
        """ Using getattr to obtain the reference of the attribute with the name stored in self.bjornorch_status"""
        try:
            self.bjornstatusimage = getattr(self, self.bjornorch_status)
            if self.bjornstatusimage is None:
                raise AttributeError
        except AttributeError:
            logger.warning(f"The image for status {self.bjornorch_status} is not available, using IDLE image by default.")
            self.bjornstatusimage = self.attack
        
        self.bjornstatustext = self.bjornorch_status  # Mettre à jour le texte du statut


    def load_image(self, image_path):

        """Load an image."""
        try:
            if not os.path.exists(image_path):
                logger.warning(f"Warning: {image_path} does not exist.")
                return None
            return Image.open(image_path)
        except Exception as e:
            logger.error(f"Error loading image {image_path}: {e}")
            raise

    def update_image_randomizer(self):
        """Update the image randomizer and the imagegen variable."""
        try:
            status = self.bjornstatustext
            if status in self.image_series and self.image_series[status]:
                random_index = random.randint(0, len(self.image_series[status]) - 1)
                self.imagegen = self.image_series[status][random_index]
                self.x_center = (self.width - self.imagegen.width) // 2
                self.y_bottom = self.height - self.imagegen.height
            else:
                logger.warning(f"Warning: No images available for status {status}, defaulting to IDLE images.")
                if "IDLE" in self.image_series and self.image_series["IDLE"]:
                    random_index = random.randint(0, len(self.image_series["IDLE"]) - 1)
                    self.imagegen = self.image_series["IDLE"][random_index]
                    self.x_center = (self.width - self.imagegen.width) // 2
                    self.y_bottom = self.height - self.imagegen.height
                else:
                    logger.error("No IDLE images available either.")
                    self.imagegen = None
        except Exception as e:
            logger.error(f"Error updating image randomizer: {e}")
            raise

    def wrap_text(self, text, font, max_width):
        """Wrap text to fit within a specified width when rendered."""
        try:
            lines = []
            words = text.split()
            while words:
                line = ''
                while words and font.getlength(line + words[0]) <= max_width:
                    line = line + (words.pop(0) + ' ')
                lines.append(line)
            return lines
        except Exception as e:
            logger.error(f"Error wrapping text: {e}")
            raise


    def read_data(self):
        """Read data from the CSV file."""
        self.initialize_csv()  # Ensure CSV is initialized with correct headers
        data = []
        with open(self.netkbfile, 'r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                data.append(row)
        return data

    def write_data(self, data):
        """Write data to the CSV file."""
        with open(self.actions_file, 'r') as file:
            actions = json.load(file)
        action_names = [action["b_class"] for action in actions if "b_class" in action]

        # Read existing CSV file if it exists
        if os.path.exists(self.netkbfile):
            with open(self.netkbfile, 'r') as file:
                reader = csv.DictReader(file)
                existing_headers = reader.fieldnames
                existing_data = list(reader)
        else:
            existing_headers = []
            existing_data = []

        # Check for missing action columns and add them
        new_headers = ["MAC Address", "IPs", "Hostnames", "Alive", "Ports"] + action_names
        missing_headers = [header for header in new_headers if header not in existing_headers]

        # Update headers
        headers = existing_headers + missing_headers

        # Merge new data with existing data
        mac_to_existing_row = {row["MAC Address"]: row for row in existing_data}

        for new_row in data:
            mac_address = new_row["MAC Address"]
            if mac_address in mac_to_existing_row:
                # Update the existing row with new data
                existing_row = mac_to_existing_row[mac_address]
                for key, value in new_row.items():
                    if value:
                        existing_row[key] = value
            else:
                # Add new row
                mac_to_existing_row[mac_address] = new_row

        # PG-2 (SD-card protection): write to a temp file in the same dir, then os.replace().
        # os.replace is atomic on POSIX, so a power loss mid-write leaves netkb.csv either fully
        # old or fully new — never a half-written, corrupt CSV (this file is rewritten on every
        # action, so it's the most exposed to a yanked-plug corruption).
        tmpfile = self.netkbfile + '.tmp'
        with open(tmpfile, 'w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=headers)
            writer.writeheader()
            for row in mac_to_existing_row.values():
                writer.writerow(row)
            file.flush()
            os.fsync(file.fileno())  # force bytes to the SD before the rename
        os.replace(tmpfile, self.netkbfile)

    def update_stats(self):
        """Coins/level are a monotonic, persisted high-water-mark score (see stats_engine /
        docs/COINS_STATS_PLAN.md), not a live recompute — so the score never drops when a count
        falls (netkb cleaned, hosts offline) and survives restarts. Called only from the display
        thread (single writer)."""
        counts = {
            "hosts": self.networkkbnbr, "creds": self.crednbr, "data": self.datanbr,
            "zombies": self.zombiesnbr, "attacks": self.attacksnbr, "vulns": self.vulnnbr,
        }
        result = stats_engine.update(os.path.join(self.datadir, "stats.json"), counts)
        self.coinnbr = result["coins"]
        self.levelnbr = result["level"]
        self._stats_breakdown = result["breakdown"]  # exposed via utils.get_stats_snapshot


    def print(self, message):
        """Print a debug message if debug mode is enabled."""
        if self.config['debug_mode']:
            logger.debug(message)


# ---------------------------------------------------------------------------
# Small stdlib-CSV helpers (P2): the connectors + display only read/count/dedupe
# netkb and creds files. Doing that with the `csv` module avoids importing pandas
# (~2-5s + 50-80MB on a Pi Zero) in the always-loaded scan/attack path.
# ---------------------------------------------------------------------------
def netkb_targets(netkbfile, port):
    """Rows from netkb whose Ports field contains str(port).

    Substring match, matching the old pandas `Ports.str.contains(port, na=False)`.
    Returns a list of dict rows (csv.DictReader); [] if the file is missing.
    """
    port_s = str(port)
    rows = []
    try:
        with open(netkbfile, newline='') as f:
            for row in csv.DictReader(f):
                if port_s in (row.get("Ports") or ""):
                    rows.append(row)
    except FileNotFoundError:
        pass
    return rows


def append_csv_rows(path, rows):
    """Append list-of-list rows to a CSV (no header — the file is created with one)."""
    with open(path, "a", newline='') as f:
        csv.writer(f).writerows(rows)


def dedupe_csv(path):
    """Drop duplicate rows from a CSV in place, keeping first-occurrence order (incl. header).

    Equivalent to the old `pd.read_csv(...).drop_duplicates().to_csv(...)`.
    """
    with open(path, newline='') as f:
        rows = list(csv.reader(f))
    seen = set()
    unique = []
    for row in rows:
        key = tuple(row)
        if key not in seen:
            seen.add(key)
            unique.append(row)
    with open(path, "w", newline='') as f:
        csv.writer(f).writerows(unique)


# Credential reuse / lateral chaining (backlog Wave 1 #2). The pool helpers live in the
# dependency-free credential_pool module (unit-testable without SharedData); re-exported here so
# the connectors keep importing them from `shared`.
from credential_pool import known_cred_pairs, record_cracked_cred, credential_candidates  # noqa: E402,F401
