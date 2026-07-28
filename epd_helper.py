# epd_helper.py
# Loads a Waveshare e-Paper driver by name (config `epd_type`) and wraps init/clear/display.
# Uses Bjorn's Logger so display errors land in data/logs/ alongside everything else, with a
# full traceback — a blank panel is almost always a driver/SPI/wiring failure that shows here.

import importlib
import logging
import traceback

# Prefer Bjorn's Logger (rich console + rotating files in data/logs/) so display errors surface
# alongside everything else. Fall back to stdlib logging where rich/Logger isn't available
# (dev box, unit tests) so this module stays importable without hardware deps.
try:
    from logger import Logger
    logger = Logger(name="epd_helper.py", level=logging.DEBUG)
except Exception:
    logger = logging.getLogger("epd_helper")


class EPDHelper:
    def __init__(self, epd_type):
        self.epd_type = epd_type
        self.epd = self._load_epd_module()

    def _load_epd_module(self):
        epd_module_name = f'resources.waveshare_epd.{self.epd_type}'
        logger.info(f"Loading EPD driver: {epd_module_name}")
        try:
            epd_module = importlib.import_module(epd_module_name)
            epd = epd_module.EPD()
            width = getattr(epd, 'width', '?')
            height = getattr(epd, 'height', '?')
            logger.info(f"EPD driver '{self.epd_type}' loaded (declared size {width}x{height}).")
            return epd
        except ImportError as e:
            logger.error(f"EPD module '{self.epd_type}' not found: {e}. "
                         f"Check 'epd_type' in config/shared_config.json — it must match a driver "
                         f"in resources/waveshare_epd/ and your actual HAT.")
            logger.error(traceback.format_exc())
            raise
        except Exception as e:
            logger.error(f"Error constructing EPD driver '{self.epd_type}': {e}")
            logger.error(traceback.format_exc())
            raise

    def init_full_update(self):
        try:
            logger.info(f"Initializing EPD '{self.epd_type}' (full update)...")
            if hasattr(self.epd, 'FULL_UPDATE'):
                self.epd.init(self.epd.FULL_UPDATE)
            elif hasattr(self.epd, 'lut_full_update'):
                self.epd.init(self.epd.lut_full_update)
            else:
                self.epd.init()
            logger.info("EPD full update initialization complete.")
        except Exception as e:
            logger.error(f"Error initializing EPD '{self.epd_type}' for full update: {e}")
            logger.error(traceback.format_exc())
            raise

    def init_partial_update(self):
        # Called on every refresh — log only failures, never per-frame success (that produced
        # ~3 log lines/second → log bloat + needless SD writes; cf. PG-2 SD-protection).
        try:
            if hasattr(self.epd, 'PART_UPDATE'):
                self.epd.init(self.epd.PART_UPDATE)
            elif hasattr(self.epd, 'lut_partial_update'):
                self.epd.init(self.epd.lut_partial_update)
            else:
                self.epd.init()
        except Exception as e:
            logger.error(f"Error initializing EPD '{self.epd_type}' for partial update: {e}")
            logger.error(traceback.format_exc())
            raise

    def display_partial(self, image):
        # Per-frame — failures only (see init_partial_update note).
        try:
            if hasattr(self.epd, 'displayPartial'):
                self.epd.displayPartial(self.epd.getbuffer(image))
            else:
                self.epd.display(self.epd.getbuffer(image))
        except Exception as e:
            logger.error(f"Error during partial display update on '{self.epd_type}': {e}")
            logger.error(traceback.format_exc())
            raise

    def clear(self):
        try:
            self.epd.Clear()
            logger.info("EPD cleared.")
        except Exception as e:
            logger.error(f"Error clearing EPD '{self.epd_type}': {e}")
            logger.error(traceback.format_exc())
            raise
