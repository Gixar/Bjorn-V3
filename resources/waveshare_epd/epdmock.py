# epdmock.py
# Null/mock e-Paper backend so Bjorn boots and runs the web UI on a non-Pi dev
# machine (testing only — not a portability target). Selected via epd_type: "mock".
# Matches the interface EPDHelper duck-types: init/Clear + getbuffer/display(Partial),
# plus width/height. No hardware imports.

import logging
import os

logger = logging.getLogger(__name__)


class EPD:
    def __init__(self):
        # Default 2.13" geometry so downstream layout math (scale factors, centering) works.
        self.width = 122
        self.height = 250
        self._frame = 0

    def init(self, *args):
        return 0

    def Clear(self, *args):
        return 0

    def getbuffer(self, image):
        # Real drivers pack the PIL image into a device buffer; the mock passes it through
        # so display() can optionally dump it for a look.
        return image

    def _dump(self, image):
        """Best-effort: write the rendered frame to data/output/mock_display.png so a dev
        can eyeball what the e-Paper would show. Never raises — display must not crash the app."""
        try:
            out = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "..", "..", "data", "output", "mock_display.png",
            )
            image.save(os.path.abspath(out))
        except Exception as e:  # pragma: no cover - purely diagnostic
            logger.debug(f"mock display dump skipped: {e}")

    def display(self, image, *args):
        if hasattr(image, "save"):
            self._dump(image)
        return 0

    def displayPartial(self, image, *args):
        return self.display(image, *args)

    def sleep(self, *args):
        return 0
