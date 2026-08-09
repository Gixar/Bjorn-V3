"""telegram_report.py - auto-deliver the raw target dataset off-device (backlog Wave 2/3).

A standalone action: each cycle it compiles the target data (netkb + findings) and sends it as a
JSON document to the configured Telegram bot — falling back to SMTP when Telegram is unset or
blocked — but only when the data has actually changed since the last send (delta detection) and the
min-interval rate floor has elapsed. No-op unless telegram_enabled or smtp_enabled. All the work
lives in telegram_client.send_targets(), shared with the web "Send now" handler.
"""
import logging
from shared import SharedData
from logger import Logger
import telegram_client

logger = Logger(name="telegram_report.py", level=logging.INFO)

b_class = "TelegramReport"
b_module = "telegram_report"
b_status = "telegram_report"
b_port = 0  # standalone action
# Needs the internet: skipped entirely while Bjorn has no uplink, rather than failing
# once per offline cycle (see orchestrator.run_offline_cycle).
b_needs_internet = True
b_parent = None


class TelegramReport:
    def __init__(self, shared_data):
        self.shared_data = shared_data
        logger.info("TelegramReport initialized.")

    def execute(self):
        try:
            if not (getattr(self.shared_data, "telegram_enabled", False)
                    or getattr(self.shared_data, "smtp_enabled", False)):
                return 'skipped'
            ok, detail, sent = telegram_client.send_targets(self.shared_data, force=False)
            if not sent:
                # Nothing to send (data unchanged) or inside the rate floor — not an outcome worth
                # recording either way.
                logger.debug(f"Report not sent: {detail}")
                return 'skipped'
            if ok:
                logger.success(f"Target data delivered ({detail}).")
                return 'success'
            logger.warning(f"Report send failed: {detail}")
            return 'failed'
        except Exception as e:
            logger.error(f"Error in Telegram report: {e}")
            return 'failed'


if __name__ == "__main__":
    TelegramReport(SharedData()).execute()
