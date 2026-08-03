"""telegram_report.py - auto-deliver the raw target dataset to Telegram (backlog Wave 2).

A standalone action: each cycle it compiles the target data (netkb + findings) and sends it as a
JSON document to the configured bot — but only when the data has actually changed since the last
send (delta detection) and the min-interval rate floor has elapsed. No-op unless telegram_enabled
and a bot token + chat id are set. All the work lives in telegram_client.send_targets(), shared with
the web "Send now" handler.
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
b_parent = None


class TelegramReport:
    def __init__(self, shared_data):
        self.shared_data = shared_data
        logger.info("TelegramReport initialized.")

    def execute(self):
        try:
            if not getattr(self.shared_data, "telegram_enabled", False):
                return 'success'
            ok, detail, sent = telegram_client.send_targets(self.shared_data, force=False)
            if sent and ok:
                logger.success(f"Telegram: target data sent ({detail}).")
            elif not ok:
                logger.warning(f"Telegram send skipped/failed: {detail}")
            return 'success'
        except Exception as e:
            logger.error(f"Error in Telegram report: {e}")
            return 'failed'


if __name__ == "__main__":
    TelegramReport(SharedData()).execute()
