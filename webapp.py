#webapp.py
#
# MIGRATION NOTE (webapp v3):
# Rewritten from a raw `http.server.SimpleHTTPRequestHandler` + single-threaded
# `socketserver.TCPServer` to FastAPI + Uvicorn. It runs a Uvicorn server on its own asyncio
# event loop inside a background thread (WebThread below) — this keeps the exact shape Bjorn.py
# already expects (a `web_thread` object with .start()/.is_alive()/.join(), started once at
# boot) and, critically, keeps the web server in the SAME PROCESS as the orchestrator and
# display threads, so it still reads/writes the same in-memory `shared_data` singleton directly
# — no IPC, no second process, nothing else about Bjorn.py needs to change.
#
# From a browser's point of view, every existing route behaves the same, with two exceptions:
#   1. utils.py: serve_favicon() had a real path bug (documented there) — now fixed.
#   2. New: GET /api/stats + WebSocket /ws/stats + GET /stats.html for the live stats
#      dashboard (the coinnbr/levelnbr/vulnnbr/... numbers already computed in shared.py's
#      update_stats() but never previously exposed anywhere off the e-Paper image).
#
# SECURITY NOTE found during the migration: the old do_GET() fell through to
# `super().do_GET()` (SimpleHTTPRequestHandler's default) for any unmatched path, which serves
# files relative to the process's working directory. Since Bjorn runs from inside the repo
# root, an unmatched request like GET /shared_config.json or GET /requirements.txt would have
# been served directly by the stdlib handler. This version has no such fallback: unmatched
# paths get a 404, and the only static assets served are the ones explicitly mounted under
# /web (css/js/images) — nothing outside that directory is reachable.

import asyncio
import logging
import os
import signal
import sys
import threading

import uvicorn
from fastapi import FastAPI, Request, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel

from logger import Logger
from init_shared import shared_data
from utils import WebUtils

# Initialize the logger
logger = Logger(name="webapp.py", level=logging.DEBUG)

web_utils = WebUtils(shared_data, logger)

app = FastAPI(title="Bjorn", docs_url="/api/docs", redoc_url="/api/redoc")
# GZip everything over ~1KB — replaces the old per-page manual gzip_encode()/serve_file_gzipped().
app.add_middleware(GZipMiddleware, minimum_size=1024)

# Static assets: css/js/images, referenced from every page as "web/..." or "/web/...".
app.mount("/web", StaticFiles(directory=shared_data.webdir), name="web")


# ---------------------------------------------------------------------------
# Request bodies — free validation via Pydantic, replacing the manual json.loads(...) +
# KeyError handling that used to live inline in each handler.
# ---------------------------------------------------------------------------
class WifiCredentials(BaseModel):
    ssid: str
    password: str
    # Optional static IPv4. When ip_address is set (CIDR, e.g. 192.168.1.50/24) the
    # connection uses method=manual; left blank it stays DHCP (method=auto) as before.
    ip_address: str = ""
    gateway: str = ""
    dns: str = ""


class ManualAttackRequest(BaseModel):
    ip: str
    port: str
    action: str


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
_PAGES = {
    "index", "config", "actions", "network", "netkb",
    "bjorn", "loot", "credentials",
    "stats",  # new — live stats dashboard
    "logs",   # new — dedicated log viewer
    "telegram",  # new — Telegram reporting config + test/send
    "ble",       # new — BLE recon config + results
    "wifi",      # new — Wi-Fi (airodump-ng) recon config + results
    "bettercap", # new — Bettercap daemon config + live status
    "help",      # new — usage + configuration manual (static, no API)
}


def _page(filename):
    return FileResponse(os.path.join(shared_data.webdir, filename), media_type="text/html")


@app.get("/")
@app.get("/index.html")
def index():
    return _page("index.html")


@app.get("/{page_name}.html")
def serve_page(page_name: str):
    if page_name not in _PAGES:
        return Response(status_code=404)
    return _page(f"{page_name}.html")


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
@app.get("/load_config")
def load_config():
    return web_utils.serve_current_config()


@app.get("/restore_default_config")
def restore_default_config():
    return web_utils.restore_default_config()


@app.get("/ble_data")
def ble_data():
    return web_utils.serve_ble_data()


@app.get("/wifi_data")
def wifi_data():
    return web_utils.serve_wifi_data()


@app.get("/wifi_ifaces")
def wifi_ifaces():
    return web_utils.wifi_ifaces()


@app.post("/wifi_scan_now")
def wifi_scan_now():
    return web_utils.wifi_scan_now()


@app.post("/wifi_monitor_test")
async def wifi_monitor_test(request: Request):
    body = await request.json()
    return web_utils.wifi_monitor_test((body.get("iface") or "").strip())


@app.get("/bettercap_status")
def bettercap_status():
    return web_utils.bettercap_status()


@app.post("/bettercap_hunt_now")
def bettercap_hunt_now():
    return web_utils.hunt_now()


@app.get("/download_handshakes")
def download_handshakes():
    return web_utils.download_handshakes()


@app.post("/telegram_test")
def telegram_test():
    return web_utils.telegram_test()


@app.post("/telegram_send")
def telegram_send():
    return web_utils.telegram_send()


@app.post("/save_config")
async def save_config(request: Request):
    params = await request.json()
    return web_utils.save_configuration(params)


@app.get("/get_web_delay")
def get_web_delay():
    return JSONResponse({"web_delay": shared_data.web_delay})


@app.post("/run_benchmark")
def run_benchmark():
    return web_utils.run_benchmark()


@app.get("/benchmark_results")
def benchmark_results():
    return web_utils.benchmark_results()


# ---------------------------------------------------------------------------
# Wi-Fi
# ---------------------------------------------------------------------------
@app.get("/scan_wifi")
def scan_wifi():
    return web_utils.scan_wifi()


@app.post("/connect_wifi")
def connect_wifi(body: WifiCredentials):
    response = web_utils.connect_wifi(body.model_dump())
    # Matches the original behavior: wifichanged is set unconditionally after the call,
    # even if connect_wifi() itself failed internally and returned an error response.
    shared_data.wifichanged = True
    return response


@app.post("/disconnect_wifi")
def disconnect_wifi():
    return web_utils.disconnect_and_clear_wifi()


# ---------------------------------------------------------------------------
# Network / NetKB data
# ---------------------------------------------------------------------------
@app.get("/network_data")
def network_data():
    return web_utils.serve_network_data()


@app.get("/module_files/{group}")
def module_files(group: str):
    return web_utils.serve_module_files(group)


@app.get("/module_file/{group}/{key}")
def module_file(group: str, key: str, download: int = 0):
    return web_utils.serve_module_file(group, key, download=bool(download))


@app.get("/netkb_data")
def netkb_data():
    return web_utils.serve_netkb_data()


@app.get("/netkb_data_json")
def netkb_data_json():
    return web_utils.serve_netkb_data_json()


# ---------------------------------------------------------------------------
# Stats dashboard (new)
# ---------------------------------------------------------------------------
@app.get("/api/stats")
def api_stats():
    return JSONResponse(web_utils.get_stats_snapshot())


@app.websocket("/ws/stats")
async def ws_stats(websocket: WebSocket):
    await websocket.accept()
    # Config-tunable push interval (config/shared_config.json: "stats_ws_interval"), falls
    # back to 2s if the key isn't present (e.g. an older config that predates this feature).
    interval = getattr(shared_data, "stats_ws_interval", 2)
    try:
        while True:
            await websocket.send_json(web_utils.get_stats_snapshot())
            await asyncio.sleep(interval)
    except WebSocketDisconnect:
        pass


# ---------------------------------------------------------------------------
# Assets served at root (browsers request these exact paths regardless of current page)
# ---------------------------------------------------------------------------
@app.get("/screen.png")
def screen_png():
    return web_utils.serve_image()


@app.get("/favicon.ico")
def favicon():
    return web_utils.serve_favicon()


@app.get("/manifest.json")
def manifest():
    return web_utils.serve_manifest()


@app.get("/apple-touch-icon")
def apple_touch_icon():
    return web_utils.serve_apple_touch_icon()


# ---------------------------------------------------------------------------
# Logs / credentials / loot files
# ---------------------------------------------------------------------------
@app.get("/get_logs")
def get_logs():
    return web_utils.serve_logs()


@app.get("/list_credentials")
def list_credentials():
    return web_utils.serve_credentials_data()


@app.get("/list_files")
def list_files():
    return web_utils.list_files_endpoint()


@app.get("/download_file")
def download_file(path: str):
    return web_utils.download_file(path)


@app.get("/download_backup")
def download_backup(filename: str):
    return web_utils.download_backup(filename)


# ---------------------------------------------------------------------------
# System / housekeeping actions
# ---------------------------------------------------------------------------
@app.post("/clear_files")
def clear_files():
    return web_utils.clear_files()


@app.post("/clear_files_light")
def clear_files_light():
    return web_utils.clear_files_light()


@app.post("/initialize_csv")
def initialize_csv():
    return web_utils.initialize_csv()


@app.post("/reboot")
def reboot():
    return web_utils.reboot_system()


@app.post("/shutdown")
def shutdown():
    return web_utils.shutdown_system()


@app.post("/restart_bjorn_service")
def restart_bjorn_service():
    return web_utils.restart_bjorn_service()


@app.post("/backup")
def backup():
    return web_utils.backup()


@app.post("/restore")
async def restore(file: UploadFile = File(...)):
    return await web_utils.restore(file)


@app.post("/stop_orchestrator")
def stop_orchestrator():
    return web_utils.stop_orchestrator()


@app.post("/start_orchestrator")
def start_orchestrator():
    return web_utils.start_orchestrator()


@app.post("/execute_manual_attack")
def execute_manual_attack(body: ManualAttackRequest):
    return web_utils.execute_manual_attack(body.model_dump())


# ---------------------------------------------------------------------------
# Thread wrapper — drop-in replacement for the old WebThread(threading.Thread) so Bjorn.py
# doesn't need to change. Runs a Uvicorn server on its own asyncio event loop inside this
# thread, in the SAME process as the orchestrator/display threads (see migration note at top).
# ---------------------------------------------------------------------------
class WebThread(threading.Thread):
    """Thread to run the FastAPI/Uvicorn web server serving the EPD display interface."""

    def __init__(self, port=8000):
        super().__init__(daemon=True)
        self.shared_data = shared_data
        self.port = port
        self._loop = None
        config = uvicorn.Config(
            app,
            host="0.0.0.0",
            port=self.port,
            log_level="warning",  # webapp.py's own Logger already handles app-level logging
            loop="asyncio",
        )
        self.server = uvicorn.Server(config)
        # Note: no manual "port + 1 on conflict" retry loop here (the old TCPServer version
        # bumped 8000 -> 8001 -> ... on "Address already in use"). asyncio's loop.create_server()
        # sets SO_REUSEADDR by default on POSIX (unlike socketserver.TCPServer, which is why the
        # old code needed the separate ReusableTCPServer/allow_reuse_address fix for issue #16),
        # so a quick restart reclaims :8000 immediately instead of drifting to the next port.

    def run(self):
        """Run the Uvicorn server in this thread's own event loop."""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            logger.info(f"Serving at port {self.port}")
            self._loop.run_until_complete(self.server.serve())
        except Exception as e:
            logger.error(f"Error in web server: {e}")
        finally:
            self._loop.close()
            logger.info("Web server closed.")

    def shutdown(self):
        """Shutdown the web server gracefully."""
        if self.server:
            self.server.should_exit = True


def handle_exit_web(signum, frame):
    """Handle exit signals to shutdown the web server cleanly."""
    shared_data.webapp_should_exit = True
    if web_thread.is_alive():
        web_thread.shutdown()
        web_thread.join()
    logger.info("Server shutting down...")
    sys.exit(0)


# Initialize the web thread
web_thread = WebThread(port=8000)

# Set up signal handling for graceful shutdown
signal.signal(signal.SIGINT, handle_exit_web)
signal.signal(signal.SIGTERM, handle_exit_web)

if __name__ == "__main__":
    try:
        # Start the web server thread
        web_thread.start()
        logger.info("Web server thread started.")
    except Exception as e:
        logger.error(f"An exception occurred during web server start: {e}")
        handle_exit_web(signal.SIGINT, None)
        sys.exit(1)
