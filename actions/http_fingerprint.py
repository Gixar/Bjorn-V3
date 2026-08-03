"""http_fingerprint.py - HTTP(S) service fingerprinting (backlog Wave 2, PRD P3-5).

A per-host recon action: for a live host with a web port open, GET each web port and record the
status, Server / X-Powered-By headers, and page <title>. Results land in
data/output/scan_results/http_fingerprints.csv — a map of what web tech is on the LAN, and the
feed for the planned nuclei-style templated checks (next Wave 2 item).

Registered on b_port=80 so it triggers on any host exposing :80, then fingerprints *all* of that
host's open web ports in one execute(). Stdlib only (urllib) — no new dependency.
ponytail: b_port=80 misses hosts that expose 443 but not 80; add an https-only sibling module if
that gap matters in practice.
"""
import os
import re
import ssl
import csv
import logging
import urllib.error
import urllib.request
from shared import SharedData
from logger import Logger
from csv_safe import sanitize_row

logger = Logger(name="http_fingerprint.py", level=logging.INFO)

b_class = "HTTPFingerprint"
b_module = "http_fingerprint"
b_status = "http_fingerprint"
b_port = 80
b_parent = None

# open web ports we probe -> is it TLS
WEB_PORTS = {"80": False, "443": True, "8080": False, "8443": True,
             "8000": False, "8888": False, "9090": False}


class HTTPFingerprint:
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.outfile = os.path.join(shared_data.scan_results_dir, "http_fingerprints.csv")
        logger.info("HTTPFingerprint initialized.")

    def execute(self, ip, port, row, status_key):
        self.shared_data.bjornorch_status = "HTTPFingerprint"
        targets = self._web_ports([p for p in row.get("Ports", "").split(";") if p])
        if not targets:
            return 'failed'
        hostname = row.get("Hostnames", "")
        rows = []
        for web_port, tls in targets:
            info = self._fingerprint_one(ip, web_port, tls)
            if info:
                rows.append([ip, hostname, web_port, info["status"], info["server"],
                             info["powered_by"], info["title"], info["url"]])
        if not rows:
            return 'failed'
        self._save(rows)
        logger.success(f"HTTP fingerprint: {ip} -> {len(rows)} web service(s)")
        return 'success'

    @staticmethod
    def _web_ports(host_ports):
        """[(port, is_tls)] for the host's open web ports, in WEB_PORTS order (stable)."""
        return [(p, WEB_PORTS[p]) for p in WEB_PORTS if p in host_ports]

    @staticmethod
    def _extract_title(body):
        m = re.search(r'<title[^>]*>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
        return re.sub(r'\s+', ' ', m.group(1)).strip()[:120] if m else ""

    def _fingerprint_one(self, ip, port, tls):
        scheme = "https" if tls else "http"
        url = f"{scheme}://{ip}:{port}/"
        ctx = None
        if tls:  # devices self-sign; we're fingerprinting, not trusting
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Bjorn recon)"})
        try:
            with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
                status, headers = resp.status, resp.headers
                body = resp.read(20000).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:  # 4xx/5xx are still a fingerprint
            status, headers, body = e.code, (e.headers or {}), ""
        except Exception as e:
            logger.debug(f"HTTP fingerprint {url} failed: {e}")
            return None
        return {
            "status": status,
            "server": headers.get("Server", ""),
            "powered_by": headers.get("X-Powered-By", ""),
            "title": self._extract_title(body),
            "url": url,
        }

    def _save(self, rows):
        os.makedirs(os.path.dirname(self.outfile), exist_ok=True)
        if not os.path.exists(self.outfile):
            with open(self.outfile, "w", newline="") as f:
                csv.writer(f).writerow(
                    ["IP", "Hostname", "Port", "Status", "Server", "X-Powered-By", "Title", "URL"])
        with open(self.outfile, "a", newline="") as f:
            csv.writer(f).writerows(sanitize_row(r) for r in rows)


if __name__ == "__main__":
    shared_data = SharedData()
    fp = HTTPFingerprint(shared_data)
    for r in shared_data.read_data():
        if r.get("Alive") == '1':
            fp.execute(r["IPs"], "80", r, b_status)
