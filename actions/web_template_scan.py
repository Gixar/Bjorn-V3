"""web_template_scan.py - nuclei-style templated web checks (backlog Wave 2).

A child action of HTTPFingerprint: once a host's web services are fingerprinted, GET each bundled
template's path against every web port and report a hit when the matchers pass. Findings land in
data/output/scan_results/web_template_findings.csv. Templates live in config/web_templates.json —
plain JSON (stdlib, no pyyaml dep), extensible without code.

ponytail: fires every template at every web port (no tech-gating on the fingerprint yet); add a
`match_server` gate to the template format if the request volume becomes a problem on a Pi Zero.
"""
import os
import ssl
import csv
import json
import logging
import urllib.error
import urllib.request
from shared import SharedData
from logger import Logger
from actions.http_fingerprint import HTTPFingerprint

logger = Logger(name="web_template_scan.py", level=logging.INFO)

b_class = "WebTemplateScan"
b_module = "web_template_scan"
b_status = "web_template_scan"
b_port = 80
b_parent = "HTTPFingerprint"  # run after the host's web services are fingerprinted


class WebTemplateScan:
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self._templates = None
        self.outfile = os.path.join(shared_data.scan_results_dir, "web_template_findings.csv")
        logger.info("WebTemplateScan initialized.")

    def execute(self, ip, port, row, status_key):
        self.shared_data.bjornorch_status = "WebTemplateScan"
        if self._templates is None:
            self._templates = self._load_templates()
        targets = HTTPFingerprint._web_ports([p for p in row.get("Ports", "").split(";") if p])
        if not self._templates or not targets:
            return 'failed'

        hostname = row.get("Hostnames", "")
        findings = []
        for web_port, tls in targets:
            ctx = self._tls_context() if tls else None
            base = f"{'https' if tls else 'http'}://{ip}:{web_port}"
            for tpl in self._templates:
                status, body = self._get(base + tpl.get("path", "/"), ctx)
                if status is None:
                    continue
                if self._matches(tpl.get("matchers", {}), status, body):
                    findings.append([ip, hostname, web_port, tpl.get("id", ""),
                                     tpl.get("severity", "?"), tpl.get("name", ""),
                                     base + tpl.get("path", "/")])
                    logger.success(f"Web template hit: {ip}:{web_port} {tpl.get('id')}")
        if findings:
            self._save(findings)
        return 'success'  # scan completed; don't hammer the host every cycle

    def _load_templates(self):
        path = os.path.join(self.shared_data.configdir, "web_templates.json")
        try:
            with open(path) as f:
                return json.load(f).get("templates", [])
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.warning(f"Web templates unavailable ({path}): {e}")
            return []

    @staticmethod
    def _matches(matchers, status, body):
        """A template matches when every *specified* matcher passes: `status` = code in the list;
        `body_contains` = any of the substrings present. Pure/testable."""
        if "status" in matchers and status not in matchers["status"]:
            return False
        if "body_contains" in matchers and not any(s in body for s in matchers["body_contains"]):
            return False
        return True

    @staticmethod
    def _tls_context():
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # probing untrusted hosts, not establishing trust
        return ctx

    @staticmethod
    def _get(url, ctx):
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Bjorn recon)"})
        try:
            with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
                return resp.status, resp.read(50000).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, ""
        except Exception:
            return None, ""

    def _save(self, rows):
        os.makedirs(os.path.dirname(self.outfile), exist_ok=True)
        if not os.path.exists(self.outfile):
            with open(self.outfile, "w", newline="") as f:
                csv.writer(f).writerow(
                    ["IP", "Hostname", "Port", "TemplateID", "Severity", "Name", "URL"])
        with open(self.outfile, "a", newline="") as f:
            csv.writer(f).writerows(rows)


if __name__ == "__main__":
    shared_data = SharedData()
    scanner = WebTemplateScan(shared_data)
    for r in shared_data.read_data():
        if r.get("Alive") == '1':
            scanner.execute(r["IPs"], "80", r, b_status)
