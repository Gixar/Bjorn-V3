"""Tests for offline CVE enrichment in NmapVulnScanner: CPE parsing + signature matching
(exact / contains / version_lt). Pure static methods — no nmap, no SharedData. Runs under
pytest and as `python tests/test_cve_enrichment.py`.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _stubs  # noqa: E402
_stubs.install()

from actions.nmap_vuln_scanner import NmapVulnScanner  # noqa: E402

parse = NmapVulnScanner._parse_service_versions
match = NmapVulnScanner._match_signatures

SIGS = [
    {"product": "vsftpd", "version": "2.3.4", "cve": "CVE-2011-2523", "severity": "critical"},
    {"product": "openssh", "version_lt": "7.7", "cve": "CVE-2018-15473", "severity": "medium"},
    {"product": "proftpd", "version_contains": "1.3.5", "cve": "CVE-2015-3306", "severity": "critical"},
]

SAMPLE = """
21/tcp open  ftp     vsftpd 2.3.4
| cpe:/a:vsftpd:vsftpd:2.3.4
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu
| cpe:/a:openbsd:openssh:7.6p1
80/tcp open  http    Apache httpd 2.4.52
| cpe:/a:apache:http_server:2.4.52
"""


def test_parses_product_version_from_cpe():
    pairs = parse(SAMPLE)
    assert ("vsftpd", "2.3.4") in pairs
    assert ("openssh", "7.6p1") in pairs
    assert ("http_server", "2.4.52") in pairs


def test_exact_version_match():
    assert match([("vsftpd", "2.3.4")], SIGS) == {"CVE-2011-2523 (vsftpd 2.3.4) [critical]"}
    # a different vsftpd version is not flagged
    assert match([("vsftpd", "3.0.3")], SIGS) == set()


def test_version_lt_true_and_false():
    # 7.6p1 < 7.7 -> vulnerable
    assert match([("openssh", "7.6p1")], SIGS) == {"CVE-2018-15473 (openssh 7.6p1) [medium]"}
    # 8.4 is NOT < 7.7 -> no finding (guards against the classic false positive)
    assert match([("openssh", "8.4")], SIGS) == set()
    # exactly 7.7 is not < 7.7
    assert match([("openssh", "7.7")], SIGS) == set()


def test_contains_match():
    assert match([("proftpd", "1.3.5rc3")], SIGS) == {"CVE-2015-3306 (proftpd 1.3.5rc3) [critical]"}


def test_service_line_fallback_without_cpe():
    # consumer gear nmap can't CPE-identify still yields (product, version) from the -sV line
    out = "21/tcp open  ftp     vsftpd 2.3.4\n"   # note: no cpe:/ line at all
    assert ("vsftpd", "2.3.4") in parse(out)
    assert match(parse(out), SIGS) == {"CVE-2011-2523 (vsftpd 2.3.4) [critical]"}


def test_service_line_garbage_is_no_false_positive():
    # a router with an un-CPE'd banner: first two tokens are junk, must match nothing
    out = "80/tcp open  http    ZTE web server 1.0 ZTE corp 2015.\n"
    assert ("zte", "web") in parse(out)   # parsed, but...
    assert match(parse(out), SIGS) == set()  # ...matches no signature


def test_end_to_end_sample_no_apache_sig():
    # Apache 2.4.52 has no signature here -> only vsftpd + openssh flagged
    findings = match(parse(SAMPLE), SIGS)
    assert findings == {
        "CVE-2011-2523 (vsftpd 2.3.4) [critical]",
        "CVE-2018-15473 (openssh 7.6p1) [medium]",
    }


def test_scan_reports_failure_when_nmap_exits_nonzero():
    """#5 side-effect verification: nmap that exits non-zero (bad args, no -sV permission, an
    unresolvable target) did not scan the host. subprocess.run does not raise on a non-zero exit,
    so the pre-#5 code returned the (often empty) stdout and execute() stamped success_<ts> —
    with retry_success off the host was then never re-scanned. A clean scan that simply found no
    vulnerabilities still succeeds (the recon convention)."""
    import tempfile
    from types import SimpleNamespace
    import actions.nmap_vuln_scanner as mod

    obj = mod.NmapVulnScanner.__new__(mod.NmapVulnScanner)
    obj.shared_data = SimpleNamespace(bjornstatustext2="", nmap_scan_aggressivity="-T4",
                                      vuln_scan_sv=False, vuln_scan_vulners=False,
                                      vuln_offline_cve=False)
    obj.summary_file = tempfile.NamedTemporaryFile(delete=False, suffix=".csv").name
    obj.scan_results = []
    obj._cve_signatures = []

    real_run = mod.subprocess.run

    def run_rc(rc, stdout=""):
        return lambda *a, **k: SimpleNamespace(returncode=rc, stdout=stdout, stderr="boom")

    try:
        mod.subprocess.run = run_rc(1)  # nmap errored
        assert obj.scan_vulnerabilities("10.0.0.9", "h", "AA:BB", ["80"]) is None, \
            "a non-zero nmap exit is a scan that did not happen, not a success"

        mod.subprocess.run = run_rc(0, "80/tcp open http\nnothing vulnerable here\n")  # clean, no vulns
        assert obj.scan_vulnerabilities("10.0.0.9", "h", "AA:BB", ["80"]) is not None, \
            "a clean scan that found no vulns still succeeds"
    finally:
        mod.subprocess.run = real_run


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
