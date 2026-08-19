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

        # A host with no known open ports: netkb stores "" and row["Ports"].split(";") yields [""],
        # which built `-p ""` and made nmap refuse the run (Error #485). Nothing to scan means nmap
        # is never spawned at all. Recorded, not raised — scan_vulnerabilities catches Exception,
        # and an AssertionError from inside the fake would be swallowed into the None this asserts.
        spawned = []

        def record(*a, **k):
            spawned.append(a[0])
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        mod.subprocess.run = record
        for portless in ([""], [], ["", " "]):
            assert obj.scan_vulnerabilities("10.0.0.9", "h", "AA:BB", portless) is None, \
                f"{portless!r} is no ports at all, not a port specification"
        assert not spawned, f"nmap was spawned without a port list: {spawned}"
    finally:
        mod.subprocess.run = real_run


def test_a_portless_host_is_not_reported_as_a_failed_scan():
    """Nothing to scan is not a scan that broke. Five of seven hosts on the live net have no open
    ports, so execute() warning on every one of them was 49 WARNING lines in three hours — noise at
    a level reserved for problems. A scan that actually ran and failed must still warn."""
    import tempfile
    from types import SimpleNamespace
    import actions.nmap_vuln_scanner as mod

    obj = mod.NmapVulnScanner.__new__(mod.NmapVulnScanner)
    obj.shared_data = SimpleNamespace(bjornstatustext2="", bjornorch_status="",
                                      nmap_scan_aggressivity="-T4", vuln_scan_sv=False,
                                      vuln_scan_vulners=False, vuln_offline_cve=False)
    obj.summary_file = tempfile.NamedTemporaryFile(delete=False, suffix=".csv").name
    obj.scan_results = []
    obj._cve_signatures = []

    warned, spawned = [], []
    real_run, real_warn = mod.subprocess.run, mod.logger.warning
    mod.logger.warning = lambda msg, *a, **k: warned.append(msg)

    def record(*a, **k):
        spawned.append(a[0])
        return SimpleNamespace(returncode=1, stdout="", stderr="boom")

    try:
        mod.subprocess.run = record
        row = {"Ports": "", "Hostnames": "h", "MAC Address": "AA:BB"}
        assert obj.execute("10.0.0.9", row, "NmapVulnScanner") == "skipped"
        assert not spawned, "no ports, so nmap must not run"
        assert not warned, f"a host with nothing to scan is not a failure: {warned}"

        # ...but a host with ports whose scan really did fail still has to say so.
        row = {"Ports": "80;443", "Hostnames": "h", "MAC Address": "AA:BB"}
        assert obj.execute("10.0.0.9", row, "NmapVulnScanner") == "skipped"
        assert spawned, "a host with ports must actually be scanned"
        assert warned, "a scan that ran and failed must still warn"
    finally:
        mod.subprocess.run, mod.logger.warning = real_run, real_warn


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
