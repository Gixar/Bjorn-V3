# action_planner.py
# Heuristic work-selection for Bjorn's orchestrator.
#
# Replaces the old "walk actions in load order, break on the first success" loop with a scored
# candidate list, so Bjorn:
#   1. prefers high-value / ready work (parent succeeded, never tried, known CVEs, rich port list)
#   2. still gets round to every eligible tool (anti-starvation / fair rotation)
#   3. can say *why* it picked something, on the e-Paper and in the log
#
# Pure functions plus a thin Planner class — no SharedData needed to test any of it. The
# orchestrator stays the executor; this module only ranks and picks.
from __future__ import annotations

import csv
from dataclasses import dataclass, field
from typing import Any, List, Optional, Sequence, Set

from retry_policy import retry_wait_remaining

# Ports whose services historically yield the most on a home/lab LAN. Additive when the port is
# open on the host and the action targets it.
HIGH_VALUE_PORTS = {
    21: 18,    # FTP
    22: 28,    # SSH — credentials + lateral movement
    23: 16,    # Telnet
    139: 10,
    445: 26,   # SMB — credentials + files
    1433: 14,  # MSSQL
    3306: 22,  # MySQL
    3389: 24,  # RDP
    5432: 14,  # Postgres
    80: 12,    # HTTP recon
    443: 12,
    8080: 8,
    8443: 8,
}

# Per-action base priority. Steal actions outrank the brute-force that unlocks them so loot is
# collected promptly once a parent succeeds.
ACTION_BASE = {
    "StealFilesSSH": 40,
    "StealFilesSMB": 40,
    "StealFilesFTP": 40,
    "StealFilesRDP": 40,
    "StealFilesTelnet": 40,
    "StealDataSQL": 40,
    "WebTemplateScan": 30,
    "SSHBruteforce": 20,
    "SMBBruteforce": 20,
    "FTPBruteforce": 18,
    "RDPBruteforce": 18,
    "SQLBruteforce": 18,
    "TelnetBruteforce": 16,
    "HTTPFingerprint": 14,
    "NmapVulnScanner": 12,
}

DEFAULT_BASE = 10  # anything not listed above (new actions rank mid-pack rather than last)

# Device families worth reaching first, matched against what HTTPFingerprint already recorded
# (Server / X-Powered-By / Title). These are the appliance classes that ship with default or weak
# credentials and hold something worth having — a NAS is files, a camera is a live feed, an admin
# panel is the box itself. A generic web server is deliberately absent: "nginx" says nothing about
# whether the host is interesting.
#
# Substrings are matched case-insensitively and must be unambiguous — a false positive here quietly
# reorders the whole attack queue. ("axis" is left out for that reason: Apache Axis is a SOAP
# library, not a camera.) A starting list, meant to be tuned against what a real LAN turns up.
SERVICE_HINTS = (
    ("synology", 30, "NAS"),
    ("qnap", 30, "NAS"),
    ("truenas", 30, "NAS"),
    ("freenas", 30, "NAS"),
    ("openmediavault", 30, "NAS"),
    ("hikvision", 28, "camera"),
    ("dahua", 28, "camera"),
    ("ipcamera", 28, "camera"),
    ("netwave", 28, "camera"),
    ("jenkins", 26, "admin panel"),
    ("webmin", 26, "admin panel"),
    ("phpmyadmin", 26, "admin panel"),
    ("routeros", 22, "router"),
    ("mikrotik", 22, "router"),
    ("openwrt", 22, "router"),
    ("dd-wrt", 22, "router"),
    ("draytek", 22, "router"),
    ("zyxel", 22, "router"),
    ("tp-link", 22, "router"),
    ("goahead", 20, "embedded"),   # embedded web server, near-exclusively appliances
    ("mini_httpd", 20, "embedded"),
    ("jetdirect", 18, "printer"),
    ("cups/", 18, "printer"),
)


@dataclass
class Candidate:
    """One runnable unit of work."""
    kind: str  # "host" | "standalone"
    action: Any
    action_name: str
    score: int
    reason: str
    ip: str = ""
    port: str = "0"
    row: Optional[dict] = None
    # A child action whose parent has already succeeded (eligibility guarantees that). Exempt from
    # the one-class-per-cycle rule: loot waiting to be collected beats variety.
    is_child: bool = False


def _action_name(action) -> str:
    return getattr(action, "action_name", None) or action.__class__.__name__


def _ports_of(row: dict) -> List[str]:
    return [p for p in str(row.get("Ports") or "").split(";") if p]


def load_vuln_ips(summary_path) -> Set[str]:
    """IPs with at least one recorded vulnerability, from vulnerability_summary.csv.

    Deliberately NOT "the vuln scanner succeeded on this host" — that only means the scan ran, and
    it is true of nearly every host once a pass completes, so it would boost everything equally
    (which is the same as boosting nothing, but with a misleading reason on the display). Read from
    the summary file so the signal means an actual finding. stdlib csv: pandas is a heavy import to
    pull into the scheduling hot path on a Pi Zero."""
    ips: Set[str] = set()
    try:
        with open(summary_path, newline="", encoding="utf-8", errors="replace") as f:
            for row in csv.DictReader(f):
                if (row.get("Vulnerabilities") or "").strip() and (row.get("IP") or "").strip():
                    ips.add(row["IP"].strip())
    except (FileNotFoundError, OSError):
        pass
    return ips


def load_service_hints(fingerprint_path) -> dict:
    """{ip: (weight, label)} from http_fingerprints.csv — what kind of box this looks like.

    HTTPFingerprint already banks the Server / X-Powered-By / Title of every web port; this just
    reads meaning out of data Bjorn collected two actions ago. A host can expose several ports, so
    the strongest hint wins. Missing file (no fingerprints yet) is the normal early state."""
    hints: dict = {}
    try:
        with open(fingerprint_path, newline="", encoding="utf-8", errors="replace") as f:
            for row in csv.DictReader(f):
                ip = (row.get("IP") or "").strip()
                if not ip:
                    continue
                haystack = " ".join((row.get("Server") or "", row.get("X-Powered-By") or "",
                                     row.get("Title") or "")).lower()
                for needle, weight, label in SERVICE_HINTS:
                    if needle in haystack and weight > hints.get(ip, (0, ""))[0]:
                        hints[ip] = (weight, label)
    except (FileNotFoundError, OSError):
        pass
    return hints


def plan_idle_seconds(base_interval, failed_scans, next_retry_wait=0, floor=30):
    """How long to idle after a scan that found nothing. Pure/testable.

    Two pulls in opposite directions:
      * **Back off** as fruitless scans pile up — an exhausted network does not become interesting
        by being asked four times a minute, and each pass costs CPU and SD writes on a Pi Zero.
        Capped at 4x so it stays responsive to someone walking a new device onto the LAN.
      * **Wake early** when the only thing standing between Bjorn and real work is a retry window.
        The planner knows when the soonest blocked action unblocks; sleeping past that wastes the
        difference. The floor stops a nearly-expired window from turning into a busy loop.
    """
    interval = base_interval * min(4, max(1, failed_scans))
    if next_retry_wait and next_retry_wait < interval:
        return int(max(floor, min(next_retry_wait, interval)))
    return int(interval)


def _in_failed_backoff(status: str, delay: int) -> bool:
    return "failed" in status and retry_wait_remaining(status, delay) > 0


def _in_success_window(status: str, delay: int, retry_success: bool) -> bool:
    """Whether a *successful* action is still off-limits. For host actions this is the
    'don't re-attack a box you already cracked' rule."""
    if "success" not in status:
        return False
    if not retry_success:
        return True
    return retry_wait_remaining(status, delay) > 0


def host_gate(
    action,
    row: dict,
    *,
    success_retry_delay: int,
    failed_retry_delay: int,
    retry_success_actions: bool,
):
    """(eligible, seconds_until_eligible) for one (action, host) pair.

    The second value is only meaningful when eligible is False *and* the block is a retry window
    that will actually expire — it feeds the adaptive idle interval. A success with
    `retry_success_actions` off never expires, so it reports 0: waiting for it would be waiting
    forever. Structural mismatches (dead host, closed port, parent not yet succeeded) report 0 too;
    no amount of sleeping fixes them."""
    if row.get("Alive") != "1":
        return False, 0

    port = getattr(action, "port", None)
    if port is not None and str(port) not in ("0", "None") and str(port) not in _ports_of(row):
        return False, 0

    parent = getattr(action, "b_parent_action", None)
    if parent and "success" not in str(row.get(parent, "") or ""):
        return False, 0

    status = str(row.get(_action_name(action), "") or "")
    if "success" in status:
        if not retry_success_actions:
            return False, 0
        wait = retry_wait_remaining(status, success_retry_delay)
        return (False, wait) if wait > 0 else (True, 0)
    if "failed" in status:
        wait = retry_wait_remaining(status, failed_retry_delay)
        return (False, wait) if wait > 0 else (True, 0)
    return True, 0


def is_host_action_eligible(action, row: dict, **kw) -> bool:
    """The same gates the orchestrator applied before ranking existed: host alive, port open,
    parent succeeded, not inside a retry window."""
    return host_gate(action, row, **kw)[0]


def standalone_gate(action, row: Optional[dict], *, failed_retry_delay: int):
    """(eligible, seconds_until_eligible) for a standalone action — see is_standalone_eligible."""
    if row is None:
        return True, 0
    status = str(row.get(_action_name(action), "") or "")
    if "failed" in status:
        wait = retry_wait_remaining(status, failed_retry_delay)
        return (False, wait) if wait > 0 else (True, 0)
    return True, 0


def is_standalone_eligible(action, row: Optional[dict], *, failed_retry_delay: int) -> bool:
    """Standalone actions get **no success gate** — only the failed-retry backoff.

    This is the Wave 4 fix, and it has to hold here too or the planner reintroduces the bug one
    layer up: `retry_success_actions` defaults to False, which is right for a *host* action but
    applied to a recurring job means one success marks it done for the lifetime of the netkb. These
    police their own cadence (ble_scan_interval, wifi_scan_interval, wpasec_interval,
    telegram_min_interval), so the scheduler must not also latch them off."""
    if row is None:
        return True
    status = str(row.get(_action_name(action), "") or "")
    return not _in_failed_backoff(status, failed_retry_delay)


def score_host_action(action, row: dict, vuln_ips: Optional[Set[str]] = None,
                      service_hints: Optional[dict] = None):
    """Rank one (action, host) pair. Higher runs sooner. Returns (score, short reason)."""
    name = _action_name(action)
    score = ACTION_BASE.get(name, DEFAULT_BASE)
    reasons: List[str] = []

    parent = getattr(action, "b_parent_action", None)
    if parent and "success" in str(row.get(parent, "") or ""):
        score += 55
        reasons.append("parent ok")

    status = str(row.get(name, "") or "")
    if not status:
        score += 45
        reasons.append("never tried")
    elif "failed" in status:
        score += 20
        reasons.append("retry due")
    elif "success" in status:
        score += 5
        reasons.append("re-check")

    ip = row.get("IPs", "")
    if vuln_ips and ip in vuln_ips:
        score += 35
        reasons.append("has CVEs")

    if service_hints and ip in service_hints:
        weight, label = service_hints[ip]
        score += weight
        reasons.append(label)

    port = getattr(action, "port", None)
    try:
        port_i = int(port) if port is not None else None
    except (TypeError, ValueError):
        port_i = None
    if port_i in HIGH_VALUE_PORTS:
        score += HIGH_VALUE_PORTS[port_i]
        reasons.append(f":{port_i}")

    nports = len(_ports_of(row))
    if nports:
        score += min(nports, 12)
        if nports >= 5:
            reasons.append(f"{nports} ports")

    reason = f"{name}@{ip or '?'}"
    if reasons:
        reason += " - " + " - ".join(reasons[:3])
    return score, reason


def score_standalone(action, row: Optional[dict], *, idle_boost: int = 0):
    """Standalone recon/reporting (BLE, Wi-Fi, SNMP, wpa-sec, Telegram): a mild base, plus a boost
    when host work has dried up. They are cheap and self-throttling, so they never need to outrank
    real attack work — they just must not be starved by it."""
    name = _action_name(action)
    score = 8 + idle_boost
    status = str(row.get(name, "") or "") if row is not None else ""
    if not status:
        score += 25
        return score, f"{name} - never ran"
    if "failed" in status:
        score += 12
        return score, f"{name} - retry"
    return score, f"{name} - periodic"


@dataclass
class Planner:
    """Builds and ranks one orchestrator cycle's worth of work.

    max_host_actions:  host-targeted actions per cycle. A cycle with work does not sleep, so this
                       is a fairness window, not a throughput cap.
    standalone_every:  force a standalone action every N cycles even while host work remains, so
                       recon/reporting is not starved by an endless supply of brute-force targets.
    """
    success_retry_delay: int = 900
    failed_retry_delay: int = 600
    retry_success_actions: bool = False
    max_host_actions: int = 4
    standalone_every: int = 3
    _cycle: int = field(default=0, repr=False)
    _recent_names: List[str] = field(default_factory=list, repr=False)
    # Seconds until the soonest retry-blocked action becomes runnable, or 0 when nothing is merely
    # waiting. Set by collect(), read by the orchestrator to size the idle sleep.
    next_retry_wait: int = field(default=0, repr=False)

    def sync_config(self, shared_data) -> None:
        """Re-read the knobs from live config. Called each cycle: everything else in Bjorn honours
        a config change without a restart, and a scheduler that needed one would be a surprise.
        Clamped because these are hand-editable — standalone_every=0 would divide by zero."""
        self.success_retry_delay = getattr(shared_data, "success_retry_delay", 900)
        self.failed_retry_delay = getattr(shared_data, "failed_retry_delay", 600)
        self.retry_success_actions = getattr(shared_data, "retry_success_actions", False)
        self.max_host_actions = max(1, int(getattr(shared_data, "planner_max_host_actions", 4) or 4))
        self.standalone_every = max(1, int(getattr(shared_data, "planner_standalone_every", 3) or 3))

    def collect(
        self,
        host_actions: Sequence,
        standalone_actions: Sequence,
        current_data: Sequence[dict],
        *,
        idle_boost: int = 0,
        vuln_ips: Optional[Set[str]] = None,
        service_hints: Optional[dict] = None,
    ) -> List[Candidate]:
        candidates: List[Candidate] = []
        recent = self._recent_names[-6:]
        waits: List[int] = []

        for action in host_actions:
            name = _action_name(action)
            for row in current_data:
                if row.get("MAC Address") == "STANDALONE":
                    continue
                eligible, wait = host_gate(
                    action, row,
                    success_retry_delay=self.success_retry_delay,
                    failed_retry_delay=self.failed_retry_delay,
                    retry_success_actions=self.retry_success_actions,
                )
                if not eligible:
                    if wait:
                        waits.append(wait)
                    continue
                score, reason = score_host_action(action, row, vuln_ips, service_hints)
                if name in recent:
                    score -= 8  # mild anti-monopoly; a strong candidate still wins
                candidates.append(Candidate(
                    kind="host", action=action, action_name=name, score=score, reason=reason,
                    ip=row.get("IPs", ""), port=str(getattr(action, "port", "0") or "0"), row=row,
                    is_child=bool(getattr(action, "b_parent_action", None)),
                ))

        standalone_row = next(
            (r for r in current_data if r.get("MAC Address") == "STANDALONE"), None)
        for action in standalone_actions:
            eligible, wait = standalone_gate(action, standalone_row,
                                             failed_retry_delay=self.failed_retry_delay)
            if not eligible:
                if wait:
                    waits.append(wait)
                continue
            score, reason = score_standalone(action, standalone_row, idle_boost=idle_boost)
            candidates.append(Candidate(
                kind="standalone", action=action, action_name=_action_name(action),
                score=score, reason=reason, row=standalone_row,
            ))

        self.next_retry_wait = min(waits) if waits else 0
        candidates.sort(key=lambda c: c.score, reverse=True)
        return candidates

    def select(self, candidates: List[Candidate]) -> List[Candidate]:
        """Pick this cycle's work: the top host actions (capped, preferring a spread of action
        classes) plus a standalone turn every `standalone_every` cycles."""
        self._cycle += 1
        chosen: List[Candidate] = []
        seen_names: set = set()
        host_count = 0

        for c in candidates:
            if c.kind != "host":
                continue
            if host_count >= self.max_host_actions:
                break
            # One action class per cycle, so a LAN full of SSH boxes can't monopolise the window.
            # Parent-ready child actions (steals, template scans) are exempt — collecting loot that
            # is already unlocked beats variety. Keyed on the action having a satisfied parent, not
            # on a score threshold: an ordinary never-tried SSH on a multi-port host scores 95 too,
            # so a threshold high enough to admit steals also readmits the monopoly it was meant to
            # prevent.
            if c.action_name in seen_names and not c.is_child:
                continue
            chosen.append(c)
            seen_names.add(c.action_name)
            host_count += 1

        if self._cycle % self.standalone_every == 0 or not chosen:
            for c in candidates:
                if c.kind == "standalone":
                    chosen.append(c)
                    break

        self._recent_names.extend(c.action_name for c in chosen)
        del self._recent_names[:-24]
        return chosen
