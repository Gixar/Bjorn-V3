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


def is_host_action_eligible(
    action,
    row: dict,
    *,
    success_retry_delay: int,
    failed_retry_delay: int,
    retry_success_actions: bool,
) -> bool:
    """The same gates the orchestrator applied before ranking existed: host alive, port open,
    parent succeeded, not inside a retry window."""
    if row.get("Alive") != "1":
        return False

    port = getattr(action, "port", None)
    if port is not None and str(port) not in ("0", "None") and str(port) not in _ports_of(row):
        return False

    parent = getattr(action, "b_parent_action", None)
    if parent and "success" not in str(row.get(parent, "") or ""):
        return False

    status = str(row.get(_action_name(action), "") or "")
    if _in_success_window(status, success_retry_delay, retry_success_actions):
        return False
    if _in_failed_backoff(status, failed_retry_delay):
        return False
    return True


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


def score_host_action(action, row: dict, vuln_ips: Optional[Set[str]] = None):
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

    if vuln_ips and row.get("IPs", "") in vuln_ips:
        score += 35
        reasons.append("has CVEs")

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

    reason = f"{name}@{row.get('IPs', '?')}"
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
    ) -> List[Candidate]:
        candidates: List[Candidate] = []
        recent = self._recent_names[-6:]

        for action in host_actions:
            name = _action_name(action)
            for row in current_data:
                if row.get("MAC Address") == "STANDALONE":
                    continue
                if not is_host_action_eligible(
                    action, row,
                    success_retry_delay=self.success_retry_delay,
                    failed_retry_delay=self.failed_retry_delay,
                    retry_success_actions=self.retry_success_actions,
                ):
                    continue
                score, reason = score_host_action(action, row, vuln_ips)
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
            if not is_standalone_eligible(action, standalone_row,
                                          failed_retry_delay=self.failed_retry_delay):
                continue
            score, reason = score_standalone(action, standalone_row, idle_boost=idle_boost)
            candidates.append(Candidate(
                kind="standalone", action=action, action_name=_action_name(action),
                score=score, reason=reason, row=standalone_row,
            ))

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
