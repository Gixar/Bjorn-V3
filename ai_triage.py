"""ai_triage.py - what may leave the device, and in what shape (#15, P-AI).

Standalone and dependency-free, in the same shape as `path_safety` / `retry_policy` /
`action_outcome`: the action wires this to the network, this module decides the payload. Keeping
the two apart means the rule that matters — *no secret ever goes to a cloud API* — is testable
without a key, a network, or the SDK.

**Allowlist, not denylist.** `redact()` builds each host record field by field from
`_ALLOWED_FIELDS`; it never copies a row and deletes the bad parts. A denylist would leak the day
someone adds a netkb column, which is exactly how this class of bug ships. Cracked credentials and
stolen loot are not filtered here at all — they live in `crackedpwd/` and `stolen_data/`, and this
module simply never reads those files. What the model gets is: an IP, its open ports, which
actions have succeeded against it (the *finding* — "SSH creds are weak" — never the password),
and any CVE tokens the vuln scanner recorded.

MAC addresses and hostnames are deliberately dropped: a MAC identifies hardware and a hostname is
routinely a person's name. Neither improves a remediation report that can address hosts by IP.
"""

# netkb columns copied verbatim. Everything not named here is dropped, including columns that do
# not exist yet.
_ALLOWED_FIELDS = ("IPs", "Ports")

# Action columns hold "success_<ts>" / "failed_<ts>". The timestamp is noise to the model and a
# weak fingerprint of operator activity, so only the verb survives.
_OUTCOME_VERBS = ("success", "failed")

MAX_HOSTS_DEFAULT = 25
MAX_VULNS_PER_HOST = 12


def _verb(value):
    """'success_20260815_120000' -> 'success'. Anything else -> None (no claim)."""
    text = str(value or "").strip().lower()
    for verb in _OUTCOME_VERBS:
        if text.startswith(verb):
            return verb
    return None


def redact(rows, vulns_by_ip=None, max_hosts=MAX_HOSTS_DEFAULT):
    """netkb rows -> the minimal host records the model is allowed to see.

    `vulns_by_ip` maps IP -> iterable of CVE/vuln tokens (from the vuln summary). Dead hosts and
    the STANDALONE bookkeeping row are dropped; the list is truncated to `max_hosts`, which is the
    input half of the per-run token budget the PRD requires.
    """
    vulns_by_ip = vulns_by_ip or {}
    hosts = []
    for row in rows or []:
        if row.get("Alive") != '1':
            continue
        ip = str(row.get("IPs", "")).strip()
        if not ip or ip == "STANDALONE":
            continue

        host = {field: str(row.get(field, "")).strip() for field in _ALLOWED_FIELDS}
        findings = sorted(
            name for name, value in row.items()
            if name not in _ALLOWED_FIELDS and _verb(value) == "success"
        )
        if findings:
            host["succeeded"] = findings
        tokens = [str(v).strip() for v in vulns_by_ip.get(ip, []) if str(v).strip()]
        if tokens:
            host["vulns"] = sorted(set(tokens))[:MAX_VULNS_PER_HOST]
        hosts.append(host)
        if len(hosts) >= max(1, int(max_hosts or MAX_HOSTS_DEFAULT)):
            break
    return hosts


SYSTEM = """You are writing a defensive security audit for the operator of a small \
authorized-testing device on their own network. You are given only what that device \
found: per host, its IP, open ports, which of the device's own checks succeeded, and \
any CVE identifiers matched against service versions.

A check listed under "succeeded" means that control is weak on that host — for example \
an SSH or FTP entry means a password from a small common-password list was accepted. \
You are never given the credential itself; do not ask for it and do not guess it.

Write a remediation report in Markdown:

- Order hosts by how much risk they carry, worst first.
- For each finding: one line on why it matters, then the concrete fix (the setting to \
change, the service to disable, the patch to apply). Name versions where the CVE \
identifies one.
- Close with the two or three actions that remove the most risk for the least work.

Be specific and short. No preamble, no restating the input, no speculation beyond the \
findings given. This is remediation advice for a defender: do not write exploit steps, \
proof-of-concept code, or attack instructions."""


def build_user_message(hosts):
    """The findings, as compact JSON. Sorted so an unchanged network yields an unchanged
    prefix — the cheap half of prompt caching, and it makes the report stable run to run."""
    import json
    return json.dumps(sorted(hosts, key=lambda h: h.get("IPs", "")),
                      indent=1, sort_keys=True)


def demo():
    """Runnable check: the allowlist holds even when the row is full of secrets."""
    rows = [
        {"MAC Address": "aa:bb:cc:dd:ee:ff", "IPs": "192.168.1.10",
         "Hostnames": "andres-laptop", "Alive": "1", "Ports": "22;80",
         "SSHBruteforce": "success_20260815_120000", "FTPBruteforce": "failed_20260815_120001",
         "Password": "hunter2", "loot": "/root/secrets.txt"},
        {"MAC Address": "11:22:33:44:55:66", "IPs": "192.168.1.99", "Alive": "0", "Ports": "443"},
        {"MAC Address": "STANDALONE", "IPs": "STANDALONE", "Alive": "1", "Ports": "0"},
    ]
    hosts = redact(rows, vulns_by_ip={"192.168.1.10": ["CVE-2021-41773", "CVE-2021-41773"]})

    assert len(hosts) == 1, "dead and STANDALONE rows must not be sent"
    host = hosts[0]
    assert host["IPs"] == "192.168.1.10" and host["Ports"] == "22;80"
    assert host["succeeded"] == ["SSHBruteforce"], "only successes are findings"
    assert host["vulns"] == ["CVE-2021-41773"], "CVE tokens deduped"
    blob = build_user_message(hosts).lower()
    for secret in ("aa:bb:cc", "andres-laptop", "hunter2", "secrets.txt"):
        assert secret not in blob, f"{secret!r} reached the payload"
    print("ai_triage demo OK")


if __name__ == "__main__":
    demo()
