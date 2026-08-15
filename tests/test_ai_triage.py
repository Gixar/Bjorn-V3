"""Tests for the #15 AI audit: redaction (what may leave the device) and the skip paths.

The redaction half needs no key, no network and no SDK — that is the point of keeping it in a
standalone `ai_triage` module. Runs under pytest and as `python tests/test_ai_triage.py`.
"""
import os
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _stubs  # noqa: E402
_stubs.install()

import ai_triage  # noqa: E402
from actions.ai_audit import AIAudit  # noqa: E402


def _row(**over):
    row = {"MAC Address": "aa:bb:cc:dd:ee:ff", "IPs": "192.168.1.10",
           "Hostnames": "andres-laptop", "Alive": "1", "Ports": "22;80"}
    row.update(over)
    return row


# --- redaction: the security boundary ---------------------------------------------------------

def test_payload_carries_findings_and_nothing_identifying():
    """The allowlist is the whole defence: a netkb row full of secrets must reduce to IP, ports
    and which checks succeeded. MAC (hardware ID) and hostname (routinely a person's name) are
    dropped; a password or loot path that ever reached a row must not reach the wire."""
    rows = [_row(**{"SSHBruteforce": "success_20260815_120000",
                    "FTPBruteforce": "failed_20260815_120001",
                    "Password": "hunter2", "loot": "/root/secrets.txt"})]
    hosts = ai_triage.redact(rows, vulns_by_ip={"192.168.1.10": ["CVE-2021-41773"] * 3})

    assert hosts == [{"IPs": "192.168.1.10", "Ports": "22;80",
                      "succeeded": ["SSHBruteforce"], "vulns": ["CVE-2021-41773"]}]
    blob = ai_triage.build_user_message(hosts).lower()
    for secret in ("aa:bb:cc", "andres-laptop", "hunter2", "secrets.txt", "120000"):
        assert secret not in blob, f"{secret!r} reached the payload"


def test_a_new_netkb_column_cannot_leak_by_default():
    """The reason this is an allowlist and not a denylist: a column nobody has written yet is
    dropped without anyone remembering to filter it. A denylist ships the leak instead."""
    hosts = ai_triage.redact([_row(**{"SomeFutureColumn": "sensitive-value"})])
    assert "sensitive" not in ai_triage.build_user_message(hosts)


def test_dead_standalone_and_over_budget_hosts_are_not_sent():
    rows = [_row(IPs=f"192.168.1.{n}") for n in range(10)]
    rows.append(_row(IPs="192.168.1.99", Alive="0"))
    rows.append(_row(IPs="STANDALONE", **{"MAC Address": "STANDALONE"}))

    hosts = ai_triage.redact(rows, max_hosts=4)
    assert len(hosts) == 4, "max_hosts is the input half of the token budget"
    ips = {h["IPs"] for h in ai_triage.redact(rows)}
    assert "192.168.1.99" not in ips and "STANDALONE" not in ips


def test_only_success_counts_as_a_finding():
    """A 'failed' mark means the control held — reporting it as a finding would put a healthy
    host in the remediation list."""
    hosts = ai_triage.redact([_row(**{"SSHBruteforce": "failed_20260815_120000",
                                      "SMBBruteforce": ""})])
    assert "succeeded" not in hosts[0]


# --- the action: every degradation path is a skip, never a failure ----------------------------

def _audit(tmp, **cfg):
    shared = types.SimpleNamespace(
        output_dir=str(tmp), vuln_summary_file=str(tmp / "nope.csv"),
        read_data=lambda: [_row(**{"SSHBruteforce": "success_20260815_120000"})],
        ai_triage_enabled=True, ai_triage_interval=0, ai_triage_max_hosts=25)
    for k, v in cfg.items():
        setattr(shared, k, v)
    return AIAudit(shared)


def test_skips_without_a_key_disabled_or_no_hosts(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert _audit(tmp_path).execute() == 'skipped', "no key must skip, not fail"

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    assert _audit(tmp_path, ai_triage_enabled=False).execute() == 'skipped'
    assert _audit(tmp_path, read_data=lambda: []).execute() == 'skipped'


def test_a_failed_call_skips_and_leaves_the_clock_ready_to_retry(tmp_path, monkeypatch):
    """Transport/auth/rate-limit errors mean the audit did not run. 'skipped' leaves no netkb
    mark, and no report file is written — a report that was never generated must not appear."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    audit = _audit(tmp_path)

    def boom():
        raise RuntimeError("connection reset")
    audit._client_factory = boom

    assert audit.execute() == 'skipped'
    assert not (tmp_path / "reports").exists(), "no call, no report"


def test_success_writes_the_report_and_sends_no_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    sent = {}

    class FakeClient:
        class messages:
            @staticmethod
            def create(**kwargs):
                sent.update(kwargs)
                block = types.SimpleNamespace(type="text", text="# Fix SSH\nSet PasswordAuth no.")
                return types.SimpleNamespace(
                    content=[block],
                    usage=types.SimpleNamespace(input_tokens=100, output_tokens=20))

    audit = _audit(tmp_path)
    audit._client_factory = lambda: FakeClient()
    assert audit.execute() == 'success'

    reports = list((tmp_path / "reports").glob("ai_audit_*.md"))
    assert len(reports) == 1 and "Fix SSH" in reports[0].read_text(encoding="utf-8")
    payload = str(sent["messages"]) + str(sent["system"])
    assert "andres-laptop" not in payload and "aa:bb:cc" not in payload
    assert sent["max_tokens"] == 4096, "output half of the token budget must be capped"


if __name__ == "__main__":
    ai_triage.demo()
    print("run the action tests with pytest (they use tmp_path/monkeypatch)")
