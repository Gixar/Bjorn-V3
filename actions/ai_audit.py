"""ai_audit.py - the defensive half of #15 (PRD P-AI): findings -> a remediation report.

A standalone action, so it runs in the idle window between cycles and never on the hot loop —
the PRD's first non-negotiable. It hands the *redacted* netkb (see `ai_triage.py`) to Claude
Haiku and writes the returned Markdown to data/output/reports/.

Degrades, never fails: no `ANTHROPIC_API_KEY` in the environment, no `anthropic` package, no
network, nothing alive to report on, or not yet due -> `'skipped'`, which leaves no netkb mark.
`b_needs_internet` means the orchestrator skips it outright while offline.

**The key is read from the environment, never from shared_config.json.** The web UI's
`/load_config` serves that file verbatim, so a key stored there would be handed to anyone who can
reach port 8000.

Deliberately not built: the target *re-ranking* half of #15. Smart Planner V2 already re-ranks
deterministically with no key and no network, and an LLM ordering has to beat that baseline
before it earns a place in the loop — see docs/IMPROVEMENT_PLAN.md.
"""
import os
import csv
import time
import logging
from datetime import datetime

import ai_triage
from logger import Logger

logger = Logger(name="ai_audit.py", level=logging.INFO)

b_class = "AIAudit"
b_module = "ai_audit"
b_status = "ai_audit"
b_port = 0          # standalone: reasons over netkb, targets no single host
b_parent = None
b_needs_internet = True

MODEL = "claude-haiku-4-5"   # PRD P-AI names Haiku: cheapest model that can write the report
MAX_OUTPUT_TOKENS = 4096     # output half of the per-run token budget


class AIAudit:
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self._last_run = 0.0
        self.outdir = os.path.join(shared_data.output_dir, "reports")
        # Injectable for tests, same pattern as WpaSecImport's _urlopen / bettercap_pwn.can_start.
        self._client_factory = self._default_client
        logger.info("AIAudit initialized.")

    @staticmethod
    def _default_client():
        # Deferred: the Pi does not need the SDK installed unless this action is switched on.
        import anthropic
        return anthropic.Anthropic()

    def _vulns_by_ip(self):
        """IP -> vuln tokens from vulnerability_summary.csv. Missing file is normal (no scan yet)."""
        found = {}
        try:
            with open(self.shared_data.vuln_summary_file, newline="",
                      encoding="utf-8", errors="replace") as f:
                for row in csv.DictReader(f):
                    ip = (row.get("IP") or "").strip()
                    tokens = (row.get("Vulnerabilities") or "").strip()
                    if ip and tokens:
                        found.setdefault(ip, []).extend(
                            t.strip() for t in tokens.split(";") if t.strip())
        except (FileNotFoundError, OSError):
            pass
        return found

    def execute(self):
        try:
            if not getattr(self.shared_data, "ai_triage_enabled", False):
                return 'skipped'
            if not (os.environ.get("ANTHROPIC_API_KEY") or "").strip():
                logger.info("ANTHROPIC_API_KEY not set in the environment; skipping AI audit.")
                return 'skipped'

            interval = getattr(self.shared_data, "ai_triage_interval", 3600)
            now = time.time()
            if interval and (now - self._last_run) < interval:
                return 'skipped'

            hosts = ai_triage.redact(
                self.shared_data.read_data(),
                vulns_by_ip=self._vulns_by_ip(),
                max_hosts=getattr(self.shared_data, "ai_triage_max_hosts",
                                  ai_triage.MAX_HOSTS_DEFAULT),
            )
            if not hosts:
                logger.info("No alive hosts with findings; skipping AI audit.")
                return 'skipped'

            # Clock starts on a real attempt, not on the decision to try — the same bug the
            # Wi-Fi scanner had, where a failed acquire burned the whole interval.
            self._last_run = now
            report = self._ask(hosts)
            if not report:
                return 'skipped'

            path = self._save(report)
            logger.info(f"AI audit written to {path} ({len(hosts)} hosts).")
            return 'success'
        except Exception as e:
            logger.error(f"Error in AIAudit: {e}")
            return 'failed'

    def _ask(self, hosts):
        """One Messages call. Returns the report text, or None when the call could not run
        (missing SDK, transport/API error) — a scan that cannot run is not a failure."""
        try:
            client = self._client_factory()
        except ImportError:
            logger.info("anthropic package not installed (pip install anthropic); skipping.")
            return None
        except Exception as e:
            # Building the client can fail too (malformed key, no egress at construction).
            # Same class of event as the call failing: the audit did not run.
            logger.warning(f"AI audit client unavailable ({type(e).__name__}: {e}); skipping.")
            return None
        try:
            response = client.messages.create(
                model=MODEL,
                max_tokens=MAX_OUTPUT_TOKENS,
                system=ai_triage.SYSTEM,
                messages=[{"role": "user", "content": ai_triage.build_user_message(hosts)}],
            )
        except Exception as e:      # transport, auth, rate limit — all "did not run"
            logger.warning(f"AI audit call failed ({type(e).__name__}: {e}); skipping this pass.")
            return None

        usage = getattr(response, "usage", None)
        if usage is not None:
            logger.info(f"AI audit tokens: in={getattr(usage, 'input_tokens', '?')} "
                        f"out={getattr(usage, 'output_tokens', '?')}")
        text = "".join(b.text for b in response.content if getattr(b, "type", "") == "text")
        return text.strip() or None

    def _save(self, report):
        os.makedirs(self.outdir, exist_ok=True)
        path = os.path.join(self.outdir,
                            f"ai_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(report + "\n")
        return path
