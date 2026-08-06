"""Secrets must not reach the logs.

save_configuration() logged the whole params dict at INFO, so every save from the Telegram page
wrote the bot token and SMTP password into data/logs — which scripts/bjorn_diag.sh then tails into
a report meant for pasting into an issue. Pure string check: no SharedData, no web stack.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def _redact(params):
    """WebUtils._redact_params without importing utils.py (which needs starlette/fastapi)."""
    src = (ROOT / "utils.py").read_text(encoding="utf-8")
    parts = re.search(r'_SECRET_KEY_PARTS = \((.*?)\)', src, re.S).group(1)
    secret_parts = tuple(p.strip().strip('"\'') for p in parts.split(",") if p.strip())
    return {k: ("***" if any(p in k.lower() for p in secret_parts) and v else v)
            for k, v in params.items()}


SECRETS = {
    "telegram_bot_token": "123456:AAE-REAL-TOKEN",
    "smtp_password": "hunter2",
    "wpasec_api_key": "deadbeef",
}


def test_secret_values_are_redacted():
    out = _redact(dict(SECRETS))
    for key, value in SECRETS.items():
        assert out[key] == "***", f"{key} was not redacted"
        assert value not in str(out)


def test_keys_are_kept_so_the_log_is_still_useful():
    """Which keys a save touched is the diagnostic value; their values never were."""
    out = _redact({"telegram_bot_token": "x", "scan_interval": 180, "epd_type": "mock"})
    assert set(out) == {"telegram_bot_token", "scan_interval", "epd_type"}
    assert out["scan_interval"] == 180 and out["epd_type"] == "mock"


def test_empty_secret_stays_empty_rather_than_looking_set():
    """'***' for an unset token would read as configured — the opposite of the truth."""
    assert _redact({"smtp_password": ""})["smtp_password"] == ""


def test_future_secret_key_names_are_covered():
    """Substring match on the key name, so a new *_token / *_password needs no code change."""
    out = _redact({"bettercap_api_password": "p", "some_new_token": "t", "oauth_secret": "s"})
    assert all(v == "***" for v in out.values())


def test_the_diag_script_never_prints_secret_values():
    """scripts/bjorn_diag.sh prints config for pasting into issues — its allow-list includes the
    secret keys on purpose (presence is diagnostic) and must redact each one."""
    src = (ROOT / "scripts" / "bjorn_diag.sh").read_text(encoding="utf-8")
    assert 'SECRET = ("token", "password", "api_key", "secret", "passwd")' in src
    assert '"<set>" if v else "<empty>"' in src
    # The old fallback grepped the config for '...|telegram|...' and printed matching lines
    # verbatim, bot token included. Comments are stripped first — the fix documents the old
    # pattern, and matching that would be a false positive.
    code = [ln for ln in src.splitlines() if not ln.lstrip().startswith("#")]
    offenders = [ln for ln in code if "grep" in ln and "telegram" in ln]
    assert not offenders, f"config grep would print secret values verbatim: {offenders}"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
