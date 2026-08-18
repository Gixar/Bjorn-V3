# csv_safe.py
# CSV formula-injection guard (CWE-1236). Bjorn writes remote-controlled data (SNMP sysDescr, HTTP
# Server/Title headers, wpa-sec SSIDs, cracked creds) into CSVs that a user may later open in
# Excel/LibreOffice, where a cell starting with = + - @ (or a leading tab/CR) is evaluated as a
# formula. Prefix such cells with an apostrophe so they render as literal text. Dependency-free so
# every writer (in shared.py or the action modules) can import it.
#
# The guard is for spreadsheets, and it has to come back OFF wherever Bjorn PARSES its own CSVs —
# see unsanitize_cell. Skipping that is what silently blinded the Wi-Fi hunter for a whole day.
# Readers that only copy values through (the wifi/BLE scan merges, the report, the web tables) can
# leave it on: sanitize_cell is idempotent, so a guarded value survives a read-modify-write
# unchanged. It is the readers that call int() on the result that must strip it first.

TRIGGERS = ('=', '+', '-', '@', '\t', '\r')


def sanitize_cell(value):
    """Neutralize a spreadsheet formula trigger: a leading = + - @ / tab / CR gets an apostrophe."""
    s = "" if value is None else str(value)
    if s and s[0] in TRIGGERS:
        return "'" + s
    return s


def sanitize_row(row):
    """Apply sanitize_cell to every field of a row (list) before it is written to a CSV."""
    return [sanitize_cell(c) for c in row]


def unsanitize_cell(value):
    """Exact inverse of sanitize_cell: drop the guard apostrophe, and only the guard apostrophe.

    Several of these CSVs are not just output — Bjorn reads them back to make decisions. Signal
    strength is the case that bit: dBm is always negative, so every Power lands on disk as "'-67",
    which is not an int. The hunter's min_rssi filter and its whole proximity score both went
    through int(), both hit the except branch, and the ranking silently degenerated to "has clients
    + is WPA" over a table that never expires. On 2026-08-17 that parked the radio on one 5 GHz
    channel for 9h53m of a 10h walk and produced zero handshakes.

    Only one apostrophe is ever there to remove: sanitize_cell is idempotent, because "'" is not
    itself a trigger, so a guarded value that survives a read-modify-write cycle does not ratchet.

    The `s[1] in TRIGGERS` test is what keeps this lossless. An ESSID that genuinely starts with an
    apostrophe was never prefixed by sanitize_cell, so it must not be trimmed here.
    """
    s = "" if value is None else str(value)
    return s[1:] if len(s) > 1 and s[0] == "'" and s[1] in TRIGGERS else s


def unsanitize_dict(row):
    """unsanitize_cell over a csv.DictReader row, for a reader that has to parse its own values.

    Non-str values are passed through untouched: DictReader hands back a *list* under the restkey
    when a row has more fields than the header, and str()-ing that would corrupt it.
    """
    return {k: (unsanitize_cell(v) if isinstance(v, str) else v) for k, v in row.items()}
