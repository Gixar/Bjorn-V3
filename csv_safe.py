# csv_safe.py
# CSV formula-injection guard (CWE-1236). Bjorn writes remote-controlled data (SNMP sysDescr, HTTP
# Server/Title headers, wpa-sec SSIDs, cracked creds) into CSVs that a user may later open in
# Excel/LibreOffice, where a cell starting with = + - @ (or a leading tab/CR) is evaluated as a
# formula. Prefix such cells with an apostrophe so they render as literal text. Dependency-free so
# every writer (in shared.py or the action modules) can import it.


def sanitize_cell(value):
    """Neutralize a spreadsheet formula trigger: a leading = + - @ / tab / CR gets an apostrophe."""
    s = "" if value is None else str(value)
    if s and s[0] in ('=', '+', '-', '@', '\t', '\r'):
        return "'" + s
    return s


def sanitize_row(row):
    """Apply sanitize_cell to every field of a row (list) before it is written to a CSV."""
    return [sanitize_cell(c) for c in row]
