# credential_pool.py
# Credential reuse / lateral chaining (backlog Wave 1 #2). A shared pool of cracked
# (user, password) pairs that every brute-force connector records into on a hit and tries
# first on the next host — so a cred cracked on one host/protocol is auto-replayed across all
# the others. Read fresh per attack (the connectors are long-lived singletons), so reuse works
# within the same scan cycle. Kept dependency-free and separate from shared.py so it can be
# unit-tested without constructing SharedData (which pulls in PIL / the e-Paper stack).
import os
import csv
import threading
from csv_safe import sanitize_row

_known_creds_lock = threading.Lock()


def _known_creds_path(shared_data):
    return os.path.join(shared_data.crackedpwddir, "known_creds.csv")


def known_cred_pairs(shared_data):
    """(user, password) pairs cracked so far, from the shared pool CSV. [] if none/missing."""
    pairs = []
    try:
        with open(_known_creds_path(shared_data), newline='') as f:
            r = csv.reader(f)
            next(r, None)  # skip header
            for row in r:
                if len(row) >= 2:
                    pairs.append((row[0], row[1]))
    except FileNotFoundError:
        pass
    return pairs


def record_cracked_cred(shared_data, user, password):
    """Append (user, password) to the shared cracked-creds pool, deduped. Thread-safe (called
    from connector worker threads). No-op when credential_reuse is disabled."""
    if not getattr(shared_data, "credential_reuse", True):
        return
    path = _known_creds_path(shared_data)
    with _known_creds_lock:
        if (user, password) in set(known_cred_pairs(shared_data)):
            return
        new_file = not os.path.exists(path)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", newline='') as f:
            w = csv.writer(f)
            if new_file:
                w.writerow(["User", "Password"])
            w.writerow(sanitize_row([user, password]))


def credential_candidates(shared_data, users, passwords):
    """Ordered, deduped (user, password) attempts for one host: the cracked pool first (highest
    hit probability + cross-host/protocol reuse), then the full users x passwords product. Reads
    the pool fresh each call, so creds cracked earlier this cycle are reused immediately. Returns
    just the product when credential_reuse is disabled."""
    product = [(u, p) for u in users for p in passwords]
    if not getattr(shared_data, "credential_reuse", True):
        return product
    pairs, seen = [], set()
    for pair in known_cred_pairs(shared_data):
        if pair not in seen:
            seen.add(pair)
            pairs.append(pair)
    for pair in product:
        if pair not in seen:
            seen.add(pair)
            pairs.append(pair)
    return pairs
