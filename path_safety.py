"""Path-containment guards for the unauthenticated web surface.

Its own dependency-free module (stdlib only) so the security-critical logic is unit-testable
without importing utils.py — which pulls in starlette/fastapi and cannot load in the zero-install
test env (same reason retry_policy / config_validation / stats_engine are standalone).

The web UI serves file downloads and accepts an uploaded backup zip on 0.0.0.0 with no auth, so a
`?path=../../etc/passwd`, an absolute path, or a zip member like `../../home/bjorn/.ssh/...` would
otherwise read or write arbitrary files. These two functions confine both.
"""

import os


def safe_under(base, user_path):
    """Resolve base/user_path and return it only if it stays inside base — else None.

    realpath resolves `..` and symlinks; the commonpath check is what actually confines it.
    Note os.path.join drops `base` entirely when user_path is absolute — realpath+commonpath
    catches that too. Callers should 404 on None and never echo the requested path back."""
    base_real = os.path.realpath(base)
    target = os.path.realpath(os.path.join(base_real, user_path))
    try:
        if target != base_real and os.path.commonpath([base_real, target]) != base_real:
            return None
    except ValueError:
        return None  # different drives (Windows) / mixed abs+rel — treat as escape
    return target


def zip_escapes(namelist, dest):
    """Return the first zip member name that would extract outside dest, or None if all are safe.

    Zip-slip: extractall() honours `..` and absolute member paths, so one crafted member escapes
    the target dir. Validate every member before extracting a single byte; reject the whole
    archive on the first escape."""
    dest_real = os.path.realpath(dest)
    for member in namelist:
        target = os.path.realpath(os.path.join(dest_real, member))
        if target != dest_real and os.path.commonpath([dest_real, target]) != dest_real:
            return member
    return None


def _demo():
    """Runnable self-check: assert-based, no framework. `python path_safety.py`."""
    import tempfile
    with tempfile.TemporaryDirectory() as base:
        inside = os.path.join(base, "loot", "a.txt")
        os.makedirs(os.path.dirname(inside), exist_ok=True)
        open(inside, "w").close()
        assert safe_under(base, "loot/a.txt") == os.path.realpath(inside)
        assert safe_under(base, "../../etc/passwd") is None
        assert safe_under(base, "loot/../../../etc/passwd") is None
        # absolute path must not escape (os.path.join drops base)
        assert safe_under(base, os.path.abspath(os.sep + "etc")) is None
        assert zip_escapes(["ok.txt", "sub/ok.txt"], base) is None
        assert zip_escapes(["../evil"], base) == "../evil"
        assert zip_escapes(["sub/../../evil"], base) == "sub/../../evil"
    print("ok")


if __name__ == "__main__":
    _demo()
