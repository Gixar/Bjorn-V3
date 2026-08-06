"""Tests that references resolve: config keys moved onto their own module pages, nav links that
reach a real routable page, and docs that point at scripts which still exist.

Pure text checks over the source files — no imports, no stubs, no browser. The failure these
exist to catch is a config key hidden from the generic Config form with no other page able to
set it, which makes a setting silently unreachable from the UI.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "web"

CONFIG_JS = (WEB / "scripts" / "config.js").read_text(encoding="utf-8")
COMMON_JS = (WEB / "scripts" / "common.js").read_text(encoding="utf-8")
WEBAPP_PY = (ROOT / "webapp.py").read_text(encoding="utf-8")
SHARED_PY = (ROOT / "shared.py").read_text(encoding="utf-8")

# Keys come from get_default_config(), not config/shared_config.json — the shipped JSON is a
# saved runtime config that lags the defaults until something writes it (load_config() merges
# defaults over it in memory). Text-scraped to keep this test import-free.
CONFIG_KEYS = re.findall(
    r'^\s*"([a-z_][a-z0-9_]*)"\s*:',
    SHARED_PY.split("def get_default_config")[1].split("def update_mac_blacklist")[0],
    re.M,
)


def hidden_prefixes():
    """The prefixes config.js filters out of the generic form, with their owning page."""
    block = CONFIG_JS.split("const PAGE_OWNED_KEYS")[1].split("];")[0]
    return re.findall(r'prefix:\s*"([^"]+)".*?href:\s*"/([^"]+)\.html"', block)


def nav_pages():
    return re.findall(r'href:\s*"/([a-z_]+)\.html"', COMMON_JS)


def test_every_hidden_key_is_settable_on_its_page():
    """A key removed from the Config form must be written by the owning page's script."""
    owned = hidden_prefixes()
    assert owned, "PAGE_OWNED_KEYS not found in config.js"

    for key in CONFIG_KEYS:
        match = next((o for o in owned if key.startswith(o[0])), None)
        if not match:
            continue
        _prefix, page = match
        script = WEB / "scripts" / f"{page}.js"
        assert script.exists(), f"{key} is hidden and points at a missing {script.name}"
        assert key in script.read_text(encoding="utf-8"), (
            f"'{key}' is hidden from the Config form but {script.name} never sets it — "
            f"the setting would be unreachable from the web UI"
        )


def test_hidden_prefixes_actually_match_something():
    """A stale prefix (renamed key) would silently stop hiding anything."""
    for prefix, _page in hidden_prefixes():
        assert any(k.startswith(prefix) for k in CONFIG_KEYS), \
            f"no config key starts with '{prefix}' — stale entry in PAGE_OWNED_KEYS"


def test_nav_links_resolve_to_routable_pages():
    """Every nav entry needs both an .html file and a webapp._PAGES entry, or it 404s."""
    pages = set(re.search(r"_PAGES = \{(.*?)\}", WEBAPP_PY, re.S).group(1).split())
    pages = {p.strip('",') for p in pages if p.startswith('"')}

    for page in nav_pages():
        assert (WEB / f"{page}.html").exists(), f"nav links /{page}.html but the file is missing"
        assert page in pages, f"/{page}.html is in the nav but not in webapp._PAGES — it 404s"


def test_help_page_is_reachable_and_points_at_the_module_pages():
    assert "help" in nav_pages(), "the Help page is not linked from the nav"
    help_html = (WEB / "help.html").read_text(encoding="utf-8")
    for _prefix, page in hidden_prefixes():
        assert f"/{page}.html" in help_html, f"Help doesn't link to the {page} page"


def test_docs_only_reference_scripts_that_exist():
    """Renaming or merging a script leaves the docs pointing at a file that no longer exists —
    which is worst for a *diagnostic* script, since the reader is already stuck. Prose that names
    a retired script ("supersedes X", "replaced X") is fine; a runnable path is not."""
    runnable = re.compile(r'`?(?:sudo\s+)?(?:bash\s+|\./)?(?:[\w./-]*/)?scripts/([\w.-]+\.(?:sh|py))')
    missing = []
    for doc in list(ROOT.glob("*.md")) + list((ROOT / "docs").glob("*.md")) + [WEB / "help.html"]:
        if doc.name == "CHANGELOG.md":
            continue  # a historical record; it names scripts as they were at the time
        for line in doc.read_text(encoding="utf-8").splitlines():
            if re.search(r"supersed|replaced|renamed|used to be", line, re.I):
                continue
            for name in runnable.findall(line):
                if not (ROOT / "scripts" / name).exists():
                    missing.append(f"{doc.name}: scripts/{name}")
    assert not missing, f"docs reference scripts that don't exist: {missing}"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
