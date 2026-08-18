// bettercap.js — Bettercap config (saved via /save_config merge) + live status (/bettercap_status)

function bcToggleReveal(id) {
    const el = document.getElementById(id);
    if (el) el.type = el.type === "password" ? "text" : "password";
}

function bcInt(id, fallback) {
    const n = parseInt(document.getElementById(id).value, 10);
    return Number.isNaN(n) ? fallback : n;
}

function bcFillConfig(cfg) {
    document.getElementById("bc-enabled").checked = !!cfg.bettercap_enabled;
    document.getElementById("bc-url").value = cfg.bettercap_api_url || "http://127.0.0.1:8081";
    document.getElementById("bc-user").value = cfg.bettercap_user || "bjorn";
    document.getElementById("bc-password").value = cfg.bettercap_password || "";
    document.getElementById("bc-arp").checked = !!cfg.bettercap_arp_spoof;
    document.getElementById("bc-sniff").checked = !!cfg.bettercap_sniff;
    document.getElementById("bc-pwn-enabled").checked = !!cfg.bettercap_pwn_enabled;
    document.getElementById("bc-pwn-iface").value = cfg.bettercap_pwn_iface || "";
    document.getElementById("bc-pwn-rssi").value =
        cfg.bettercap_pwn_min_rssi !== undefined ? cfg.bettercap_pwn_min_rssi : -80;
    document.getElementById("bc-pwn-max-age").value =
        cfg.bettercap_pwn_max_target_age !== undefined ? cfg.bettercap_pwn_max_target_age : 600;
}

async function bcSave() {
    const body = {
        bettercap_enabled: document.getElementById("bc-enabled").checked,
        bettercap_api_url: document.getElementById("bc-url").value.trim(),
        bettercap_user: document.getElementById("bc-user").value.trim(),
        bettercap_password: document.getElementById("bc-password").value,
        bettercap_arp_spoof: document.getElementById("bc-arp").checked,
        bettercap_sniff: document.getElementById("bc-sniff").checked,
        bettercap_pwn_enabled: document.getElementById("bc-pwn-enabled").checked,
        bettercap_pwn_iface: document.getElementById("bc-pwn-iface").value.trim(),
        bettercap_pwn_min_rssi: parseInt(document.getElementById("bc-pwn-rssi").value, 10) || -80,
        // Not `|| 600`: 0 is the documented "never forget" setting, and || would silently discard
        // it and write the default back over the user's choice.
        bettercap_pwn_max_target_age: bcInt("bc-pwn-max-age", 600),
    };
    try {
        await postJson("/save_config", body);
        toast("Bettercap config saved", "success");
        bcRefreshStatus();
    } catch (e) {
        toast(e.message || "Save failed", "error");
    }
}

function bcRefreshStatus() {
    const el = document.getElementById("bc-status");
    if (el) el.textContent = "Checking…";
    fetch("/bettercap_status")
        .then((r) => r.json())
        .then((d) => {
            if (!el) return;
            // The handler answers with a plain sentence per state — "disabled", "unreachable",
            // "unauthorized", "running v2.x". Rendering it verbatim keeps the wording in one
            // place; two copies of these strings would be two chances to describe a state wrongly.
            el.textContent = d.message || "unknown";
            // The hunter's line is its own: "ready to hunt on wlan1" and "only 1 wireless radio"
            // are the two answers an operator actually needs, and both come from can_start() so
            // the page cannot disagree with the code about why nothing is happening.
            const h = document.getElementById("bc-hunter-status");
            if (h) h.textContent = d.hunter || "unknown";
            const loot = document.getElementById("bc-loot");
            if (loot && d.loot) {
                loot.textContent = d.loot.captures
                    ? `${d.loot.captures} capture(s) from ${d.loot.unique_bssids} network(s)` +
                      (d.loot.updated ? ` — indexed ${d.loot.updated}` : "")
                    : "No captures yet.";
            }
        })
        .catch(() => {
            if (el) el.textContent = "status unavailable";
            const h = document.getElementById("bc-hunter-status");
            if (h) h.textContent = "status unavailable";
        });
    // #5(a): surface BettercapPoller._last_error (via /api/stats) in red when non-null.
    fetch("/api/stats")
        .then((r) => r.json())
        .then((s) => {
            const errEl = document.getElementById("bc-last-error");
            if (!errEl) return;
            const msg = s.bettercap_last_error;
            if (msg) {
                errEl.textContent = "Last poll error: " + msg;
                errEl.style.display = "";
            } else {
                errEl.textContent = "";
                errEl.style.display = "none";
            }
        })
        .catch(() => {});
}

async function bcHuntNow() {
    // Disabled for the session's length, like the Wi-Fi "Scan now" button: the radio is taken for
    // the whole window, and a second click would only be told "already hunting".
    const btn = document.getElementById("bc-hunt-btn");
    try {
        const r = await postJson("/bettercap_hunt_now", {});
        const secs = (r && r.duration) || 60;
        if (btn) { btn.disabled = true; btn.textContent = `Hunting (${secs}s)…`; }
        toast(`Hunting for ${secs}s`, "success");
        setTimeout(() => {
            if (btn) { btn.disabled = false; btn.textContent = "Hunt now (60s)"; }
            bcRefreshStatus();
        }, (secs + 5) * 1000);
    } catch (e) {
        toast(e.message || "Could not start hunting", "error");
    }
}

document.addEventListener("DOMContentLoaded", () => {
    if (typeof renderNav === "function") renderNav();
    fetch("/load_config").then((r) => r.json()).then(bcFillConfig).catch(() => {});
    bcRefreshStatus();
});
