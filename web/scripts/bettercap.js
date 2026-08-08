// bettercap.js — Bettercap config (saved via /save_config merge) + live status (/bettercap_status)

function bcToggleReveal(id) {
    const el = document.getElementById(id);
    if (el) el.type = el.type === "password" ? "text" : "password";
}

function bcFillConfig(cfg) {
    document.getElementById("bc-enabled").checked = !!cfg.bettercap_enabled;
    document.getElementById("bc-url").value = cfg.bettercap_api_url || "http://127.0.0.1:8081";
    document.getElementById("bc-user").value = cfg.bettercap_user || "bjorn";
    document.getElementById("bc-password").value = cfg.bettercap_password || "";
    document.getElementById("bc-arp").checked = !!cfg.bettercap_arp_spoof;
    document.getElementById("bc-sniff").checked = !!cfg.bettercap_sniff;
}

async function bcSave() {
    const body = {
        bettercap_enabled: document.getElementById("bc-enabled").checked,
        bettercap_api_url: document.getElementById("bc-url").value.trim(),
        bettercap_user: document.getElementById("bc-user").value.trim(),
        bettercap_password: document.getElementById("bc-password").value,
        bettercap_arp_spoof: document.getElementById("bc-arp").checked,
        bettercap_sniff: document.getElementById("bc-sniff").checked,
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
        })
        .catch(() => {
            if (el) el.textContent = "status unavailable";
        });
}

document.addEventListener("DOMContentLoaded", () => {
    if (typeof renderNav === "function") renderNav();
    fetch("/load_config").then((r) => r.json()).then(bcFillConfig).catch(() => {});
    bcRefreshStatus();
});
