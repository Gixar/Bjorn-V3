// telegram.js — report delivery config (Telegram + SMTP fallback) + test/send.
// Config saves via the shared /save_config merge.

function tgToggleReveal(id) {
    const el = document.getElementById(id);
    if (el) el.type = el.type === "password" ? "text" : "password";
}

function tgFillFromConfig(cfg) {
    document.getElementById("tg-enabled").checked = !!cfg.telegram_enabled;
    document.getElementById("tg-creds").checked = !!cfg.telegram_include_creds;
    document.getElementById("tg-token").value = cfg.telegram_bot_token || "";
    document.getElementById("tg-chat").value = cfg.telegram_chat_id || "";
    document.getElementById("tg-interval").value =
        cfg.telegram_min_interval !== undefined ? cfg.telegram_min_interval : 300;
    document.getElementById("smtp-enabled").checked = !!cfg.smtp_enabled;
    document.getElementById("smtp-host").value = cfg.smtp_host || "";
    document.getElementById("smtp-port").value = cfg.smtp_port !== undefined ? cfg.smtp_port : 587;
    document.getElementById("smtp-user").value = cfg.smtp_user || "";
    document.getElementById("smtp-password").value = cfg.smtp_password || "";
    document.getElementById("smtp-to").value = cfg.smtp_to || "";
}

function tgGather() {
    return {
        telegram_enabled: document.getElementById("tg-enabled").checked,
        telegram_include_creds: document.getElementById("tg-creds").checked,
        telegram_bot_token: document.getElementById("tg-token").value.trim(),
        telegram_chat_id: document.getElementById("tg-chat").value.trim(),
        telegram_min_interval: parseInt(document.getElementById("tg-interval").value, 10) || 0,
        smtp_enabled: document.getElementById("smtp-enabled").checked,
        smtp_host: document.getElementById("smtp-host").value.trim(),
        smtp_port: parseInt(document.getElementById("smtp-port").value, 10) || 587,
        smtp_user: document.getElementById("smtp-user").value.trim(),
        smtp_password: document.getElementById("smtp-password").value,
        smtp_to: document.getElementById("smtp-to").value.trim(),
    };
}

function tgStatus(msg) {
    const el = document.getElementById("tg-status");
    if (el) el.textContent = msg;
}

async function tgSave() {
    try {
        await postJson("/save_config", tgGather());
        toast("Telegram config saved", "success");
    } catch (e) {
        toast(e.message || "Save failed", "error");
    }
}

async function tgTest() {
    tgStatus("Sending test…");
    try {
        const d = await postJson("/telegram_test");
        toast(d.message || "Test sent", "success");
        tgStatus(d.message || "Test sent.");
    } catch (e) {
        toast(e.message || "Test failed", "error");
        tgStatus("Test failed: " + (e.message || ""));
    }
}

async function tgSendNow() {
    tgStatus("Sending data…");
    try {
        const d = await postJson("/telegram_send");
        toast(d.message || "Sent", "success");
        tgStatus(d.message || "Sent.");
    } catch (e) {
        toast(e.message || "Send failed", "error");
        tgStatus("Send failed: " + (e.message || ""));
    }
}

function tgBundleStatus(text) {
    const el = document.getElementById("tg-bundle-status");
    if (el) el.textContent = text;
}

function tgRefreshBundle() {
    fetch("/bundle_status")
        .then((r) => r.json())
        .then((d) => {
            const b = (d && d.bundle) || {};
            tgBundleStatus(b.exists
                ? `Bundle ready — ${Math.round(b.bytes / 1024)} KB, built ${b.built}`
                : "No bundle yet. Press Compile.");
        })
        .catch(() => tgBundleStatus("status unavailable"));
}

async function tgCompileBundle() {
    tgBundleStatus("Compiling…");
    try {
        const d = await postJson("/compile_bundle", {});
        const b = (d && d.bundle) || {};
        // Say whether credentials went in. The switch that decides it lives in the card above, so
        // the one thing worth confirming here is which way it was set when the archive was built.
        const creds = b.creds_included ? "with credentials" : "credentials excluded";
        toast(d.message || "Compiled", "success");
        tgBundleStatus(`Bundle ready — ${d.message}, ${creds}.`);
    } catch (e) {
        toast(e.message || "Compile failed", "error");
        tgBundleStatus("Compile failed: " + (e.message || ""));
    }
}

async function tgSendBundle() {
    tgBundleStatus("Sending bundle…");
    try {
        const d = await postJson("/send_bundle", {});
        toast(d.message || "Sent", "success");
        tgBundleStatus(d.message || "Sent.");
    } catch (e) {
        toast(e.message || "Send failed", "error");
        tgBundleStatus("Send failed: " + (e.message || ""));
    }
}

document.addEventListener("DOMContentLoaded", () => {
    if (typeof renderNav === "function") renderNav();
    fetch("/load_config").then((r) => r.json()).then(tgFillFromConfig).catch(() => {});
    tgRefreshBundle();
});
