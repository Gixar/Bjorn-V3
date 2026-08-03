// telegram.js — Telegram config + test/send (config saves via the shared /save_config merge)

function tgToggleReveal() {
    const el = document.getElementById("tg-token");
    if (el) el.type = el.type === "password" ? "text" : "password";
}

function tgFillFromConfig(cfg) {
    document.getElementById("tg-enabled").checked = !!cfg.telegram_enabled;
    document.getElementById("tg-creds").checked = !!cfg.telegram_include_creds;
    document.getElementById("tg-token").value = cfg.telegram_bot_token || "";
    document.getElementById("tg-chat").value = cfg.telegram_chat_id || "";
    document.getElementById("tg-interval").value =
        cfg.telegram_min_interval !== undefined ? cfg.telegram_min_interval : 300;
}

function tgGather() {
    return {
        telegram_enabled: document.getElementById("tg-enabled").checked,
        telegram_include_creds: document.getElementById("tg-creds").checked,
        telegram_bot_token: document.getElementById("tg-token").value.trim(),
        telegram_chat_id: document.getElementById("tg-chat").value.trim(),
        telegram_min_interval: parseInt(document.getElementById("tg-interval").value, 10) || 0,
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

document.addEventListener("DOMContentLoaded", () => {
    if (typeof renderNav === "function") renderNav();
    fetch("/load_config").then((r) => r.json()).then(tgFillFromConfig).catch(() => {});
});
