// ble.js — BLE recon config (saved via /save_config merge) + results view (/ble_data)

function bleFillConfig(cfg) {
    document.getElementById("ble-enabled").checked = !!cfg.ble_scan_enabled;
    document.getElementById("ble-duration").value =
        cfg.ble_scan_duration !== undefined ? cfg.ble_scan_duration : 10;
    document.getElementById("ble-interval").value =
        cfg.ble_scan_interval !== undefined ? cfg.ble_scan_interval : 300;
}

async function bleSave() {
    const body = {
        ble_scan_enabled: document.getElementById("ble-enabled").checked,
        ble_scan_duration: parseInt(document.getElementById("ble-duration").value, 10) || 10,
        ble_scan_interval: parseInt(document.getElementById("ble-interval").value, 10) || 0,
    };
    try {
        await postJson("/save_config", body);
        toast("BLE config saved", "success");
    } catch (e) {
        toast(e.message || "Save failed", "error");
    }
}

function bleRenderDevices(devices) {
    const body = document.getElementById("ble-body");
    const count = document.getElementById("ble-count");
    if (count) count.textContent = `${devices.length} device(s)`;
    if (!body) return;
    body.replaceChildren();  // textContent cells — device names are untrusted
    devices.forEach((d) => {
        const tr = document.createElement("tr");
        [d.MAC, d.Name, d.Tracker === "yes" ? "⚠ tracker" : "", d.FirstSeen, d.LastSeen]
            .forEach((val) => {
                const td = document.createElement("td");
                td.textContent = val || "";
                tr.appendChild(td);
            });
        body.appendChild(tr);
    });
}

function bleRefresh() {
    fetch("/ble_data")
        .then((r) => r.json())
        .then((d) => bleRenderDevices(d.devices || []))
        .catch(() => toast("Could not load BLE results", "error"));
}

document.addEventListener("DOMContentLoaded", () => {
    if (typeof renderNav === "function") renderNav();
    fetch("/load_config").then((r) => r.json()).then(bleFillConfig).catch(() => {});
    bleRefresh();
});
