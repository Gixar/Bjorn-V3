// wifi.js — Wi-Fi (airodump-ng) recon config + results view.
// Config saves via the shared /save_config merge; results come from /wifi_data.

let wifiUplink = "";

function wifiStatus(msg) {
    const el = document.getElementById("wifi-status");
    if (el) el.textContent = msg;
}

async function wifiLoadIfaces(selected) {
    const sel = document.getElementById("wifi-iface");
    if (!sel) return;
    sel.replaceChildren();
    let data = { interfaces: [], uplink: "" };
    try {
        data = await (await fetch("/wifi_ifaces")).json();
    } catch (e) { /* iw missing or not a Pi — leave the dropdown empty */ }
    wifiUplink = data.uplink || "";

    const blank = document.createElement("option");
    blank.value = "";
    blank.textContent = data.interfaces.length ? "— select a radio —" : "no wireless interfaces found";
    sel.appendChild(blank);

    (data.interfaces || []).forEach((i) => {
        const opt = document.createElement("option");
        opt.value = i.name;
        // Label, don't hide: an unexplained missing interface reads as a bug.
        opt.textContent = i.uplink ? `${i.name} (Bjorn's uplink — cannot be used)` : i.name;
        opt.disabled = !!i.uplink;
        sel.appendChild(opt);
    });
    if (selected) sel.value = selected;

    if (data.configured_missing) {
        wifiStatus(`Configured radio "${data.configured}" is not present. `
            + `Interface names follow probe order, so a dongle moved to another USB port or `
            + `re-enumerated after a reboot can come back under a different name. `
            + `Pick it again below and Save.`);
    }
}

function wifiFillConfig(cfg) {
    document.getElementById("wifi-enabled").checked = !!cfg.wifi_scan_enabled;
    document.getElementById("wifi-duration").value =
        cfg.wifi_scan_duration !== undefined ? cfg.wifi_scan_duration : 30;
    document.getElementById("wifi-interval").value =
        cfg.wifi_scan_interval !== undefined ? cfg.wifi_scan_interval : 900;
    document.getElementById("wifi-band").value = cfg.wifi_scan_band || "bg";
    document.getElementById("wifi-channel").value =
        cfg.wifi_scan_channel !== undefined ? cfg.wifi_scan_channel : 0;
    document.getElementById("offline-enabled").checked = cfg.offline_mode_enabled !== false;
    document.getElementById("offline-wifi-interval").value =
        cfg.wifi_scan_interval_offline !== undefined ? cfg.wifi_scan_interval_offline : 120;
    document.getElementById("offline-cycle").value =
        cfg.offline_cycle_interval !== undefined ? cfg.offline_cycle_interval : 60;
    document.getElementById("wifi-autojoin").checked = cfg.wifi_autojoin !== false;
    document.getElementById("wifi-autojoin-open").checked = !!cfg.wifi_autojoin_open;
    wifiLoadIfaces(cfg.wifi_scan_iface || "");
}

async function wifiSave() {
    const iface = document.getElementById("wifi-iface").value;
    // No longer a blocking error: with offline recon on, a Bjorn with no dongle still scans (on the
    // onboard radio, only while there is no uplink). It just won't scan while connected.
    if (document.getElementById("wifi-enabled").checked && !iface) {
        toast("No monitor interface picked — Bjorn will only scan while offline", "info");
    }
    const body = {
        wifi_scan_enabled: document.getElementById("wifi-enabled").checked,
        wifi_scan_iface: iface,
        wifi_scan_duration: parseInt(document.getElementById("wifi-duration").value, 10) || 30,
        wifi_scan_interval: parseInt(document.getElementById("wifi-interval").value, 10) || 0,
        wifi_scan_band: document.getElementById("wifi-band").value,
        wifi_scan_channel: parseInt(document.getElementById("wifi-channel").value, 10) || 0,
        offline_mode_enabled: document.getElementById("offline-enabled").checked,
        wifi_scan_interval_offline: parseInt(document.getElementById("offline-wifi-interval").value, 10) || 0,
        offline_cycle_interval: parseInt(document.getElementById("offline-cycle").value, 10) || 60,
        wifi_autojoin: document.getElementById("wifi-autojoin").checked,
        wifi_autojoin_open: document.getElementById("wifi-autojoin-open").checked,
    };
    try {
        await postJson("/save_config", body);
        toast("Wi-Fi config saved", "success");
    } catch (e) {
        toast(e.message || "Save failed", "error");
    }
}

// Run one capture right now. The backend returns as soon as it has started the thread (a capture is
// 30s+), so the countdown here is cosmetic — the real completion signal is the results table.
async function wifiScanNow() {
    const btn = document.getElementById("wifi-scan-btn");
    const iface = document.getElementById("wifi-iface").value;
    if (!iface) {
        toast("Pick an interface first", "error");
        return;
    }
    let d;
    try {
        d = await postJson("/wifi_scan_now");
    } catch (e) {
        toast(e.message || "Could not start the capture", "error");
        wifiStatus("Scan failed to start: " + (e.message || ""));
        return;
    }
    toast(d.message || "Capture started", "success");

    // Disabled for the capture window: a second click would be refused by the radio lock anyway,
    // and an error toast for pressing an enabled button reads as a bug.
    let left = (d.duration || 30) + 3;
    btn.disabled = true;
    const tick = setInterval(() => {
        left -= 1;
        wifiStatus(`Capturing on ${iface}… ${left}s`);
        if (left <= 0) {
            clearInterval(tick);
            btn.disabled = false;
            wifiStatus("Capture finished — results refreshed.");
            wifiRefresh();
        }
    }, 1000);
}

async function wifiTestMonitor() {
    const iface = document.getElementById("wifi-iface").value;
    if (!iface) {
        toast("Pick an interface first", "error");
        return;
    }
    wifiStatus("Testing " + iface + "…");
    try {
        const d = await postJson("/wifi_monitor_test", { iface });
        toast(d.message || "Supported", "success");
        wifiStatus(d.message || "Supported.");
    } catch (e) {
        toast(e.message || "Test failed", "error");
        wifiStatus("Test failed: " + (e.message || ""));
    }
}

function wifiFillTable(bodyId, countId, rows, cols, label) {
    const body = document.getElementById(bodyId);
    const count = document.getElementById(countId);
    if (count) count.textContent = `${rows.length} ${label}`;
    if (!body) return;
    body.replaceChildren();  // textContent cells — ESSIDs are untrusted input
    rows.forEach((r) => {
        const tr = document.createElement("tr");
        cols.forEach((c) => {
            const td = document.createElement("td");
            td.textContent = r[c] || "";
            tr.appendChild(td);
        });
        body.appendChild(tr);
    });
}

function wifiRefresh() {
    fetch("/wifi_data")
        .then((r) => r.json())
        .then((d) => {
            wifiFillTable("wifi-ap-body", "wifi-ap-count", d.aps || [],
                ["BSSID", "ESSID", "Channel", "Privacy", "Cipher", "Auth", "Power", "Beacons",
                    "LastSeen"], "AP(s)");
            wifiFillTable("wifi-client-body", "wifi-client-count", d.clients || [],
                ["Station", "BSSID", "Power", "Packets", "ProbedESSIDs", "LastSeen"], "client(s)");
        })
        .catch(() => toast("Could not load Wi-Fi results", "error"));
}

document.addEventListener("DOMContentLoaded", () => {
    if (typeof renderNav === "function") renderNav();
    fetch("/load_config").then((r) => r.json()).then(wifiFillConfig).catch(() => {});
    wifiRefresh();
});
