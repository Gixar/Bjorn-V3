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
}

function wifiFillConfig(cfg) {
    document.getElementById("wifi-enabled").checked = !!cfg.wifi_scan_enabled;
    document.getElementById("wifi-duration").value =
        cfg.wifi_scan_duration !== undefined ? cfg.wifi_scan_duration : 30;
    document.getElementById("wifi-interval").value =
        cfg.wifi_scan_interval !== undefined ? cfg.wifi_scan_interval : 900;
    wifiLoadIfaces(cfg.wifi_scan_iface || "");
}

async function wifiSave() {
    const iface = document.getElementById("wifi-iface").value;
    if (document.getElementById("wifi-enabled").checked && !iface) {
        toast("Pick a monitor-mode interface first", "error");
        return;
    }
    const body = {
        wifi_scan_enabled: document.getElementById("wifi-enabled").checked,
        wifi_scan_iface: iface,
        wifi_scan_duration: parseInt(document.getElementById("wifi-duration").value, 10) || 30,
        wifi_scan_interval: parseInt(document.getElementById("wifi-interval").value, 10) || 0,
    };
    try {
        await postJson("/save_config", body);
        toast("Wi-Fi config saved", "success");
    } catch (e) {
        toast(e.message || "Save failed", "error");
    }
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
