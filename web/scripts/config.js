/* config.js — configuration form + Wi-Fi panel */

// Keys owned by a dedicated page, hidden from this generic form so each module is configured in
// one place — next to its own results, test buttons and manual. Prefix match, so a new key on an
// existing module needs no change here. /save_config merges key-by-key, so hidden keys survive
// a save from this page untouched.
const PAGE_OWNED_KEYS = [
    { prefix: "ble_scan_", href: "/ble.html", label: "BLE" },
    { prefix: "wifi_scan_", href: "/wifi.html", label: "Wi-Fi" },
    { prefix: "wifi_autojoin", href: "/wifi.html", label: "Wi-Fi" },
    { prefix: "offline_", href: "/wifi.html", label: "Wi-Fi" },
    { prefix: "telegram_", href: "/telegram.html", label: "Telegram" },
    { prefix: "smtp_", href: "/telegram.html", label: "Telegram" },
];

function pageOwner(key) {
    return PAGE_OWNED_KEYS.find((o) => key.startsWith(o.prefix));
}

function generateConfigForm(config) {
    const formElement = document.querySelector(".config-form");
    if (!formElement) return;
    formElement.innerHTML = "";

    const leftColumn = document.createElement("div");
    leftColumn.classList.add("left-column");

    const rightColumn = document.createElement("div");
    rightColumn.classList.add("right-column");

    for (const [key, value] of Object.entries(config)) {
        if (pageOwner(key)) {
            continue;
        } else if (key.startsWith("__title_")) {
            rightColumn.innerHTML += `<div class="section-title">${value}</div>`;
        } else if (typeof value === "boolean") {
            const checked = value ? "checked" : "";
            leftColumn.innerHTML += `
                <div class="label-switch">
                    <label class="switch">
                        <input type="checkbox" id="${key}" name="${key}" ${checked}>
                        <span class="slider round"></span>
                    </label>
                    <label for="${key}">${key}</label>
                </div>`;
        } else if (Array.isArray(value)) {
            const listValue = value.join(",");
            rightColumn.innerHTML += `
                <div class="section-item">
                    <label for="${key}">${key}</label>
                    <input type="text" id="${key}" name="${key}" value="${listValue}">
                </div>`;
        } else if (!isNaN(value) && !key.toLowerCase().includes("ip") && !key.toLowerCase().includes("mac")) {
            rightColumn.innerHTML += `
                <div class="section-item">
                    <label for="${key}">${key}</label>
                    <input type="number" id="${key}" name="${key}" value="${value}">
                </div>`;
        } else {
            rightColumn.innerHTML += `
                <div class="section-item">
                    <label for="${key}">${key}</label>
                    <input type="text" id="${key}" name="${key}" value="${value}">
                </div>`;
        }
    }

    formElement.appendChild(leftColumn);
    formElement.appendChild(rightColumn);

    // Say where the hidden keys went — a setting that silently vanished reads as a bug.
    const seen = [];
    PAGE_OWNED_KEYS.forEach((o) => {
        if (!seen.some((s) => s.href === o.href)) seen.push(o);
    });
    formElement.innerHTML +=
        `<p class="config-moved-note">Module settings live on their own page, next to their results
         and their manual: ` +
        seen.map((o) => `<a href="${o.href}">${o.label}</a>`).join(" · ") +
        `. New here? See the <a href="/help.html">Help</a> page.</p>`;
    formElement.innerHTML += '<div style="height: 40px; grid-column: 1 / -1;"></div>';
}

function saveConfig() {
    const formElement = document.querySelector(".config-form");
    if (!formElement) {
        if (typeof toast === "function") toast("Form not found", "error");
        return;
    }

    const formData = new FormData(formElement);
    const formDataObj = {};
    const arrayFields = [
        "portlist",
        "mac_scan_blacklist",
        "ip_scan_blacklist",
        "steal_file_names",
        "steal_file_extensions",
    ];

    formData.forEach((value, key) => {
        if (value.includes(",") || arrayFields.includes(key)) {
            formDataObj[key] = value.split(",").map((item) => {
                const trimmedItem = item.trim();
                return isNaN(trimmedItem) || trimmedItem === "" ? trimmedItem : parseFloat(trimmedItem);
            });
        } else {
            formDataObj[key] = value === "on" ? true : isNaN(value) ? value : parseFloat(value);
        }
    });

    formElement.querySelectorAll('input[type="checkbox"]').forEach((checkbox) => {
        if (!formData.has(checkbox.name)) formDataObj[checkbox.name] = false;
    });

    fetch("/save_config", {
        method: "POST",
        headers: { "Content-Type": "application/json;charset=UTF-8" },
        body: JSON.stringify(formDataObj),
    })
        .then((r) => r.json())
        .then((data) => {
            if (data.status === "error") throw new Error(data.message);
            if (typeof toast === "function") toast(data.message || "Configuration saved", "success");
            loadConfig();
        })
        .catch((e) => {
            if (typeof toast === "function") toast(e.message || "Save failed", "error");
            else alert("Failed to save configuration");
        });
}

function restoreDefault() {
    if (!confirm("Restore default configuration?")) return;
    fetch("/restore_default_config")
        .then((r) => r.json())
        .then((data) => {
            generateConfigForm(data);
            if (typeof toast === "function") toast("Defaults loaded (save to persist)", "info");
        })
        .catch((e) => {
            if (typeof toast === "function") toast(e.message, "error");
        });
}

function loadConfig() {
    fetch("/load_config")
        .then((r) => r.json())
        .then((data) => generateConfigForm(data))
        .catch((e) => console.error("load config", e));
}

// Run the nmap-vs-RustScan scan-engine benchmark, then poll for the result row it appends and
// toast the speedup. The backend runs it in a background thread (two discovery passes), so this
// can take a minute or two on a Pi.
function runBenchmark() {
    fetch("/benchmark_results")
        .then((r) => r.json())
        .then((data) => {
            const baseline = (data.results || []).length; // detect the new row this run adds
            return fetch("/run_benchmark", { method: "POST" })
                .then((r) => r.json())
                .then((d) => {
                    if (d.status === "error") throw new Error(d.message);
                    if (typeof toast === "function") toast(d.message || "Benchmark started", "info");
                    pollBenchmark(baseline, Date.now());
                });
        })
        .catch((e) => {
            if (typeof toast === "function") toast(e.message || "Benchmark failed to start", "error");
        });
}

function pollBenchmark(baseline, startedAt) {
    if (Date.now() - startedAt > 5 * 60 * 1000) {
        if (typeof toast === "function") toast("Benchmark timed out — see data/scan_engine_benchmark.csv", "error");
        return;
    }
    fetch("/benchmark_results")
        .then((r) => r.json())
        .then((data) => {
            const rows = data.results || [];
            if (rows.length > baseline) {
                const r = rows[rows.length - 1];
                const nmap = r["nmap Seconds"], rust = r["rustscan Seconds"], sp = r["Speedup (nmap/rustscan)"];
                const msg = sp
                    ? `nmap ${nmap}s vs RustScan ${rust}s — ${sp}× faster (${r.Hosts} hosts)`
                    : `nmap ${nmap}s · RustScan: ${rust || "skipped (not installed)"}`;
                if (typeof toast === "function") toast(msg, "success");
            } else {
                setTimeout(() => pollBenchmark(baseline, startedAt), 4000);
            }
        })
        .catch(() => setTimeout(() => pollBenchmark(baseline, startedAt), 4000));
}

let wifiIntervalId;

function toggleWifiPanel() {
    const wifiPanel = document.getElementById("wifi-panel");
    if (!wifiPanel) return;
    if (wifiPanel.style.display === "block") {
        clearInterval(wifiIntervalId);
        wifiPanel.style.display = "none";
    } else {
        scanWifi(true);
    }
}

function closeWifiPanel() {
    clearInterval(wifiIntervalId);
    const wifiPanel = document.getElementById("wifi-panel");
    if (wifiPanel) wifiPanel.style.display = "none";
}

function scanWifi(update = false) {
    fetch("/scan_wifi")
        .then((r) => r.json())
        .then((data) => {
            if (data.error) throw new Error(data.error);
            const wifiPanel = document.getElementById("wifi-panel");
            const wifiList = document.getElementById("wifi-list");
            if (!wifiList || !wifiPanel) return;
            wifiList.innerHTML = "";
            (data.networks || []).forEach((network) => {
                const li = document.createElement("li");
                li.innerText = network;
                li.setAttribute("data-ssid", network);
                li.onclick = () => connectWifi(network);
                if (network === data.current_ssid) {
                    li.classList.add("current-wifi");
                    li.innerText += " ✓";
                }
                wifiList.appendChild(li);
            });
            wifiPanel.style.display = "block";
            if (update) {
                clearInterval(wifiIntervalId);
                wifiIntervalId = setInterval(() => scanWifi(true), 5000);
            }
        })
        .catch((error) => {
            console.error("Wi-Fi scan:", error);
            if (typeof toast === "function") toast(error.message || "Wi-Fi scan failed", "error");
        });
}

function connectWifi(ssid) {
    const password = prompt("Enter the password for " + ssid);
    if (!password) return;
    // Optional static IP; blank fields → DHCP (backend defaults to method=auto).
    const ip_address = (document.getElementById("wifi-ip")?.value || "").trim();
    const gateway = (document.getElementById("wifi-gw")?.value || "").trim();
    const dns = (document.getElementById("wifi-dns")?.value || "").trim();
    fetch("/connect_wifi", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ssid, password, ip_address, gateway, dns }),
    })
        .then((r) => r.json())
        .then((data) => {
            if (data.status === "error") throw new Error(data.message);
            if (typeof toast === "function") toast(data.message || "Connected", "success");
            else alert(data.message);
        })
        .catch((error) => {
            if (typeof toast === "function") toast(error.message || "Connect failed", "error");
            else alert("Error: " + error);
        });
}

let fontSize = /Mobi|Android/i.test(navigator.userAgent) ? 12 : 13;

function adjustConfigFontSize(change) {
    fontSize += change;
    document.querySelectorAll(".section-item, .section-title, .label-switch, .config-form").forEach((el) => {
        el.style.fontSize = fontSize + "px";
    });
}

document.addEventListener("DOMContentLoaded", () => {
    if (typeof renderNav === "function") renderNav();
    loadConfig();
});

window.saveConfig = saveConfig;
window.restoreDefault = restoreDefault;
window.toggleWifiPanel = toggleWifiPanel;
window.closeWifiPanel = closeWifiPanel;
window.adjustConfigFontSize = adjustConfigFontSize;
