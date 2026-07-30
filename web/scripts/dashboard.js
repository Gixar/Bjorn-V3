/* dashboard.js — home page: live stats, e-Paper preview, console, manual attack */

const STAT_KEYS = [
    "coins", "level", "known_hosts", "vulnerabilities",
    "credentials_cracked", "data_stolen", "zombies", "attacks",
    "targets", "open_ports",
];

const levelClasses = {
    DEBUG: "debug",
    INFO: "info",
    WARNING: "warning",
    ERROR: "error",
    CRITICAL: "critical",
    SUCCESS: "success",
};

let fontSize = /Mobi|Android/i.test(navigator.userAgent) ? 11 : 12.5;
let logInterval = null;
let isConsoleOn = false;
let epdInterval = null;
let ws = null;
let wsRetryCount = 0;
let pollTimer = null;
let manualOpen = false;
let netkbCache = null;
const fileColors = new Map();
const maxLines = 1500;

// ---------------------------------------------------------------------------
// Stats (WebSocket + polling fallback) — same contract as stats.js
// ---------------------------------------------------------------------------
function setIndicator(state, text) {
    const el = document.getElementById("ws-indicator");
    const textEl = document.getElementById("ws-indicator-text");
    if (!el || !textEl) return;
    el.className = "ws-indicator ws-" + state;
    textEl.textContent = text;
}

function applySnapshot(data) {
    STAT_KEYS.forEach((key) => {
        const el = document.getElementById("stat-" + key);
        if (el && data[key] !== undefined) el.textContent = data[key];
    });

    const orch = document.getElementById("orchestrator-badge");
    if (orch) {
        orch.textContent = "Orchestrator: " + (data.orchestrator_status || "—");
        orch.className = "status-badge " + (data.orchestrator_status === "IDLE" ? "badge-idle" : "badge-active");
    }

    const wifi = document.getElementById("wifi-badge");
    if (wifi) {
        wifi.textContent = data.wifi_connected ? "Wi-Fi: connected" : "Wi-Fi: disconnected";
        wifi.className = "status-badge " + (data.wifi_connected ? "badge-good" : "badge-bad");
    }

    const mode = document.getElementById("mode-badge");
    if (mode) {
        mode.textContent = data.manual_mode ? "Mode: manual" : "Mode: auto";
        mode.className = "status-badge badge-idle";
    }
}

function connectWebSocket() {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const url = `${protocol}//${window.location.host}/ws/stats`;
    try {
        ws = new WebSocket(url);
    } catch (_) {
        scheduleReconnectOrFallback();
        return;
    }
    ws.onopen = () => {
        wsRetryCount = 0;
        stopPolling();
        setIndicator("connected", "Live");
    };
    ws.onmessage = (event) => {
        try {
            applySnapshot(JSON.parse(event.data));
        } catch (e) {
            console.error("stats WS parse error", e);
        }
    };
    ws.onclose = () => {
        setIndicator("connecting", "Reconnecting…");
        scheduleReconnectOrFallback();
    };
    ws.onerror = () => {
        try { ws.close(); } catch (_) {}
    };
}

function scheduleReconnectOrFallback() {
    wsRetryCount += 1;
    if (wsRetryCount <= 5) {
        setTimeout(connectWebSocket, Math.min(1000 * wsRetryCount, 5000));
    } else {
        setIndicator("polling", "Live (polling)");
        startPolling();
    }
}

function startPolling() {
    if (pollTimer) return;
    pollOnce();
    pollTimer = setInterval(pollOnce, 3000);
}

function stopPolling() {
    if (pollTimer) {
        clearInterval(pollTimer);
        pollTimer = null;
    }
}

function pollOnce() {
    fetch("/api/stats")
        .then((r) => r.json())
        .then(applySnapshot)
        .catch((e) => console.error("poll /api/stats", e));
}

// ---------------------------------------------------------------------------
// e-Paper preview
// ---------------------------------------------------------------------------
function updateEpdImage() {
    const image = document.getElementById("screenImage_Home");
    if (!image) return;
    const next = new Image();
    next.onload = () => { image.src = next.src; };
    next.src = "screen.png?t=" + Date.now();
}

function startEpdLiveview(delayMs) {
    updateEpdImage();
    if (epdInterval) clearInterval(epdInterval);
    epdInterval = setInterval(updateEpdImage, delayMs || 2000);
}

// ---------------------------------------------------------------------------
// Console
// ---------------------------------------------------------------------------
function getRandomColor() {
    const letters = "89ABCDEF";
    let color = "#";
    for (let i = 0; i < 6; i++) color += letters[Math.floor(Math.random() * letters.length)];
    return color;
}

function colorizeLine(line) {
    if (line.includes("==>") || line.includes("<==")) return null;
    let modified = line;

    const regexFile = /(\w+\.py)/g;
    let match;
    while ((match = regexFile.exec(line)) !== null) {
        const fileName = match[1];
        if (!fileColors.has(fileName)) fileColors.set(fileName, getRandomColor());
        modified = modified.replace(
            fileName,
            `<span style="color:${fileColors.get(fileName)}">${fileName}</span>`
        );
    }

    modified = modified.replace(/\b(DEBUG|INFO|WARNING|ERROR|CRITICAL|SUCCESS)\b/g, (m) =>
        `<span class="${levelClasses[m]}">${m}</span>`
    );
    modified = modified.replace(/^\d+/, (m) => `<span class="line-number">${m}</span>`);
    modified = modified.replace(/\b\d+\b/g, (m) => `<span class="number">${m}</span>`);
    return modified;
}

function fetchLogs() {
    fetch("/get_logs")
        .then((r) => r.text())
        .then((data) => {
            const lines = data.split("\n");
            const colored = [];
            lines.forEach((line) => {
                const c = colorizeLine(line);
                if (c !== null) colored.push(c);
            });
            const logConsole = document.getElementById("log-console");
            if (!logConsole) return;
            let all = colored;
            if (all.length > maxLines) all = all.slice(all.length - maxLines);
            logConsole.innerHTML = all.join("<br>") + "<br>";
            logConsole.scrollTop = logConsole.scrollHeight;
        })
        .catch((e) => console.error("fetch logs", e));
}

function startConsole() {
    if (logInterval) return;
    fetchLogs();
    logInterval = setInterval(fetchLogs, 1500);
}

function stopConsole() {
    if (logInterval) {
        clearInterval(logInterval);
        logInterval = null;
    }
}

function toggleConsole() {
    const img = document.getElementById("toggle-console-image");
    const label = document.getElementById("console-state-label");
    isConsoleOn = !isConsoleOn;
    if (isConsoleOn) {
        startConsole();
        if (img) img.src = "/web/images/on.png";
        if (label) label.textContent = "Stop";
    } else {
        stopConsole();
        if (img) img.src = "/web/images/off.png";
        if (label) label.textContent = "Start";
    }
}

function clearConsoleView() {
    const logConsole = document.getElementById("log-console");
    if (logConsole) logConsole.innerHTML = "";
}

function adjustFontSize(change) {
    fontSize += change;
    const logConsole = document.getElementById("log-console");
    if (logConsole) logConsole.style.fontSize = fontSize + "px";
}

// ---------------------------------------------------------------------------
// Manual attack
// ---------------------------------------------------------------------------
function toggleManualPanel() {
    const panel = document.getElementById("manual-panel");
    const icon = document.getElementById("manual-toggle-icon");
    if (!panel) return;

    manualOpen = !manualOpen;
    if (manualOpen) {
        panel.classList.remove("collapsed");
        if (icon) icon.src = "/web/images/ai.png";
        SystemActions.stopOrchestrator();
        loadManualOptions();
    } else {
        panel.classList.add("collapsed");
        if (icon) icon.src = "/web/images/manual.png";
        SystemActions.startOrchestrator();
    }
}

function loadManualOptions() {
    fetch("/netkb_data_json")
        .then((r) => r.json())
        .then((data) => {
            netkbCache = data;
            const ipDropdown = document.getElementById("ip-dropdown");
            const actionDropdown = document.getElementById("action-dropdown");
            if (!ipDropdown || !actionDropdown) return;

            const ips = data.ips || [];
            ipDropdown.innerHTML = ips.length
                ? ips.map((ip) => `<option value="${ip}">${ip}</option>`).join("")
                : `<option value="">No live hosts</option>`;

            const actions = data.actions || [];
            actionDropdown.innerHTML = actions.length
                ? actions.map((a) => `<option value="${a}">${a}</option>`).join("")
                : `<option value="">No actions</option>`;

            updatePorts();
        })
        .catch((e) => {
            console.error("load netkb", e);
            toast("Failed to load NetKB targets", "error");
        });
}

function updatePorts() {
    const ip = document.getElementById("ip-dropdown")?.value;
    const portDropdown = document.getElementById("port-dropdown");
    if (!portDropdown) return;
    const ports = (netkbCache && netkbCache.ports && netkbCache.ports[ip]) || [];
    portDropdown.innerHTML = ports.length
        ? ports.map((p) => `<option value="${p}">${p}</option>`).join("")
        : `<option value="">—</option>`;
}

async function executeManualAttack() {
    const ip = document.getElementById("ip-dropdown")?.value;
    const port = document.getElementById("port-dropdown")?.value;
    const action = document.getElementById("action-dropdown")?.value;
    const btn = document.getElementById("execute-attack-btn");

    if (!ip || !action) {
        toast("Select a target and action", "error");
        return;
    }

    if (btn) {
        btn.disabled = true;
        btn.textContent = "Running…";
    }

    try {
        const data = await postJson("/execute_manual_attack", { ip, port: port || "0", action });
        toast(data.message || `Attack ${action} on ${ip} finished`, "success");
        if (isConsoleOn) fetchLogs();
        else {
            // briefly show logs even if console was off
            fetchLogs();
        }
    } catch (e) {
        toast(e.message || "Attack failed", "error");
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.textContent = "Execute attack";
        }
    }
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------
document.addEventListener("DOMContentLoaded", () => {
    renderNav();

    // Stats
    pollOnce();
    connectWebSocket();

    // e-Paper refresh interval from server config when available
    fetch("/get_web_delay")
        .then((r) => r.json())
        .then((d) => startEpdLiveview(d.web_delay || 2000))
        .catch(() => startEpdLiveview(2000));

    // Console starts off (user enables it) — less load on Pi Zero by default
    const logConsole = document.getElementById("log-console");
    if (logConsole) logConsole.style.fontSize = fontSize + "px";

    document.addEventListener("visibilitychange", () => {
        if (document.hidden) {
            stopPolling();
            if (epdInterval) {
                clearInterval(epdInterval);
                epdInterval = null;
            }
        } else {
            if (!ws || ws.readyState !== WebSocket.OPEN) startPolling();
            startEpdLiveview(2000);
            if (isConsoleOn) startConsole();
        }
    });
});

// Expose for inline handlers
window.toggleManualPanel = toggleManualPanel;
window.updatePorts = updatePorts;
window.executeManualAttack = executeManualAttack;
window.toggleConsole = toggleConsole;
window.adjustFontSize = adjustFontSize;
window.clearConsoleView = clearConsoleView;
